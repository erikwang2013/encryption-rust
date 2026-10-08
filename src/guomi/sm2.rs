// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 国密 SM2 公钥加密 / 私钥解密与签名 / 验签（GB/T 32918）。
//!
//! - 密钥与密文 / 签名均为十六进制字符串；
//! - 密文布局为 **C1C3C2**（现行标准的默认布局），C1 为非压缩点（`04‖X‖Y`）；
//! - 私钥为 64 位十六进制（32 字节标量）；公钥接受 130 位（`04‖X‖Y`）、
//!   128 位（`X‖Y`，自动补 `04`）与 66 位（压缩 `02/03‖X`）三种写法，
//!   生成密钥对时输出 130 位非压缩形式；
//! - 签名（GB/T 32918.2）为定长 64 字节 `r‖s`，即 128 位十六进制。
//!
//! **用户标识（ZA 的 ID）：固定为 [`DEFAULT_DIST_ID`] = `"1234567812345678"`**
//! ——业界惯例默认 ID（GM/T 0003.2 公开示例实际使用 `"ALICE123@YAHOO.COM"`）；
//! sm2 crate 本身不设默认，必须显式传入。
//! ID 不随消息或签名传输，**验签方必须使用同一个 ID**，否则验签必然失败。
//!
//! 对应 PHP 版的 `Asymmetric\Sm2AsymmetricCipher` 与 `Guomi\Sm2EncryptionService`。

use getrandom::SysRng;
use sm2::SecretKey;
use sm2::dsa::signature::{Signer as _, Verifier as _};
use sm2::dsa::{Signature, SigningKey, VerifyingKey};
use sm2::elliptic_curve::Generate;
use sm2::elliptic_curve::sec1::ToSec1Point;
use sm2::pke::{DecryptingKey, EncryptingKey};

use crate::contract::{AsymmetricCipher, Identified, Signer};
use crate::error::{Error, Result};
use crate::internal::{hex_decode, hex_encode};

const LABEL: &str = "SM2";

/// 签名 / 验签的用户标识（ZA 计算中的 ID），签名方与验签方必须一致。
///
/// 取值 `"1234567812345678"` 为业界惯例默认 ID（标准公开示例使用
/// `"ALICE123@YAHOO.COM"`；sm2 crate 不设默认，本库固定此值供开箱即用）。
/// 16 字节 ASCII，ENTLA = 0x0080。
pub const DEFAULT_DIST_ID: &str = "1234567812345678";

/// SM2 密钥对（十六进制）：私钥 64 位，公钥 130 位（非压缩 `04‖X‖Y`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPairHex {
    pub private_key_hex: String,
    pub public_key_hex: String,
}

/// SM2 静态门面（对应 PHP 版 `Sm2EncryptionService`）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Sm2Service;

impl Sm2Service {
    /// 公钥加密，返回十六进制密文（C1C3C2）。
    pub fn encrypt(plaintext: &[u8], public_key_hex: &str) -> Result<String> {
        let encrypting_key = parse_public_key(public_key_hex)?;
        let ciphertext = encrypting_key
            .encrypt(&mut SysRng, plaintext)
            .map_err(|_| Error::EncryptionFailed { label: LABEL })?;
        Ok(hex_encode(&ciphertext))
    }

    /// 私钥解密十六进制密文。
    pub fn decrypt(ciphertext_hex: &str, private_key_hex: &str) -> Result<Vec<u8>> {
        let decrypting_key = DecryptingKey::new(parse_private_key(private_key_hex)?);
        let ciphertext =
            hex_decode(ciphertext_hex).map_err(|_| Error::DecryptionFailed { label: LABEL })?;
        decrypting_key
            .decrypt(&ciphertext)
            .map_err(|_| Error::DecryptionFailed { label: LABEL })
    }

    /// 生成密钥对：私钥用系统 CSPRNG 采样（不经任何非密码学随机源）。
    pub fn generate_key_pair_hex() -> Result<KeyPairHex> {
        let secret_key = SecretKey::try_generate_from_rng(&mut SysRng)
            .map_err(|_| Error::EncryptionFailed { label: LABEL })?;
        let public_key = secret_key.public_key();

        Ok(KeyPairHex {
            private_key_hex: hex_encode(secret_key.to_bytes().as_slice()),
            public_key_hex: hex_encode(public_key.to_sec1_point(false).as_bytes()),
        })
    }

    /// 私钥签名，返回定长 64 字节 `r‖s` 的十六进制（128 位）。
    ///
    /// 用户标识固定为 [`DEFAULT_DIST_ID`]；随机数 `k` 走 RFC 6979 确定性
    /// 派生（同一私钥 + 同一消息必得同一签名，不依赖运行时随机源）。
    ///
    /// 私钥格式非法（十六进制或长度）返回 [`Error::InvalidKey`]，
    /// 其余签名失败返回 [`Error::SignFailed`]。
    pub fn sign(message: &[u8], private_key_hex: &str) -> Result<String> {
        let signing_key = SigningKey::new(DEFAULT_DIST_ID, &parse_private_key(private_key_hex)?)
            .map_err(|_| Error::SignFailed { label: LABEL })?;
        let signature: Signature = signing_key
            .try_sign(message)
            .map_err(|_| Error::SignFailed { label: LABEL })?;
        Ok(hex_encode(signature.to_bytes().as_slice()))
    }

    /// 公钥验签。签名不对、消息被改、公钥 / 签名格式错误一律
    /// [`Error::VerificationFailed`]（与契约一致，不区分原因）。
    ///
    /// 公钥写法接受与非对称加密相同的三种形式；用户标识固定为
    /// [`DEFAULT_DIST_ID`]，签名方 ID 不一致时验签必然失败。
    pub fn verify(message: &[u8], signature_hex: &str, public_key_hex: &str) -> Result<()> {
        let fail = || Error::VerificationFailed { label: LABEL };
        let sec1 = sec1_public_key_bytes(public_key_hex).map_err(|_| fail())?;
        let verifying_key =
            VerifyingKey::from_sec1_bytes(DEFAULT_DIST_ID, &sec1).map_err(|_| fail())?;
        let signature_bytes = hex_decode(signature_hex).map_err(|_| fail())?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|_| fail())?;
        verifying_key
            .verify(message, &signature)
            .map_err(|_| fail())
    }
}

/// SM2 非对称加密器（实现 [`AsymmetricCipher`]；行为与 [`Sm2Service`] 一致）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Sm2AsymmetricCipher;

impl Sm2AsymmetricCipher {
    pub const IDENTIFIER: &'static str = "sm2";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for Sm2AsymmetricCipher {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl AsymmetricCipher for Sm2AsymmetricCipher {
    fn encrypt(&self, plaintext: &[u8], public_key_hex: &str) -> Result<String> {
        Sm2Service::encrypt(plaintext, public_key_hex)
    }

    fn decrypt(&self, ciphertext_hex: &str, private_key_hex: &str) -> Result<Vec<u8>> {
        Sm2Service::decrypt(ciphertext_hex, private_key_hex)
    }
}

/// SM2 签名器（实现 [`Signer`]；行为与 [`Sm2Service::sign`] / [`Sm2Service::verify`] 一致）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Sm2Signer;

impl Sm2Signer {
    pub const IDENTIFIER: &'static str = "sm2";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for Sm2Signer {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl Signer for Sm2Signer {
    fn sign(&self, message: &[u8], private_key_hex: &str) -> Result<String> {
        Sm2Service::sign(message, private_key_hex)
    }

    fn verify(&self, message: &[u8], signature_hex: &str, public_key_hex: &str) -> Result<()> {
        Sm2Service::verify(message, signature_hex, public_key_hex)
    }
}

/// 接受 130 位（`04‖X‖Y`）/ 128 位（`X‖Y`）/ 66 位（压缩点）三种公钥写法，
/// 归一化成 SEC1 字节（加密与验签共用）。
fn sec1_public_key_bytes(public_key_hex: &str) -> Result<Vec<u8>> {
    let bytes = hex_decode(public_key_hex).map_err(|_| Error::InvalidKey { label: LABEL })?;

    match bytes.len() {
        65 | 33 => Ok(bytes),
        64 => {
            // 裸 X‖Y：补上非压缩点标记。
            let mut normalized = Vec::with_capacity(65);
            normalized.push(0x04);
            normalized.extend_from_slice(&bytes);
            Ok(normalized)
        }
        _ => Err(Error::InvalidKey { label: LABEL }),
    }
}

fn parse_public_key(public_key_hex: &str) -> Result<EncryptingKey> {
    let sec1 = sec1_public_key_bytes(public_key_hex)?;
    EncryptingKey::from_sec1_bytes(&sec1).map_err(|_| Error::InvalidKey { label: LABEL })
}

/// 私钥：64 位十六进制（32 字节标量），其余长度一律拒绝。
fn parse_private_key(private_key_hex: &str) -> Result<SecretKey> {
    let bytes = hex_decode(private_key_hex).map_err(|_| Error::InvalidKey { label: LABEL })?;
    SecretKey::from_slice(&bytes).map_err(|_| Error::InvalidKey { label: LABEL })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip_and_hex_shapes() {
        let pair = Sm2Service::generate_key_pair_hex().unwrap();
        assert_eq!(pair.private_key_hex.len(), 64);
        assert_eq!(pair.public_key_hex.len(), 130);
        assert!(pair.public_key_hex.starts_with("04"));

        let ciphertext =
            Sm2Service::encrypt("国密数据 🎉".as_bytes(), &pair.public_key_hex).unwrap();
        let plaintext = Sm2Service::decrypt(&ciphertext, &pair.private_key_hex).unwrap();
        assert_eq!(plaintext, "国密数据 🎉".as_bytes());
    }

    #[test]
    fn bare_xy_public_key_is_accepted_too() {
        let pair = Sm2Service::generate_key_pair_hex().unwrap();
        let bare = &pair.public_key_hex[2..]; // 去掉 04 前缀

        let ciphertext = Sm2Service::encrypt(b"payload", bare).unwrap();
        let plaintext = Sm2Service::decrypt(&ciphertext, &pair.private_key_hex).unwrap();
        assert_eq!(plaintext, b"payload");
    }

    #[test]
    fn wrong_private_key_or_tampered_ciphertext_fails() {
        let pair = Sm2Service::generate_key_pair_hex().unwrap();
        let other = Sm2Service::generate_key_pair_hex().unwrap();
        let ciphertext = Sm2Service::encrypt(b"secret", &pair.public_key_hex).unwrap();

        assert_eq!(
            Sm2Service::decrypt(&ciphertext, &other.private_key_hex).unwrap_err(),
            Error::DecryptionFailed { label: LABEL }
        );

        let mut tampered = ciphertext.clone();
        let last = tampered.len() - 1;
        let flipped = if tampered.as_bytes()[last] == b'0' {
            '1'
        } else {
            '0'
        };
        tampered.replace_range(last.., &flipped.to_string());
        assert_eq!(
            Sm2Service::decrypt(&tampered, &pair.private_key_hex).unwrap_err(),
            Error::DecryptionFailed { label: LABEL }
        );
    }

    #[test]
    fn malformed_keys_are_rejected() {
        let pair = Sm2Service::generate_key_pair_hex().unwrap();

        assert_eq!(
            Sm2Service::decrypt("00", "zz").unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
        assert_eq!(
            Sm2Service::encrypt(b"x", "abcd").unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
        // 私钥位数不对（多一位十六进制）。
        let mut longer = pair.private_key_hex.clone();
        longer.push('a');
        assert_eq!(
            Sm2Service::decrypt("00", &longer).unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
    }

    #[test]
    fn cipher_trait_matches_service() {
        let cipher = Sm2AsymmetricCipher::new();
        assert_eq!(cipher.identifier(), "sm2");

        let pair = Sm2Service::generate_key_pair_hex().unwrap();
        let ciphertext = cipher.encrypt(b"via trait", &pair.public_key_hex).unwrap();
        assert_eq!(
            cipher.decrypt(&ciphertext, &pair.private_key_hex).unwrap(),
            b"via trait"
        );
    }

    #[test]
    fn sign_verify_roundtrip_and_signature_shape() {
        let pair = Sm2Service::generate_key_pair_hex().unwrap();
        let signature = Sm2Service::sign("国密签名 🎉".as_bytes(), &pair.private_key_hex).unwrap();

        assert_eq!(signature.len(), 128); // 64 字节 r‖s
        Sm2Service::verify("国密签名 🎉".as_bytes(), &signature, &pair.public_key_hex).unwrap();
    }

    #[test]
    fn signature_is_deterministic() {
        // RFC 6979 确定性 k：同一私钥 + 同一消息必得同一签名。
        let pair = Sm2Service::generate_key_pair_hex().unwrap();
        let first = Sm2Service::sign(b"same message", &pair.private_key_hex).unwrap();
        let second = Sm2Service::sign(b"same message", &pair.private_key_hex).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn verify_rejects_wrong_input_forms() {
        let failed = Error::VerificationFailed { label: LABEL };
        let pair = Sm2Service::generate_key_pair_hex().unwrap();
        let other = Sm2Service::generate_key_pair_hex().unwrap();
        let signature = Sm2Service::sign(b"message", &pair.private_key_hex).unwrap();

        // 消息被改。
        assert_eq!(
            Sm2Service::verify(b"messagE", &signature, &pair.public_key_hex).unwrap_err(),
            failed
        );
        // 换了别人的公钥。
        assert_eq!(
            Sm2Service::verify(b"message", &signature, &other.public_key_hex).unwrap_err(),
            failed
        );
        // 签名被篡改（翻转最后一个十六进制字符）。
        let mut tampered = signature.clone();
        let last = tampered.len() - 1;
        let flipped = if tampered.as_bytes()[last] == b'0' {
            '1'
        } else {
            '0'
        };
        tampered.replace_range(last.., &flipped.to_string());
        assert_eq!(
            Sm2Service::verify(b"message", &tampered, &pair.public_key_hex).unwrap_err(),
            failed
        );
        // 格式错误：公钥非法、签名非法、签名长度不对——一律 VerificationFailed。
        assert_eq!(
            Sm2Service::verify(b"message", &signature, "zz").unwrap_err(),
            failed
        );
        assert_eq!(
            Sm2Service::verify(b"message", "not-hex", &pair.public_key_hex).unwrap_err(),
            failed
        );
        assert_eq!(
            Sm2Service::verify(b"message", "00", &pair.public_key_hex).unwrap_err(),
            failed
        );
    }

    #[test]
    fn bare_xy_public_key_verifies_too() {
        let pair = Sm2Service::generate_key_pair_hex().unwrap();
        let bare = &pair.public_key_hex[2..]; // 去掉 04 前缀

        let signature = Sm2Service::sign(b"payload", &pair.private_key_hex).unwrap();
        Sm2Service::verify(b"payload", &signature, bare).unwrap();
    }

    /// 压缩公钥（66 位 hex = 02/03‖X）同样可验签——文档承诺的第三种写法。
    #[test]
    fn compressed_public_key_verifies_too() {
        use sm2::elliptic_curve::sec1::ToSec1Point;

        let pair = Sm2Service::generate_key_pair_hex().unwrap();
        let secret = sm2::SecretKey::from_slice(
            &crate::internal::hex_decode(&pair.private_key_hex).unwrap(),
        )
        .unwrap();
        let compressed_hex =
            crate::internal::hex_encode(secret.public_key().to_sec1_point(true).as_bytes());
        assert_eq!(compressed_hex.len(), 66);

        let signature = Sm2Service::sign(b"payload", &pair.private_key_hex).unwrap();
        Sm2Service::verify(b"payload", &signature, &compressed_hex).unwrap();
    }

    /// 跨层核验：本库 `Sm2Signer` 的签名必须能被裸 sm2 crate 的 `VerifyingKey`
    /// （同一 DIST_ID 与编码路径）接受——钉住封装层没有引入 ID / 编码偏差。
    #[test]
    fn signature_is_accepted_by_raw_sm2_crate() {
        let pair = Sm2Service::generate_key_pair_hex().unwrap();
        let signature_hex = Sm2Service::sign(b"cross-layer", &pair.private_key_hex).unwrap();

        let sec1 = crate::internal::hex_decode(&pair.public_key_hex).unwrap();
        let verifying_key =
            sm2::dsa::VerifyingKey::from_sec1_bytes(DEFAULT_DIST_ID, &sec1).unwrap();
        let sig_bytes = crate::internal::hex_decode(&signature_hex).unwrap();
        let signature = sm2::dsa::Signature::from_slice(&sig_bytes).unwrap();
        verifying_key.verify(b"cross-layer", &signature).unwrap();
    }

    #[test]
    fn sign_rejects_malformed_private_key() {
        assert_eq!(
            Sm2Service::sign(b"x", "zz").unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
        assert_eq!(
            Sm2Service::sign(b"x", "abcd").unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
    }

    #[test]
    fn signer_trait_matches_service() {
        let signer = Sm2Signer::new();
        assert_eq!(signer.identifier(), "sm2");

        let pair = Sm2Service::generate_key_pair_hex().unwrap();
        let signature = signer.sign(b"via trait", &pair.private_key_hex).unwrap();
        signer
            .verify(b"via trait", &signature, &pair.public_key_hex)
            .unwrap();
        assert_eq!(
            signer.verify(b"other", &signature, &pair.public_key_hex),
            Err(Error::VerificationFailed { label: LABEL })
        );
    }
}
