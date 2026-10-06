// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 国密 SM2 公钥加密 / 私钥解密（GB/T 32918）。
//!
//! - 密钥与密文均为十六进制字符串；
//! - 密文布局为 **C1C3C2**（现行标准的默认布局），C1 为非压缩点（`04‖X‖Y`）；
//! - 私钥为 64 位十六进制（32 字节标量）；公钥接受 130 位（`04‖X‖Y`）、
//!   128 位（`X‖Y`，自动补 `04`）与 66 位（压缩 `02/03‖X`）三种写法，
//!   生成密钥对时输出 130 位非压缩形式。
//!
//! 对应 PHP 版的 `Asymmetric\Sm2AsymmetricCipher` 与 `Guomi\Sm2EncryptionService`。

use getrandom::SysRng;
use sm2::SecretKey;
use sm2::elliptic_curve::Generate;
use sm2::elliptic_curve::sec1::ToSec1Point;
use sm2::pke::{DecryptingKey, EncryptingKey};

use crate::contract::{AsymmetricCipher, Identified};
use crate::error::{Error, Result};
use crate::internal::{hex_decode, hex_encode};

const LABEL: &str = "SM2";

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

/// 接受 130 位（`04‖X‖Y`）/ 128 位（`X‖Y`）/ 66 位（压缩点）三种公钥写法。
fn parse_public_key(public_key_hex: &str) -> Result<EncryptingKey> {
    let bytes = hex_decode(public_key_hex).map_err(|_| Error::InvalidKey { label: LABEL })?;

    let sec1 = match bytes.len() {
        65 | 33 => bytes,
        64 => {
            // 裸 X‖Y：补上非压缩点标记。
            let mut normalized = Vec::with_capacity(65);
            normalized.push(0x04);
            normalized.extend_from_slice(&bytes);
            normalized
        }
        _ => return Err(Error::InvalidKey { label: LABEL }),
    };

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
}
