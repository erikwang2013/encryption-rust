// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! RSA-OAEP 非对称加密（RFC 8017 §7.1 RSAES-OAEP），摘要与 MGF1 均固定 SHA-256。
//!
//! - 密钥与密文均为十六进制字符串；密钥格式由本库自定（PHP 版未提供 RSA，
//!   无对齐约束）：私钥 = **PKCS#8 DER** 的十六进制，公钥 = **SPKI DER**
//!   的十六进制；
//! - 密文定长：等于模数字节长 k（2048 位密钥即 256 字节）。OAEP 每次加密都注入
//!   新随机种子，同一明文两次加密的密文必然不同，调用方不应比对密文；
//! - 明文上限 k − 2×32 − 2 字节（RFC 8017 §7.1.1 式 (1)，2048 位密钥即 190 字节），
//!   超长加密报 [`Error::EncryptionFailed`]；
//! - 解密走 `decrypt_blinded`：模幂前用随机数盲化，防 Bleichenbacher 式计时
//!   侧信道；一切失败（密钥不对 / 密文被改 / 填充非法）都是
//!   [`Error::DecryptionFailed`]，不区分原因；
//! - [`RsaOaepSha256Service::generate_key_pair_hex`] 拒绝低于 2048 位的请求：
//!   2048 位是本库接受的 RSA 安全下限；**解析路径不设位宽下限**（兼容存量
//!   密钥——历史数据可能由弱密钥加密，拒绝加载会让旧数据无法解开，风险自担；
//!   新密钥请一律走 `generate`）。
//! - **已知边界（RUSTSEC-2023-0071）**：上游 `rsa` crate 的「Marvin」时序侧信道
//!   公告至今无补丁（0.9.10 与 0.10.0-rc 均受影响）。本库解密固定走
//!   `decrypt_blinded`（公告承认的缓解方向），但**网络暴露场景建议优先
//!   ECDH / X25519 / Ed25519 / ML-KEM**；RSA-OAEP 定位为与存量系统互通或本地使用。
//!
//! 对应 PHP 版：无（PHP 包未提供 RSA 实现）。

use rand_core::OsRng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use crate::contract::{AsymmetricCipher, Identified};
use crate::error::{Error, Result};
use crate::internal::{hex_decode, hex_encode};

use super::KeyPairHex;

const LABEL: &str = "RSA-OAEP-SHA256";

/// RSA 密钥生成的安全下限：2048 位。
const MIN_KEY_BITS: usize = 2048;

/// SHA-256 摘要长度（字节）：OAEP 的填充开销为 2×32 + 2。
const SHA256_OUTPUT_LEN: usize = 32;

/// RSA-OAEP-SHA256 静态门面（密钥材料每次调用显式传入）。
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaOaepSha256Service;

impl RsaOaepSha256Service {
    /// 公钥加密（OAEP + SHA-256），返回定长的十六进制密文。
    pub fn encrypt(plaintext: &[u8], public_key_hex: &str) -> Result<String> {
        let public_key = parse_public_key(public_key_hex)?;

        // RFC 8017 §7.1.1 步骤 1：明文上限 k − 2×hLen − 2。k < 66 的密钥连空明文
        // 都放不下，checked_sub 一并拒绝。这里选 EncryptionFailed 是因为错误枚举
        // 与 PHP 版对齐、不新增变体，而它是加密方向的唯一失败桶（rsa crate 在同样
        // 场景返回的 MessageTooLong 语义上也是「加密失败」）。
        let max_plaintext = public_key
            .size()
            .checked_sub(2 * SHA256_OUTPUT_LEN + 2)
            .ok_or(Error::EncryptionFailed { label: LABEL })?;
        if plaintext.len() > max_plaintext {
            return Err(Error::EncryptionFailed { label: LABEL });
        }

        let ciphertext = public_key
            .encrypt(&mut OsRng, Oaep::new::<Sha256>(), plaintext)
            .map_err(|_| Error::EncryptionFailed { label: LABEL })?;
        Ok(hex_encode(&ciphertext))
    }

    /// 私钥解密十六进制密文。
    pub fn decrypt(ciphertext_hex: &str, private_key_hex: &str) -> Result<Vec<u8>> {
        let private_key = parse_private_key(private_key_hex)?;
        let ciphertext =
            hex_decode(ciphertext_hex).map_err(|_| Error::DecryptionFailed { label: LABEL })?;

        // 必须用 decrypt_blinded：盲化后的模幂不给时序侧信道留下可用信号。
        private_key
            .decrypt_blinded(&mut OsRng, Oaep::new::<Sha256>(), &ciphertext)
            .map_err(|_| Error::DecryptionFailed { label: LABEL })
    }

    /// 生成密钥对；`bits` 低于 2048（安全下限）直接拒绝。
    ///
    /// 私钥大数由 rsa crate 自身 zeroize 清零（rsa 0.9 已依赖 zeroize），
    /// 本库不再包一层 [`crate::key::Key`]——RSA 密钥非定长。
    pub fn generate_key_pair_hex(bits: usize) -> Result<KeyPairHex> {
        if bits < MIN_KEY_BITS {
            // 变体选 InvalidKeyLength：枚举里唯一语义为「密钥长度不符合算法要求」
            // 的项，且带着 expect/got 两个数（均为位，便于定位）。
            return Err(Error::InvalidKeyLength {
                label: LABEL,
                expected: MIN_KEY_BITS,
                got: bits,
            });
        }

        let private_key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|_| Error::EncryptionFailed { label: LABEL })?;
        let private_key_der = private_key
            .to_pkcs8_der()
            .map_err(|_| Error::EncryptionFailed { label: LABEL })?;
        let public_key_der = private_key
            .to_public_key()
            .to_public_key_der()
            .map_err(|_| Error::EncryptionFailed { label: LABEL })?;

        Ok(KeyPairHex {
            private_key_hex: hex_encode(private_key_der.as_bytes()),
            public_key_hex: hex_encode(public_key_der.as_bytes()),
        })
    }
}

/// RSA-OAEP-SHA256 非对称加密器（实现 [`AsymmetricCipher`]；行为与
/// [`RsaOaepSha256Service`] 一致）。
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaOaepSha256Cipher;

impl RsaOaepSha256Cipher {
    pub const IDENTIFIER: &'static str = "rsa-oaep-sha256";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for RsaOaepSha256Cipher {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl AsymmetricCipher for RsaOaepSha256Cipher {
    fn encrypt(&self, plaintext: &[u8], public_key_hex: &str) -> Result<String> {
        RsaOaepSha256Service::encrypt(plaintext, public_key_hex)
    }

    fn decrypt(&self, ciphertext_hex: &str, private_key_hex: &str) -> Result<Vec<u8>> {
        RsaOaepSha256Service::decrypt(ciphertext_hex, private_key_hex)
    }
}

/// 公钥：SPKI DER 十六进制，只验 DER 结构，格式非法 → [`Error::InvalidKey`]。
fn parse_public_key(public_key_hex: &str) -> Result<RsaPublicKey> {
    let der = hex_decode(public_key_hex).map_err(|_| Error::InvalidKey { label: LABEL })?;
    RsaPublicKey::from_public_key_der(&der).map_err(|_| Error::InvalidKey { label: LABEL })
}

/// 私钥：PKCS#8 DER 十六进制，只验 DER 结构，格式非法 → [`Error::InvalidKey`]。
fn parse_private_key(private_key_hex: &str) -> Result<RsaPrivateKey> {
    let der = hex_decode(private_key_hex).map_err(|_| Error::InvalidKey { label: LABEL })?;
    RsaPrivateKey::from_pkcs8_der(&der).map_err(|_| Error::InvalidKey { label: LABEL })
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;

    // ── 外部定值向量（KAT）────────────────────────────────────────────────
    // 来源：Project Wycheproof `testvectors_v1/rsa_oaep_2048_sha256_mgf1sha256_test.json`
    // （google-wycheproof 0.9，Apache-2.0 许可），2048 位、SHA-256 + MGF1-SHA256
    // 分组，与 `Oaep::new::<Sha256>()`（空标签）逐字节同构。取一个 valid 例
    // （tcId 3，明文 "Test"）与两个 invalid 例（tcId 26：EM = n−1；tcId 29：空密文）。
    // 固定密钥私钥的 PKCS#8 DER 十六进制（即本库私钥格式）：
    const WYCHEPROOF_PKCS8_HEX: &str = "308204bd020100300d06092a864886f70d0101010500048204a7308204a3020100028201\
        0100a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9\
        746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db\
        92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff\
        8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266\
        f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7a\
        fc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e797500\
        5d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf782\
        0283f742b9d502030100010282010024cdc62317f5d72a6f6ba6cc9632899b01d1ff2886\
        7d72f61688995bc855a4e420a8405250089bdb13cf8e09543827b748b9d27fbb2b4d9e20\
        af8c5a6a862796d1a4cc18ad16ea678bc1bd4a83bbbe9c5e57453b5ce7388e41a3ba4ce2\
        b77b4438a229e954f720dae0353dc088ac8a76b26dc276f8e1b7851ddd6398ad16ff2e78\
        195123b9b036e945c38c9d12434f6df76fe22359eb3e1ac9c011678fc926fad3ae475a4f\
        ffff55feb2d147e9c894f4c0e29a599e762462482d968bf42780945fc0d2c31c573c4431\
        b8f4fe8b8c67bec815abd44f7a86edca1c2308737358d2c2ae5e2e0e2dadf73098026237\
        7e58b13b7d9992060a0bc870ccfdb4a9319ee102818100dc431050f782e894fb5248247d\
        98cb7d58b8d1e24f3b55d041c56e4de086b0d5bb028bda42eeb5d234d5681e5809d415e6\
        a289ad4cfbf78f978f6c35814f50eebff1c5b80a69f788e81e6bab5ddaa78369d659d143\
        ec6f17e79813a575cfad9c569156b90113e2e9110ad9e7b48a1c9348a6e653321191290e\
        a36cfb3a5b18f102818100bd1a81e7977f9898122273ae3222b598ea5fb19eb4eabc3830\
        8a5e32196603b2e500ffb79f5b886816611debc472fac45544070beb057c941378a6868a\
        f3b7a03d3f9880ec47d5e089b94fbde542aba9ae8d72c57088d7abf5b131f39098f7bc16\
        0f90536abc9492fd4e06f3ed7299d4b97bb03677207d95669f140cfbc20f2502818100a9\
        4b528b28f291599121d91952ffd1c7f21d7c1479d99d478885fb161870ee1218bf084726\
        12dbe5497e8d9c650688e09c786961ae3e2c354dc48ae34514759c4c23c4588488961dc0\
        6b414e61c0e1e7fbbd2923d31532fe289f96da220711e58c14019808e00414276933bb07\
        e4efb9b4a9b37656917205209f33f09515d7c10281803af0e72a933aef09ff2503df78ba\
        fed531c02ff1a2bc437c540cdcbd4ad35435cf511763596543480629b114ca7f780ff7ef\
        a32ea0cb6e000d6d9ea1f2ef71fd9cf9948422a165557e37e755edfe70d90b920502eb47\
        8bc98a63f788ce3a0f856d6ede7251a383bfa8fa480a81a925af7b3cc538c4bab8c9f759\
        7ffb68011d8d0281802640fbfbcfefb163ee7a87b6483a66ee41f956d90fa8a7939bfc04\
        2ee0924b1b7993d0445f758d51933e85179c0320b0c968b48a91c38b5be923e1097c0c56\
        2f88d42294b6a2759bafa5428a74f1270874e45f6fcc60f21602de5eccd143cf31241f59\
        21b5ad3983fb54ef17be3b285367e50c999c67247b552fe4bfce945f7b";
    /// tcId 3 的密文（十六进制，256 字节），解出明文 `54657374`（"Test"）。
    const WYCHEPROOF_CT_VALID: &str = "5eab3f0741e63986ed647d53e1cd71df041986900803d0f99c68355d249a15a47dc5b4f7\
        0a191477654299e5a2731f3b4eec76dea18262fc696ac794e5f66cbfcddac4472c578e24\
        6c26707598055584540b839836b1404c5611ae558a984cee8fd036cea924e0be2474a940\
        f61e0acc14fcae95ebdc59942a9ce9af9a9c81999f7f6815f057ffdc2533cb15d6391d1e\
        2d95f16f9c04209c889a4c359c7d2926d28a66e2b030a416b928d2825627998e5191fb49\
        83a6e65024262d94fc09187a2d78162122433251d1bfcc8e507d06eba2d229c10031261d\
        a32ab8ccd15f1c5f9fbf07ed158483d736a110af4b44d6a4da60d6cb519b4454213cf9f0\
        dc560f2b";
    /// tcId 26 的密文：EM = n−1，OAEP 填充校验必须失败。
    const WYCHEPROOF_CT_N_MINUS_1: &str = "a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d\
        3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db9251\
        2ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17\
        e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c0\
        21d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e\
        09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9b\
        c22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283\
        f742b9d4";
    const WYCHEPROOF_MSG_VALID_HEX: &str = "54657374"; // "Test"

    /// Wycheproof 定值密钥对（十六进制）：私钥直接用向量文件里的 PKCS#8；
    /// 公钥由 rsa crate 从同一私钥导出 SPKI，避免在源码里再嵌一份常量。
    fn wycheproof_keypair_hex() -> KeyPairHex {
        let der = hex_decode(WYCHEPROOF_PKCS8_HEX).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_der(&der).unwrap();
        let public_der = private_key.to_public_key().to_public_key_der().unwrap();
        KeyPairHex {
            private_key_hex: WYCHEPROOF_PKCS8_HEX.to_string(),
            public_key_hex: hex_encode(public_der.as_bytes()),
        }
    }

    /// 本库自己生成的 2048 位密钥对，全测试共享一份（生成一次，约数秒）。
    fn generated_keypair() -> &'static KeyPairHex {
        static PAIR: OnceLock<KeyPairHex> = OnceLock::new();
        PAIR.get_or_init(|| RsaOaepSha256Service::generate_key_pair_hex(MIN_KEY_BITS).unwrap())
    }

    #[test]
    fn wycheproof_fixed_vectors() {
        let pair = wycheproof_keypair_hex();

        // 定值解密：公开向量里的密文必须解出公开向量里的明文。
        assert_eq!(
            RsaOaepSha256Service::decrypt(WYCHEPROOF_CT_VALID, &pair.private_key_hex).unwrap(),
            hex_decode(WYCHEPROOF_MSG_VALID_HEX).unwrap()
        );

        // 加密方向：OAEP 随机化，密文对不上定值；用同一密钥对往返验证。
        let ciphertext = RsaOaepSha256Service::encrypt(b"Test", &pair.public_key_hex).unwrap();
        assert_eq!(
            RsaOaepSha256Service::decrypt(&ciphertext, &pair.private_key_hex).unwrap(),
            b"Test"
        );

        // 定值反向用例：Wycheproof 标 invalid 的密文（EM = n−1）与空密文都必须失败。
        for ciphertext in [WYCHEPROOF_CT_N_MINUS_1, ""] {
            assert_eq!(
                RsaOaepSha256Service::decrypt(ciphertext, &pair.private_key_hex).unwrap_err(),
                Error::DecryptionFailed { label: LABEL }
            );
        }
    }

    #[test]
    fn keypair_roundtrip_self_parse_and_shapes() {
        let pair = generated_keypair();

        // generate 出的两种密钥都能被自身解析：往返即证明（加密过 parse_public_key，
        // 解密过 parse_private_key）。2048 位 → 密文定长 256 字节（512 位十六进制）。
        let ciphertext =
            RsaOaepSha256Service::encrypt("RSA 数据 🎉".as_bytes(), &pair.public_key_hex).unwrap();
        assert_eq!(ciphertext.len(), 512);
        assert_eq!(
            RsaOaepSha256Service::decrypt(&ciphertext, &pair.private_key_hex).unwrap(),
            "RSA 数据 🎉".as_bytes()
        );

        // DER 外形：都是 SEQUENCE（0x30）、偶数长度十六进制。
        for der_hex in [&pair.private_key_hex, &pair.public_key_hex] {
            assert!(der_hex.starts_with("30"));
            assert!(der_hex.len().is_multiple_of(2));
        }
    }

    #[test]
    fn wrong_private_key_or_tampered_ciphertext_fails() {
        let wycheproof = wycheproof_keypair_hex();
        let generated = generated_keypair();

        // 给 Wycheproof 公钥加密的密文，换本库生成的私钥解 → 必败。
        let ciphertext =
            RsaOaepSha256Service::encrypt(b"secret", &wycheproof.public_key_hex).unwrap();
        assert_eq!(
            RsaOaepSha256Service::decrypt(&ciphertext, &generated.private_key_hex).unwrap_err(),
            Error::DecryptionFailed { label: LABEL }
        );

        // 篡改末位十六进制 → 必败。
        let mut tampered = ciphertext.clone();
        let last = tampered.len() - 1;
        let flipped = if tampered.as_bytes()[last] == b'0' {
            '1'
        } else {
            '0'
        };
        tampered.replace_range(last.., &flipped.to_string());
        assert_eq!(
            RsaOaepSha256Service::decrypt(&tampered, &wycheproof.private_key_hex).unwrap_err(),
            Error::DecryptionFailed { label: LABEL }
        );
    }

    #[test]
    fn oversized_plaintext_is_rejected() {
        let pair = wycheproof_keypair_hex();
        // 2048 位 → k = 256 字节 → 明文上限 256 − 2×32 − 2 = 190 字节。
        let max_plaintext = [0u8; 190];
        RsaOaepSha256Service::encrypt(&max_plaintext, &pair.public_key_hex).unwrap();

        let too_long = [0u8; 191];
        assert_eq!(
            RsaOaepSha256Service::encrypt(&too_long, &pair.public_key_hex).unwrap_err(),
            Error::EncryptionFailed { label: LABEL }
        );
    }

    #[test]
    fn malformed_keys_are_rejected() {
        let pair = wycheproof_keypair_hex();

        // 非十六进制 / 奇数长度 → InvalidKey（与 sm2 一致：密钥解析先于密文解析）。
        assert_eq!(
            RsaOaepSha256Service::encrypt(b"x", "zz").unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
        assert_eq!(
            RsaOaepSha256Service::decrypt("00", "zz").unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
        // 合法十六进制但不是 DER / 被截断的 DER → InvalidKey。
        assert_eq!(
            RsaOaepSha256Service::encrypt(b"x", "deadbeef").unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
        let truncated = &pair.private_key_hex[..pair.private_key_hex.len() - 2];
        assert_eq!(
            RsaOaepSha256Service::decrypt("00", truncated).unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
        // 公私混用（SPKI 当私钥）→ InvalidKey。
        assert_eq!(
            RsaOaepSha256Service::decrypt("00", &pair.public_key_hex).unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
    }

    #[test]
    fn key_bits_below_floor_are_rejected() {
        for bits in [512, 1024, 2047] {
            assert_eq!(
                RsaOaepSha256Service::generate_key_pair_hex(bits).unwrap_err(),
                Error::InvalidKeyLength {
                    label: LABEL,
                    expected: MIN_KEY_BITS,
                    got: bits,
                }
            );
        }
    }

    #[test]
    fn cipher_trait_matches_service() {
        let cipher = RsaOaepSha256Cipher::new();
        assert_eq!(cipher.identifier(), "rsa-oaep-sha256");

        let pair = wycheproof_keypair_hex();
        let ciphertext = cipher.encrypt(b"via trait", &pair.public_key_hex).unwrap();
        assert_eq!(
            cipher.decrypt(&ciphertext, &pair.private_key_hex).unwrap(),
            b"via trait"
        );
    }
}
