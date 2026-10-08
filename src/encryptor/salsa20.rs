// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! Salsa20/20 流密码（D. J. Bernstein）+ HMAC-SHA256（encrypt-then-MAC）；
//! 载荷：`v1 | nonce(8) | MAC(32) | 密文（与密钥流异或）`。密钥 32 字节。
//! 与国密 ZUC（`src/guomi/zuc.rs`）同一套帧与 etm 约定。

use cbc::cipher::{KeyIvInit, StreamCipher};
use rand_core::{OsRng, RngCore};
use salsa20::Salsa20;

use crate::contract::{Identified, SymmetricCipher};
use crate::error::Result;
use crate::internal::etm;
use crate::key::Key;

const LABEL: &str = "Salsa20";
/// Salsa20 的 nonce 是 64 位（8 字节）；即名称里的 20 之外的变体参数都在密钥里。
const NONCE_LEN: usize = 8;

/// Salsa20/20 加密器。
#[derive(Debug)]
pub struct Salsa20Encryptor {
    key: Key<32>,
}

impl Salsa20Encryptor {
    pub const IDENTIFIER: &'static str = "salsa20";

    pub fn new(key: [u8; 32]) -> Self {
        Self { key: Key::new(key) }
    }

    pub fn from_slice(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Key::from_slice(key, LABEL)?,
        })
    }
}

impl Identified for Salsa20Encryptor {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl SymmetricCipher for Salsa20Encryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let mut buffer = plaintext.to_vec();
        Salsa20::new_from_slices(self.key.as_bytes(), &nonce)
            .expect("key and nonce lengths are fixed")
            .apply_keystream(&mut buffer);

        Ok(etm::pack(&nonce, &buffer, self.key.as_bytes()))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (nonce, body) =
            etm::unpack_and_verify(ciphertext, NONCE_LEN, self.key.as_bytes(), LABEL)?;

        let mut buffer = body.to_vec();
        Salsa20::new_from_slices(self.key.as_bytes(), nonce)
            .expect("key and nonce lengths were verified")
            .apply_keystream(&mut buffer);
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    /// 十六进制字符串 → 字节：KAT 向量照抄 eSTREAM 验证向量文本，避免手工转写。
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// Salsa20/20（256 位密钥、8 字节 nonce）官方向量：直接调用裸密钥流 ——
    /// 封装层的往返测试抓不出「密钥流整体错位」。第一条 = eSTREAM/ECRYPT 验证
    /// 向量（256-bit Set 1 vector 0，只覆盖计数块 0）；第二条 = Bernstein
    /// 《The Salsa20 family of stream ciphers》§4.1 规范向量（256 字节跨 4 个
    /// 计数块，覆盖计数器的字节序与跨块递增）。两条均与 salsa20 crate 自带
    /// 测试一致，第二条数值另经独立 Python 复算核对。
    #[test]
    fn bare_keystream_matches_estream_vectors() {
        let key = unhex("8000000000000000000000000000000000000000000000000000000000000000");
        let nonce = unhex("0000000000000000");
        let mut keystream = [0u8; 64];
        Salsa20::new_from_slices(&key, &nonce)
            .unwrap()
            .apply_keystream(&mut keystream);
        assert_eq!(
            keystream.as_slice(),
            unhex(concat!(
                "e3be8fdd8beca2e3ea8ef9475b29a6e7",
                "003951e1097a5c38d23b7a5fad9f6844",
                "b22c97559e2723c7cbbd3fe4fc8d9a07",
                "44652a83e72a9c461876af4d7ef1a117"
            ))
            .as_slice()
        );

        let key = unhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let nonce = unhex("0301040105090206");
        let mut keystream = [0u8; 256];
        Salsa20::new_from_slices(&key, &nonce)
            .unwrap()
            .apply_keystream(&mut keystream);
        assert_eq!(
            keystream.as_slice(),
            unhex(concat!(
                "6ebcbdbf76fccc64ab05542bee8a67cb",
                "c28fa2e141fbefbb3a2f9b221909c8d7",
                "d4295258cb539770dd24d7ac3443769f",
                "fa27a50e60644264dc8b6b612683372e",
                "085d0a12bf240b189ce2b78289862b56",
                "fdc9fcffc33bef9325a2e81b98fb3fb9",
                "aa04cf434615ceffeb985c1cb08d8440",
                "e90b1d56ddeaea16d9e15affff1f698c",
                "483c7a466af1fe062574adfd2b06a62b",
                "4d98440719ea776385c470349a7ed696",
                "9583463ed5d26b8fefccb205da0f5bfa",
                "98c77812fe756b09eacc282aa42f4baf",
                "a79633189046e2b20f35b3e0e54aa3b9",
                "29e23c0f47dc7bcd4f928b2a9764be7d",
                "4b8a50f980a50b35ad8087375e0c556e",
                "cbe6a7161e8653ce9391e1e6710ed4f1"
            ))
            .as_slice()
        );
    }

    #[test]
    fn roundtrip_including_multi_block_and_empty() {
        let encryptor = Salsa20Encryptor::new([3u8; 32]);
        // 200 字节跨 4 个计数块（每块 64 字节）。
        for plaintext in [b"".as_slice(), b"a", b"abc", b"abcd", &[0xffu8; 200]] {
            let blob = encryptor.encrypt(plaintext).unwrap();
            assert_eq!(encryptor.decrypt(&blob).unwrap(), plaintext);
        }
    }

    #[test]
    fn ciphertext_differs_from_plaintext_and_tamper_fails() {
        let encryptor = Salsa20Encryptor::new([3u8; 32]);
        let blob = encryptor.encrypt(b"0123456789").unwrap();
        // 帧头 2 + nonce 8 + MAC 32 = 42。
        assert_ne!(&blob[42..], b"0123456789");

        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            encryptor.decrypt(&tampered).unwrap_err(),
            Error::MacVerificationFailed { label: LABEL }
        );
    }

    #[test]
    fn wrong_key_fails_mac() {
        let blob = Salsa20Encryptor::new([3u8; 32]).encrypt(b"secret").unwrap();
        let other = Salsa20Encryptor::new([4u8; 32]);
        assert_eq!(
            other.decrypt(&blob).unwrap_err(),
            Error::MacVerificationFailed { label: LABEL }
        );
    }

    #[test]
    fn nonce_is_fresh_per_encryption() {
        let encryptor = Salsa20Encryptor::new([3u8; 32]);
        let first = encryptor.encrypt(b"same plaintext").unwrap();
        let second = encryptor.encrypt(b"same plaintext").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn invalid_prefix_and_too_short_are_rejected() {
        let encryptor = Salsa20Encryptor::new([3u8; 32]);
        assert_eq!(
            encryptor.decrypt(b"v9 not a blob").unwrap_err(),
            Error::InvalidPrefix { label: LABEL }
        );
        assert_eq!(
            encryptor.decrypt(b"v1 short").unwrap_err(),
            Error::TooShort { label: LABEL }
        );
    }

    #[test]
    fn key_length_is_checked() {
        assert_eq!(
            Salsa20Encryptor::from_slice(&[0u8; 16]).unwrap_err(),
            Error::InvalidKeyLength {
                label: LABEL,
                expected: 32,
                got: 16
            }
        );
    }
}
