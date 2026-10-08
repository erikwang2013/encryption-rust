// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! Camellia-256-CBC + HMAC-SHA256（encrypt-then-MAC，PKCS#7 填充）；
//! 载荷：`v1 | IV(16) | MAC(32) | 密文`。

use camellia::Camellia256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use cbc::{Decryptor, Encryptor};
use rand_core::{OsRng, RngCore};

use crate::contract::{Identified, SymmetricCipher};
use crate::error::{Error, Result};
use crate::internal::etm;
use crate::key::Key;

const LABEL: &str = "Camellia-256-CBC";
const IV_LEN: usize = 16;

/// Camellia-256-CBC 加密器（CBC + HMAC；ISO/IEC 18033-3 块密码）。
#[derive(Debug)]
pub struct Camellia256CbcEncryptor {
    key: Key<32>,
}

impl Camellia256CbcEncryptor {
    pub const IDENTIFIER: &'static str = "camellia-256-cbc-hmac";

    pub fn new(key: [u8; 32]) -> Self {
        Self { key: Key::new(key) }
    }

    pub fn from_slice(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Key::from_slice(key, LABEL)?,
        })
    }
}

impl Identified for Camellia256CbcEncryptor {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl SymmetricCipher for Camellia256CbcEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut iv = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv);

        let ciphertext = Encryptor::<Camellia256>::new_from_slices(self.key.as_bytes(), &iv)
            .expect("key and iv lengths are fixed")
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        Ok(etm::pack(&iv, &ciphertext, self.key.as_bytes()))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (iv, body) = etm::unpack_and_verify(ciphertext, IV_LEN, self.key.as_bytes(), LABEL)?;

        Decryptor::<Camellia256>::new_from_slices(self.key.as_bytes(), iv)
            .expect("key and iv lengths were verified")
            .decrypt_padded_vec_mut::<Pkcs7>(body)
            .map_err(|_| Error::DecryptionFailed { label: LABEL })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 十六进制字符串 → 字节：KAT 向量照抄标准文本，避免手工转写。
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 3713 Appendix A 的 Camellia-256 示例（ISO/IEC 18033-3 同源）：
    /// 直接调用裸块密码 —— 封装层的往返测试抓不出「轮函数 / 密钥表整体错位」。
    #[test]
    fn bare_block_cipher_matches_rfc3713_vector() {
        use cbc::cipher::{Block, BlockEncrypt, KeyInit};

        let key = unhex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
        let plaintext = unhex("0123456789abcdeffedcba9876543210");
        let expected = unhex("9acc237dff16d76c20ef7c919e3a7509");

        let cipher = Camellia256::new_from_slice(&key).unwrap();
        let mut block = Block::<Camellia256>::clone_from_slice(&plaintext);
        cipher.encrypt_block(&mut block);
        assert_eq!(block.as_slice(), expected.as_slice());
    }

    #[test]
    fn roundtrip_at_padding_boundaries() {
        let encryptor = Camellia256CbcEncryptor::new([5u8; 32]);
        for plaintext in [
            b"".as_slice(),
            b"x",
            b"0123456789abcdef",
            b"0123456789abcdefg",
        ] {
            let blob = encryptor.encrypt(plaintext).unwrap();
            assert_eq!(encryptor.decrypt(&blob).unwrap(), plaintext);
        }
    }

    #[test]
    fn tampered_blob_fails_mac_before_decrypt() {
        let encryptor = Camellia256CbcEncryptor::new([5u8; 32]);
        let mut blob = encryptor.encrypt(b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert_eq!(
            encryptor.decrypt(&blob).unwrap_err(),
            Error::MacVerificationFailed { label: LABEL }
        );
    }

    #[test]
    fn wrong_key_fails_mac() {
        let blob = Camellia256CbcEncryptor::new([5u8; 32])
            .encrypt(b"secret")
            .unwrap();
        let other = Camellia256CbcEncryptor::new([6u8; 32]);
        assert_eq!(
            other.decrypt(&blob).unwrap_err(),
            Error::MacVerificationFailed { label: LABEL }
        );
    }

    #[test]
    fn iv_is_fresh_per_encryption() {
        let encryptor = Camellia256CbcEncryptor::new([5u8; 32]);
        let first = encryptor.encrypt(b"same plaintext").unwrap();
        let second = encryptor.encrypt(b"same plaintext").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn invalid_prefix_and_too_short_are_rejected() {
        let encryptor = Camellia256CbcEncryptor::new([5u8; 32]);
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
            Camellia256CbcEncryptor::from_slice(&[0u8; 16]).unwrap_err(),
            Error::InvalidKeyLength {
                label: LABEL,
                expected: 32,
                got: 16
            }
        );
    }
}
