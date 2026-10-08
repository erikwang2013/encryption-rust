// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! Threefish-512-CBC + HMAC-SHA256（encrypt-then-MAC，PKCS#7 填充）；
//! 载荷：`v1 | IV(64) | MAC(32) | 密文`。块长与密钥均为 512 位。

use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use cbc::{Decryptor, Encryptor};
use rand_core::{OsRng, RngCore};
use threefish::Threefish512;

use crate::contract::{Identified, SymmetricCipher};
use crate::error::{Error, Result};
use crate::internal::etm;
use crate::key::Key;

const LABEL: &str = "Threefish-512-CBC";
/// Threefish-512 的块长是 512 位（64 字节），IV 与之等长。
const IV_LEN: usize = 64;

/// Threefish-512-CBC 加密器（CBC + HMAC；Skein 家族块密码）。
#[derive(Debug)]
pub struct Threefish512CbcEncryptor {
    key: Key<64>,
}

impl Threefish512CbcEncryptor {
    pub const IDENTIFIER: &'static str = "threefish-512-cbc-hmac";

    pub fn new(key: [u8; 64]) -> Self {
        Self { key: Key::new(key) }
    }

    pub fn from_slice(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Key::from_slice(key, LABEL)?,
        })
    }
}

impl Identified for Threefish512CbcEncryptor {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl SymmetricCipher for Threefish512CbcEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut iv = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv);

        let ciphertext = Encryptor::<Threefish512>::new_from_slices(self.key.as_bytes(), &iv)
            .expect("key and iv lengths are fixed")
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        Ok(etm::pack(&iv, &ciphertext, self.key.as_bytes()))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (iv, body) = etm::unpack_and_verify(ciphertext, IV_LEN, self.key.as_bytes(), LABEL)?;

        Decryptor::<Threefish512>::new_from_slices(self.key.as_bytes(), iv)
            .expect("key and iv lengths were verified")
            .decrypt_padded_vec_mut::<Pkcs7>(body)
            .map_err(|_| Error::DecryptionFailed { label: LABEL })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 十六进制字符串 → 字节：KAT 向量照抄官方测试向量文本，避免手工转写。
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// Skein/Threefish 官方 KAT（Threefish-512，tweak 全零 = `KeyInit` 的默认 tweak）：
    /// 前两条链式向量（零密钥 → 以第一段密文为第二段密钥）。直接调用裸块密码 ——
    /// 封装层往返测试抓不出「轮函数 / 密钥表整体错位」。
    ///
    /// 注：threefish 0.5.2 自带的 tests/mod.rs 首行是 `#![cfg(featue = "cipher")]`
    /// （拼写错误），整个测试目标被 cfg 掉、从未跑过；本向量是该实现的事实锚点。
    #[test]
    fn bare_block_cipher_matches_official_kat() {
        use cbc::cipher::{Block, BlockEncrypt, KeyInit};

        let vectors = [
            (
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                concat!(
                    "b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b",
                    "7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"
                ),
            ),
            (
                concat!(
                    "b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b",
                    "7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"
                ),
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                concat!(
                    "f13ca06760dd9bbeab87b6c56f3bbbdb",
                    "e9d08a77978b942ac02d471dc10268f2",
                    "261c3d4330d6ca341f4bd4115dee16a2",
                    "1dcda2a34a0a76fba976174e4cf1e306"
                ),
            ),
        ];

        for (key, plaintext, expected) in vectors {
            let key = unhex(key);
            let plaintext = unhex(plaintext);
            let expected = unhex(expected);

            let cipher = Threefish512::new_from_slice(&key).unwrap();
            let mut block = Block::<Threefish512>::clone_from_slice(&plaintext);
            cipher.encrypt_block(&mut block);
            assert_eq!(block.as_slice(), expected.as_slice());
        }
    }

    #[test]
    fn roundtrip_at_padding_boundaries() {
        let encryptor = Threefish512CbcEncryptor::new([5u8; 64]);
        for plaintext in [
            b"".as_slice(),
            b"x",
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefg",
        ] {
            let blob = encryptor.encrypt(plaintext).unwrap();
            assert_eq!(encryptor.decrypt(&blob).unwrap(), plaintext);
        }
    }

    /// 帧布局：`v1 | IV(64) | MAC(32) | 密文`；64 字节 IV 的线宽是
    /// `etm::unpack_and_verify` 的 `iv_len` 参数唯一容易接错的地方。
    #[test]
    fn frame_uses_64_byte_iv() {
        let encryptor = Threefish512CbcEncryptor::new([5u8; 64]);
        let blob = encryptor.encrypt(b"x").unwrap();
        // v1(2) + IV(64) + MAC(32) + 一个填充后的整块(64)
        assert_eq!(blob.len(), 2 + 64 + 32 + 64);
        assert_eq!(&blob[..2], b"v1");
    }

    #[test]
    fn tampered_blob_fails_mac_before_decrypt() {
        let encryptor = Threefish512CbcEncryptor::new([5u8; 64]);
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
        let blob = Threefish512CbcEncryptor::new([5u8; 64])
            .encrypt(b"secret")
            .unwrap();
        let other = Threefish512CbcEncryptor::new([6u8; 64]);
        assert_eq!(
            other.decrypt(&blob).unwrap_err(),
            Error::MacVerificationFailed { label: LABEL }
        );
    }

    #[test]
    fn iv_is_fresh_per_encryption() {
        let encryptor = Threefish512CbcEncryptor::new([5u8; 64]);
        let first = encryptor.encrypt(b"same plaintext").unwrap();
        let second = encryptor.encrypt(b"same plaintext").unwrap();
        assert_ne!(first, second);
        // 变化必须发生在 IV 段（2..66），不是别的字段。
        assert_ne!(first[2..66], second[2..66]);
    }

    #[test]
    fn invalid_prefix_and_too_short_are_rejected() {
        let encryptor = Threefish512CbcEncryptor::new([5u8; 64]);
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
            Threefish512CbcEncryptor::from_slice(&[0u8; 32]).unwrap_err(),
            Error::InvalidKeyLength {
                label: LABEL,
                expected: 64,
                got: 32
            }
        );
    }
}
