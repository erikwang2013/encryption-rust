// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 国密 ZUC-128 流密码（GB/T 33133.1-2016）+ HMAC-SHA256（encrypt-then-MAC）；
//! 载荷：`v1 | IV(16) | MAC(32) | 密文（与密钥流异或）`。密钥 16 字节。

use rand_core::{OsRng, RngCore};
use zuc::zuc128::zuc128_xor_inplace;

use crate::contract::{Identified, SymmetricCipher};
use crate::error::Result;
use crate::internal::etm;
use crate::key::Key;

const LABEL: &str = "ZUC";
const IV_LEN: usize = 16;

/// ZUC-128 加密器。
#[derive(Debug)]
pub struct Zuc128Encryptor {
    key: Key<16>,
}

impl Zuc128Encryptor {
    pub const IDENTIFIER: &'static str = "zuc-128";

    pub fn new(key: [u8; 16]) -> Self {
        Self { key: Key::new(key) }
    }

    pub fn from_slice(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Key::from_slice(key, LABEL)?,
        })
    }
}

impl Identified for Zuc128Encryptor {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl SymmetricCipher for Zuc128Encryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut iv = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv);

        let mut buffer = plaintext.to_vec();
        let bit_len = buffer.len() * 8;
        zuc128_xor_inplace(self.key.as_bytes(), &iv, &mut buffer, bit_len);

        Ok(etm::pack(&iv, &buffer, self.key.as_bytes()))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (iv, body) = etm::unpack_and_verify(ciphertext, IV_LEN, self.key.as_bytes(), LABEL)?;
        // unpack_and_verify 已保证 IV 长度恰为 16。
        let iv: &[u8; IV_LEN] = iv.try_into().expect("iv length was verified");

        let mut buffer = body.to_vec();
        let bit_len = buffer.len() * 8;
        zuc128_xor_inplace(self.key.as_bytes(), iv, &mut buffer, bit_len);
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    /// GB/T 33133.1 标准向量：全零密钥 + 全零 IV 的前两个密钥流字为
    /// `0x27bede74`、`0x018082da`（与 PHP 版 `GuomiZucTest` 固化的向量一致，
    /// 也是 zuc crate 自带的 EXAMPLE1）。往返测试抓不出「密钥流整体错位」——
    /// 这个向量是规格符合性的锚点。
    #[test]
    fn matches_gb_standard_keystream_vector() {
        let mut buffer = [0u8; 8];
        zuc128_xor_inplace(&[0u8; 16], &[0u8; 16], &mut buffer, 64);
        assert_eq!(buffer, [0x27, 0xbe, 0xde, 0x74, 0x01, 0x80, 0x82, 0xda]);
    }

    #[test]
    fn roundtrip_including_partial_word_tail() {
        let encryptor = Zuc128Encryptor::new([3u8; 16]);
        // 覆盖 4 字节外的尾巴（密钥流按字生成，长度不足时取前缀字节）。
        for plaintext in [
            b"".as_slice(),
            b"a",
            b"abc",
            b"abcd",
            b"abcde",
            &[0xffu8; 40],
        ] {
            let blob = encryptor.encrypt(plaintext).unwrap();
            assert_eq!(encryptor.decrypt(&blob).unwrap(), plaintext);
        }
    }

    #[test]
    fn ciphertext_differs_from_plaintext_and_tamper_fails() {
        let encryptor = Zuc128Encryptor::new([3u8; 16]);
        let blob = encryptor.encrypt(b"0123456789").unwrap();
        assert_ne!(&blob[50..], b"0123456789");

        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            encryptor.decrypt(&tampered).unwrap_err(),
            Error::MacVerificationFailed { label: LABEL }
        );
    }
}
