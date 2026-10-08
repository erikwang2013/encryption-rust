// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 国密 ZUC-256 流密码（祖冲之密码算法 ZUC-256 规范 v1.1，2018-01）+
//! HMAC-SHA256（encrypt-then-MAC）；载荷：`v1 | IV(23) | MAC(32) | 密文（与密钥流异或）`。
//! 密钥 32 字节（256 位），IV 定长 23 字节（184 位）——ZUC-256 规范的取值，
//! 均与 ZUC-128（16 字节密钥 / 16 字节 IV）不同，两者不可混用密钥材料。
//!
//! 注：GB/T 33133.2-2021 是「祖冲之序列密码算法 第2部分：保密性算法」
//! （128 位密钥版本），ZUC-256 的规范文本为上述 ZUC256-version1.1 文档，
//! 尚无对应 GB/T 编号；定值向量的出处见测试模块。

use rand_core::{OsRng, RngCore};
use zuc::zuc256::Zuc256Keystream;

use crate::contract::{Identified, SymmetricCipher};
use crate::error::Result;
use crate::internal::etm;
use crate::key::Key;

const LABEL: &str = "ZUC-256";
const IV_LEN: usize = 23;

/// ZUC-256 加密器。
#[derive(Debug)]
pub struct Zuc256Encryptor {
    key: Key<32>,
}

impl Zuc256Encryptor {
    pub const IDENTIFIER: &'static str = "zuc-256";

    pub fn new(key: [u8; 32]) -> Self {
        Self { key: Key::new(key) }
    }

    pub fn from_slice(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Key::from_slice(key, LABEL)?,
        })
    }
}

impl Identified for Zuc256Encryptor {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl SymmetricCipher for Zuc256Encryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut iv = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv);
        // 注：底层按 ZUC-256 规范取 iv[22] 的低 6 bit，有效 IV 熵为 182 bit。

        let mut buffer = plaintext.to_vec();
        xor_keystream(self.key.as_bytes(), &iv, &mut buffer);

        Ok(etm::pack(&iv, &buffer, self.key.as_bytes()))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (iv, body) = etm::unpack_and_verify(ciphertext, IV_LEN, self.key.as_bytes(), LABEL)?;
        // unpack_and_verify 已保证 IV 长度恰为 23。
        let iv: &[u8; IV_LEN] = iv.try_into().expect("iv length was verified");

        let mut buffer = body.to_vec();
        xor_keystream(self.key.as_bytes(), iv, &mut buffer);
        Ok(buffer)
    }
}

/// 密钥流异或（大端 32 位字；尾部不足一字时取该字前缀字节，
/// 与 zuc128_xor_inplace 的字节对齐语义一致）。
///
/// ponytail: 与 ZUC-128 一致，单帧载荷全量驻留内存、无流式接口——
/// 能驻留内存的载荷远达不到规范的用量上限；真要分片加密再改增量接口。
fn xor_keystream(key: &[u8; 32], iv: &[u8; IV_LEN], data: &mut [u8]) {
    let mut keystream = Zuc256Keystream::new(key, iv);
    for chunk in data.chunks_mut(4) {
        let word = keystream.generate().to_be_bytes();
        for (byte, ks) in chunk.iter_mut().zip(word.iter()) {
            *byte ^= ks;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    /// 定值测试（KAT）：ZUC256-version1.1 规范文档附带的测试向量——
    /// <http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180416526664982687.pdf>
    /// （zuc 0.4.1 内嵌的 EXAMPLE1/EXAMPLE2 同源；全零向量亦见于《密码学报》
    /// 2018 年第 5 卷第 2 期 ZUC-256 一文，出处一致，非自造）。
    /// 往返测试抓不出「密钥流整体错位」——这两个向量是规格符合性的锚点。
    static EXAMPLES: &[(&[u8; 32], &[u8; IV_LEN], [u32; 20])] = &[
        (
            &[0u8; 32],
            &[0u8; IV_LEN],
            [
                0x58d0_3ad6,
                0x2e03_2ce2,
                0xdafc_683a,
                0x39bd_cb03,
                0x52a2_bc67,
                0xf1b7_de74,
                0x163c_e3a1,
                0x01ef_5558,
                0x9639_d75b,
                0x95fa_681b,
                0x7f09_0df7,
                0x5639_1ccc,
                0x903b_7612,
                0x744d_544c,
                0x17bc_3fad,
                0x8b16_3b08,
                0x2178_7c0b,
                0x9777_5bb8,
                0x4943_c6bb,
                0xe8ad_8afd,
            ],
        ),
        (
            &[0xffu8; 32],
            &[0xffu8; IV_LEN],
            [
                0x3356_cbae,
                0xd1a1_c18b,
                0x6baa_4ffe,
                0x343f_777c,
                0x9e15_128f,
                0x251a_b65b,
                0x949f_7b26,
                0xef71_57f2,
                0x96dd_2fa9,
                0xdf95_e3ee,
                0x7a5b_e02e,
                0xc32b_a585,
                0x505a_f316,
                0xc2f9_ded2,
                0x7cdb_d935,
                0xe441_ce11,
                0x15fd_0a80,
                0xbb7a_ef67,
                0x6898_9416,
                0xb8fa_c8c2,
            ],
        ),
    ];

    #[test]
    fn matches_standard_keystream_vectors() {
        for (key, iv, expected) in EXAMPLES {
            // 全零缓冲区异或后即密钥流本身。
            let mut buffer = [0u8; 80];
            xor_keystream(key, iv, &mut buffer);
            for (word, want) in buffer.as_chunks::<4>().0.iter().zip(expected.iter()) {
                assert_eq!(u32::from_be_bytes(*word), *want);
            }
        }
    }

    #[test]
    fn roundtrip_including_partial_word_tail() {
        let encryptor = Zuc256Encryptor::new([3u8; 32]);
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
            assert_eq!(blob.len(), 2 + IV_LEN + etm::MAC_LEN + plaintext.len());
            assert_eq!(encryptor.decrypt(&blob).unwrap(), plaintext);
        }
    }

    #[test]
    fn ciphertext_differs_from_plaintext_and_tamper_fails() {
        let encryptor = Zuc256Encryptor::new([3u8; 32]);
        let blob = encryptor.encrypt(b"0123456789").unwrap();
        assert_ne!(&blob[57..], b"0123456789");

        // 改密文末字节。
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            encryptor.decrypt(&tampered).unwrap_err(),
            Error::MacVerificationFailed { label: LABEL }
        );

        // 改 MAC 字节。
        let mut tampered = blob.clone();
        tampered[2 + IV_LEN] ^= 0x01;
        assert_eq!(
            encryptor.decrypt(&tampered).unwrap_err(),
            Error::MacVerificationFailed { label: LABEL }
        );
    }

    #[test]
    fn every_encrypt_uses_a_fresh_iv() {
        let encryptor = Zuc256Encryptor::new([3u8; 32]);
        let first = encryptor.encrypt(b"same").unwrap();
        let second = encryptor.encrypt(b"same").unwrap();
        assert_ne!(first, second);
        assert_ne!(first[2..2 + IV_LEN], second[2..2 + IV_LEN]);
    }

    #[test]
    fn wrong_key_and_bad_frame_fail() {
        let blob = Zuc256Encryptor::new([3u8; 32]).encrypt(b"x").unwrap();
        let other = Zuc256Encryptor::new([4u8; 32]);
        assert_eq!(
            other.decrypt(&blob).unwrap_err(),
            Error::MacVerificationFailed { label: LABEL }
        );
        assert_eq!(
            other.decrypt(b"v9....").unwrap_err(),
            Error::InvalidPrefix { label: LABEL }
        );
        assert_eq!(
            other.decrypt(b"v1short").unwrap_err(),
            Error::TooShort { label: LABEL }
        );
    }

    #[test]
    fn key_length_is_checked() {
        assert_eq!(
            Zuc256Encryptor::from_slice(&[0u8; 16]).unwrap_err(),
            Error::InvalidKeyLength {
                label: LABEL,
                expected: 32,
                got: 16
            }
        );
    }

    #[test]
    fn identifier_matches_registered_name() {
        assert_eq!(Zuc256Encryptor::new([0u8; 32]).identifier(), "zuc-256");
    }
}
