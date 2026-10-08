// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! IETF ChaCha20-Poly1305（RFC 8439，96-bit nonce）；载荷：`v1 | Nonce(12) | Tag(16) | 密文`。
//!
//! 与 `sodium-xchacha20` 是同一族原语：密钥、tag、底层 crate 都相同，区别只在
//! nonce 宽度（12 字节 vs 24 字节）。nonce 每次随机生成，12 字节在单密钥下
//! 可安全处理海量消息（RFC 8439 §4 的生日界远大于本库的密钥生命周期）。

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};
use rand_core::{OsRng, RngCore};

use crate::contract::{Identified, SymmetricCipher};
use crate::error::{Error, Result};
use crate::key::Key;

const LABEL: &str = "ChaCha20-Poly1305-IETF";
const PREFIX: &[u8] = b"v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// IETF ChaCha20-Poly1305 加密器。
#[derive(Debug)]
pub struct ChaCha20Poly1305IetfEncryptor {
    key: Key<32>,
}

impl ChaCha20Poly1305IetfEncryptor {
    pub const IDENTIFIER: &'static str = "chacha20-poly1305-ietf";

    pub fn new(key: [u8; 32]) -> Self {
        Self { key: Key::new(key) }
    }

    pub fn from_slice(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Key::from_slice(key, LABEL)?,
        })
    }

    /// 显式 nonce 的加密，返回完整载荷（`v1 | Nonce | Tag | 密文`）。
    ///
    /// 生产路径只经由 [`SymmetricCipher::encrypt`] 调用（`aad` 恒为 `b""`）；
    /// `aad` 参数是为了让测试能对 RFC 8439 §2.8.2 的官方向量（带 12 字节 AAD）
    /// 做逐字节比对，而不必自造期望值。
    pub(crate) fn encrypt_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        // Key<32> 保证长度，new_from_slice 不会失败。
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_bytes())
            .expect("key length is fixed at 32");

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, &mut buffer)
            .map_err(|_| Error::EncryptionFailed { label: LABEL })?;

        let mut blob = Vec::with_capacity(PREFIX.len() + NONCE_LEN + TAG_LEN + buffer.len());
        blob.extend_from_slice(PREFIX);
        blob.extend_from_slice(nonce);
        blob.extend_from_slice(&tag);
        blob.extend_from_slice(&buffer);
        Ok(blob)
    }

    /// 显式 AAD 的解密（`aad` 的用途同上，生产路径恒为 `b""`）。
    pub(crate) fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let body = ciphertext
            .strip_prefix(PREFIX)
            .ok_or(Error::InvalidPrefix { label: LABEL })?;
        if body.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::TooShort { label: LABEL });
        }

        let (nonce, rest) = body.split_at(NONCE_LEN);
        let (tag, ct) = rest.split_at(TAG_LEN);

        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_bytes())
            .expect("key length is fixed at 32");
        let mut buffer = ct.to_vec();
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(nonce),
                aad,
                &mut buffer,
                Tag::from_slice(tag),
            )
            .map_err(|_| Error::DecryptionFailed { label: LABEL })?;
        Ok(buffer)
    }
}

impl Identified for ChaCha20Poly1305IetfEncryptor {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl SymmetricCipher for ChaCha20Poly1305IetfEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        self.encrypt_with_nonce(&nonce, b"", plaintext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_with_aad(ciphertext, b"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::hex_decode;

    // 官方向量：RFC 8439 §2.8.2（Example and Test Vector for
    // AEAD_CHACHA20_POLY1305），逐字节誊自 RFC 文本
    // www.rfc-editor.org/rfc/rfc8439.txt（2026-10 取用）。
    //
    // nonce 注意：RFC 把 12 字节 nonce 拆成「IV（8 字节）4041424344454647」与
    // 「32-bit fixed-common part（sender id=7）07000000」两段分别列出，但实际
    // nonce 是 fixed-common part 在前 —— RFC 自己的 ChaCha 状态字给出
    // 00000007 43424140 47464544（§2.8.2 "Setup for generating Poly1305
    // one-time key"），RustCrypto 的 crate 测试与独立实现复算也一致。
    // 明文 114 字节、无填充（Poly1305 的 16 字节对齐只在 MAC 输入侧，不进密文）。
    const KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const NONCE: &str = "070000004041424344454647";
    const AAD: &str = "50515253c0c1c2c3c4c5c6c7";
    const PLAINTEXT: &str = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const CIPHERTEXT: &str = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
                              3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b\
                              3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7\
                              bc3ff4def08e4b7a9de576d26586cec64b6116";
    const TAG: &str = "1ae10b594f09e26a7e902ecbd0600691";

    #[test]
    fn kat_rfc_8439_2_8_2_is_byte_for_byte() {
        let nonce: [u8; NONCE_LEN] = hex_decode(NONCE).unwrap().try_into().unwrap();
        let aad = hex_decode(AAD).unwrap();
        let ct = hex_decode(CIPHERTEXT).unwrap();
        let tag = hex_decode(TAG).unwrap();
        // 先验证「无填充」：官方密文长度 == 官方明文长度。
        assert_eq!(ct.len(), PLAINTEXT.len());

        let encryptor =
            ChaCha20Poly1305IetfEncryptor::new(hex_decode(KEY).unwrap().try_into().unwrap());

        let mut expected = PREFIX.to_vec();
        expected.extend_from_slice(&nonce);
        expected.extend_from_slice(&tag);
        expected.extend_from_slice(&ct);
        assert_eq!(
            encryptor.encrypt_with_nonce(&nonce, &aad, PLAINTEXT.as_bytes()),
            Ok(expected)
        );

        // 反方向：官方密文帧解出官方明文。
        let blob = encryptor
            .encrypt_with_nonce(&nonce, &aad, PLAINTEXT.as_bytes())
            .unwrap();
        assert_eq!(
            encryptor.decrypt_with_aad(&blob, &aad).unwrap(),
            PLAINTEXT.as_bytes()
        );
    }

    #[test]
    fn roundtrip_and_tamper_detection() {
        let encryptor = ChaCha20Poly1305IetfEncryptor::new([7u8; 32]);
        let blob = encryptor.encrypt(b"data").unwrap();
        assert_eq!(blob.len(), 2 + NONCE_LEN + TAG_LEN + 4);
        assert_eq!(encryptor.decrypt(&blob).unwrap(), b"data");

        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            encryptor.decrypt(&tampered).unwrap_err(),
            Error::DecryptionFailed { label: LABEL }
        );
    }

    #[test]
    fn every_encrypt_uses_a_fresh_nonce() {
        let encryptor = ChaCha20Poly1305IetfEncryptor::new([7u8; 32]);
        let first = encryptor.encrypt(b"same").unwrap();
        let second = encryptor.encrypt(b"same").unwrap();
        assert_ne!(first, second);
        assert_ne!(first[2..2 + NONCE_LEN], second[2..2 + NONCE_LEN]);
    }

    #[test]
    fn wrong_key_and_bad_prefix_fail() {
        let blob = ChaCha20Poly1305IetfEncryptor::new([7u8; 32])
            .encrypt(b"x")
            .unwrap();
        let other = ChaCha20Poly1305IetfEncryptor::new([8u8; 32]);
        assert_eq!(
            other.decrypt(&blob).unwrap_err(),
            Error::DecryptionFailed { label: LABEL }
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
            ChaCha20Poly1305IetfEncryptor::from_slice(&[0u8; 16]).unwrap_err(),
            Error::InvalidKeyLength {
                label: LABEL,
                expected: 32,
                got: 16
            }
        );
    }
}
