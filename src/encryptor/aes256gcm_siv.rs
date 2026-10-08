// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! AES-256-GCM-SIV（RFC 8452，误用稳健 AEAD）；载荷：`v1 | Nonce(12) | Tag(16) | 密文`。
//!
//! 与 `aes-256-gcm` 的区别：GCM-SIV 用合成 IV（先以 nonce + 明文派生 tag，再以
//! tag 作为 CTR 计数器）——nonce 复用不会像 GCM 那样泄露异或与认证密钥，代价是
//! 每帧多一次 AES 调用。适合 nonce 唯一性难以保证的场景。

use aes_gcm_siv::aead::AeadInPlace;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce, Tag};
use rand_core::{OsRng, RngCore};

use crate::contract::{Identified, SymmetricCipher};
use crate::error::{Error, Result};
use crate::key::Key;

const LABEL: &str = "AES-256-GCM-SIV";
const PREFIX: &[u8] = b"v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// AES-256-GCM-SIV 加密器。
#[derive(Debug)]
pub struct Aes256GcmSivEncryptor {
    key: Key<32>,
}

impl Aes256GcmSivEncryptor {
    pub const IDENTIFIER: &'static str = "aes-256-gcm-siv";

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
    /// 生产路径只经由 [`SymmetricCipher::encrypt`] 调用；独立的 nonce 入口是
    /// 为了让测试能对 RFC 8452 附录 C.2 的官方向量做逐字节比对。
    pub(crate) fn encrypt_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        // Key<32> 保证长度，new_from_slice 不会失败。
        let cipher =
            Aes256GcmSiv::new_from_slice(self.key.as_bytes()).expect("key length is fixed at 32");

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(nonce), b"", &mut buffer)
            .map_err(|_| Error::EncryptionFailed { label: LABEL })?;

        let mut blob = Vec::with_capacity(PREFIX.len() + NONCE_LEN + TAG_LEN + buffer.len());
        blob.extend_from_slice(PREFIX);
        blob.extend_from_slice(nonce);
        blob.extend_from_slice(&tag);
        blob.extend_from_slice(&buffer);
        Ok(blob)
    }
}

impl Identified for Aes256GcmSivEncryptor {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl SymmetricCipher for Aes256GcmSivEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        self.encrypt_with_nonce(&nonce, plaintext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let body = ciphertext
            .strip_prefix(PREFIX)
            .ok_or(Error::InvalidPrefix { label: LABEL })?;
        if body.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::TooShort { label: LABEL });
        }

        let (nonce, rest) = body.split_at(NONCE_LEN);
        let (tag, ct) = rest.split_at(TAG_LEN);

        let cipher =
            Aes256GcmSiv::new_from_slice(self.key.as_bytes()).expect("key length is fixed at 32");
        let mut buffer = ct.to_vec();
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(nonce),
                b"",
                &mut buffer,
                Tag::from_slice(tag),
            )
            .map_err(|_| Error::DecryptionFailed { label: LABEL })?;
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::hex_decode;

    // 官方向量：RFC 8452 附录 C.2（AEAD_AES_256_GCM_SIV），逐字节誊自
    // RFC 文本 www.rfc-editor.org/rfc/rfc8452.txt（2026-10 取用）。
    // 该附录的 Result 是「密文 ‖ Tag」，本库帧把 Tag 提前（见文件头）。
    const KEY: &str = "0100000000000000000000000000000000000000000000000000000000000000";
    const NONCE: &str = "030000000000000000000000";

    /// (明文, 密文, Tag) —— 附录 C.2 前四组向量（AAD 均为 0 字节）。
    const VECTORS: &[(&str, &str, &str)] = &[
        ("", "", "07f5f4169bbf55a8400cd47ea6fd400f"),
        (
            "0100000000000000",
            "c2ef328e5c71c83b",
            "843122130f7364b761e0b97427e3df28",
        ),
        (
            "01000000000000000000000000000000",
            "85a01b63025ba19b7fd3ddfc033b3e76",
            "c9eac6fa700942702e90862383c6c366",
        ),
        (
            "0100000000000000000000000000000002000000000000000000000000000000",
            "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027f",
            "e819e63abcd020b006a976397632eb5d",
        ),
    ];

    #[test]
    fn kat_rfc_8452_appendix_c_2_is_byte_for_byte() {
        let encryptor = Aes256GcmSivEncryptor::new(hex_decode(KEY).unwrap().try_into().unwrap());
        let nonce: [u8; NONCE_LEN] = hex_decode(NONCE).unwrap().try_into().unwrap();

        for &(pt_hex, ct_hex, tag_hex) in VECTORS {
            let plaintext = hex_decode(pt_hex).unwrap();
            let ct = hex_decode(ct_hex).unwrap();
            let tag = hex_decode(tag_hex).unwrap();
            // 先验证「无填充」：官方密文长度 == 官方明文长度。
            assert_eq!(ct.len(), plaintext.len(), "plaintext {pt_hex}");

            let mut expected = PREFIX.to_vec();
            expected.extend_from_slice(&nonce);
            expected.extend_from_slice(&tag);
            expected.extend_from_slice(&ct);
            let blob = encryptor.encrypt_with_nonce(&nonce, &plaintext).unwrap();
            assert_eq!(blob, expected, "plaintext {pt_hex}");

            // 反方向：官方密文帧（本库布局）解出官方明文。
            assert_eq!(encryptor.decrypt(&blob).unwrap(), plaintext);
        }
    }

    #[test]
    fn roundtrip_and_tamper_detection() {
        let encryptor = Aes256GcmSivEncryptor::new([7u8; 32]);
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

        // nonce 也被认证：改 nonce 位同样必败（GCM 里这会改变计数器起点）。
        let mut nonce_tampered = blob.clone();
        nonce_tampered[2] ^= 0x01;
        assert_eq!(
            encryptor.decrypt(&nonce_tampered).unwrap_err(),
            Error::DecryptionFailed { label: LABEL }
        );
    }

    #[test]
    fn every_encrypt_uses_a_fresh_nonce() {
        let encryptor = Aes256GcmSivEncryptor::new([7u8; 32]);
        let first = encryptor.encrypt(b"same").unwrap();
        let second = encryptor.encrypt(b"same").unwrap();
        assert_ne!(first, second);
        assert_ne!(first[2..2 + NONCE_LEN], second[2..2 + NONCE_LEN]);
    }

    #[test]
    fn wrong_key_and_bad_prefix_fail() {
        let blob = Aes256GcmSivEncryptor::new([7u8; 32]).encrypt(b"x").unwrap();
        let other = Aes256GcmSivEncryptor::new([8u8; 32]);
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
            Aes256GcmSivEncryptor::from_slice(&[0u8; 16]).unwrap_err(),
            Error::InvalidKeyLength {
                label: LABEL,
                expected: 32,
                got: 16
            }
        );
    }
}
