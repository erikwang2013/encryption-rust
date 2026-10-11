// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! AES-256-GCM（认证加密）；载荷：`v1 | IV(12) | Tag(16) | 密文`。

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use rand_core::{OsRng, RngCore};

use crate::contract::{Identified, SymmetricCipher};
use crate::error::{Error, Result};
use crate::key::Key;

const LABEL: &str = "AES-256-GCM";
const PREFIX: &[u8] = b"v1";
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// AES-256-GCM 加密器。
///
/// 块密码实例在构造时就建立（轮密钥只展开一次），加密与解密都复用它——
/// 短载荷（本库的典型场景）下，避免每次调用重跑一遍 AES 密钥编排。
pub struct Aes256GcmEncryptor {
    cipher: Aes256Gcm,
}

impl Aes256GcmEncryptor {
    pub const IDENTIFIER: &'static str = "aes-256-gcm";

    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(&key).expect("key length is fixed at 32"),
        }
    }

    pub fn from_slice(key: &[u8]) -> Result<Self> {
        // 借 Key<N> 做长度校验；临时副本随其 Drop 清零。
        let key = Key::<32>::from_slice(key, LABEL)?;
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(key.as_bytes()).expect("key length is fixed at 32"),
        })
    }
}

/// 只打印标识符——密钥材质不出现在 `Debug` 里
/// （`Aes256Gcm` 未实现 `Debug`，此类型无法 derive）。
impl std::fmt::Debug for Aes256GcmEncryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes256GcmEncryptor")
            .field("identifier", &Self::IDENTIFIER)
            .finish_non_exhaustive()
    }
}

impl Identified for Aes256GcmEncryptor {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl SymmetricCipher for Aes256GcmEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut iv = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv);

        let mut buffer = plaintext.to_vec();
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&iv), b"", &mut buffer)
            .map_err(|_| Error::EncryptionFailed { label: LABEL })?;

        let mut blob = Vec::with_capacity(PREFIX.len() + IV_LEN + TAG_LEN + buffer.len());
        blob.extend_from_slice(PREFIX);
        blob.extend_from_slice(&iv);
        blob.extend_from_slice(&tag);
        blob.extend_from_slice(&buffer);
        Ok(blob)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let body = ciphertext
            .strip_prefix(PREFIX)
            .ok_or(Error::InvalidPrefix { label: LABEL })?;
        if body.len() < IV_LEN + TAG_LEN {
            return Err(Error::TooShort { label: LABEL });
        }

        let (iv, rest) = body.split_at(IV_LEN);
        let (tag, ct) = rest.split_at(TAG_LEN);

        let mut buffer = ct.to_vec();
        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(iv),
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

    #[test]
    fn roundtrip_and_tamper_detection() {
        let encryptor = Aes256GcmEncryptor::new([7u8; 32]);
        let blob = encryptor.encrypt(b"\xe5\xaf\x86\xe6\x96\x87").unwrap();
        assert_eq!(blob.len(), 2 + IV_LEN + TAG_LEN + 6);
        assert_eq!(
            encryptor.decrypt(&blob).unwrap(),
            b"\xe5\xaf\x86\xe6\x96\x87"
        );

        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            encryptor.decrypt(&tampered).unwrap_err(),
            Error::DecryptionFailed { label: LABEL }
        );
    }

    #[test]
    fn every_encrypt_uses_a_fresh_iv() {
        let encryptor = Aes256GcmEncryptor::new([7u8; 32]);
        let first = encryptor.encrypt(b"same").unwrap();
        let second = encryptor.encrypt(b"same").unwrap();
        assert_ne!(first, second);
        assert_ne!(first[2..14], second[2..14]);
    }

    #[test]
    fn wrong_key_and_bad_prefix_fail() {
        let blob = Aes256GcmEncryptor::new([7u8; 32]).encrypt(b"x").unwrap();
        let other = Aes256GcmEncryptor::new([8u8; 32]);
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
            Aes256GcmEncryptor::from_slice(&[0u8; 16]).unwrap_err(),
            Error::InvalidKeyLength {
                label: LABEL,
                expected: 32,
                got: 16
            }
        );
    }
}
