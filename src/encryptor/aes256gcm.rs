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
#[derive(Debug)]
pub struct Aes256GcmEncryptor {
    key: Key<32>,
}

impl Aes256GcmEncryptor {
    pub const IDENTIFIER: &'static str = "aes-256-gcm";

    pub fn new(key: [u8; 32]) -> Self {
        Self { key: Key::new(key) }
    }

    pub fn from_slice(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Key::from_slice(key, LABEL)?,
        })
    }
}

impl Identified for Aes256GcmEncryptor {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl SymmetricCipher for Aes256GcmEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Key<32> 保证长度，new_from_slice 不会失败。
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_bytes()).expect("key length is fixed at 32");

        let mut iv = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv);

        let mut buffer = plaintext.to_vec();
        let tag = cipher
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

        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_bytes()).expect("key length is fixed at 32");
        let mut buffer = ct.to_vec();
        cipher
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
