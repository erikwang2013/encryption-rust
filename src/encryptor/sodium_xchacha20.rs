// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! XChaCha20-Poly1305（对应 PHP 版 `SodiumXChaCha20Encryptor`，libsodium 布局）；
//! 载荷：`v1 | Nonce(24) | 密文 ‖ Tag(16)`。
//!
//! 纯 Rust 实现，无需任何系统扩展（原版需要 `ext-sodium`）。

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};

use crate::contract::{Identified, SymmetricCipher};
use crate::error::{Error, Result};
use crate::key::Key;

const LABEL: &str = "XChaCha20-Poly1305";
const PREFIX: &[u8] = b"v1";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// XChaCha20-Poly1305 加密器。
#[derive(Debug)]
pub struct SodiumXChaCha20Encryptor {
    key: Key<32>,
}

impl SodiumXChaCha20Encryptor {
    pub const IDENTIFIER: &'static str = "sodium-xchacha20";

    pub fn new(key: [u8; 32]) -> Self {
        Self { key: Key::new(key) }
    }

    pub fn from_slice(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Key::from_slice(key, LABEL)?,
        })
    }
}

impl Identified for SodiumXChaCha20Encryptor {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl SymmetricCipher for SodiumXChaCha20Encryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_bytes())
            .expect("key length is fixed at 32");

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), b"", &mut buffer)
            .map_err(|_| Error::EncryptionFailed { label: LABEL })?;

        // libsodium 布局：密文在前、tag 在后。
        let mut blob = Vec::with_capacity(PREFIX.len() + NONCE_LEN + buffer.len() + TAG_LEN);
        blob.extend_from_slice(PREFIX);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&buffer);
        blob.extend_from_slice(&tag);
        Ok(blob)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let body = ciphertext
            .strip_prefix(PREFIX)
            .ok_or(Error::InvalidPrefix { label: LABEL })?;
        if body.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::TooShort { label: LABEL });
        }

        let (nonce, rest) = body.split_at(NONCE_LEN);
        let (ct, tag) = rest.split_at(rest.len() - TAG_LEN);

        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_bytes())
            .expect("key length is fixed at 32");
        let mut buffer = ct.to_vec();
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(nonce),
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
        let encryptor = SodiumXChaCha20Encryptor::new([9u8; 32]);
        let blob = encryptor.encrypt(b"data").unwrap();
        assert_eq!(blob.len(), 2 + NONCE_LEN + 4 + TAG_LEN);
        assert_eq!(encryptor.decrypt(&blob).unwrap(), b"data");

        let mut tampered = blob.clone();
        let tag_start = tampered.len() - TAG_LEN;
        tampered[tag_start] ^= 0x01;
        assert_eq!(
            encryptor.decrypt(&tampered).unwrap_err(),
            Error::DecryptionFailed { label: LABEL }
        );
    }

    #[test]
    fn wrong_key_fails() {
        let blob = SodiumXChaCha20Encryptor::new([9u8; 32])
            .encrypt(b"x")
            .unwrap();
        assert_eq!(
            SodiumXChaCha20Encryptor::new([1u8; 32])
                .decrypt(&blob)
                .unwrap_err(),
            Error::DecryptionFailed { label: LABEL }
        );
    }

    #[test]
    fn bad_prefix_and_short_blob() {
        let encryptor = SodiumXChaCha20Encryptor::new([9u8; 32]);
        assert_eq!(
            encryptor.decrypt(b"nope").unwrap_err(),
            Error::InvalidPrefix { label: LABEL }
        );
        assert_eq!(
            encryptor.decrypt(b"v1tiny").unwrap_err(),
            Error::TooShort { label: LABEL }
        );
    }
}
