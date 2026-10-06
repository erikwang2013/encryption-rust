// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! AES-256-CBC + HMAC-SHA256（encrypt-then-MAC，PKCS#7 填充）；
//! 载荷：`v1 | IV(16) | MAC(32) | 密文`。

use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use cbc::{Decryptor, Encryptor};
use rand_core::{OsRng, RngCore};

use crate::contract::{Identified, SymmetricCipher};
use crate::error::{Error, Result};
use crate::internal::etm;
use crate::key::Key;

const LABEL: &str = "AES-256-CBC";
const IV_LEN: usize = 16;

/// AES-256-CBC 加密器（CBC + HMAC，兼容旧环境）。
#[derive(Debug)]
pub struct Aes256CbcEncryptor {
    key: Key<32>,
}

impl Aes256CbcEncryptor {
    pub const IDENTIFIER: &'static str = "aes-256-cbc-hmac";

    pub fn new(key: [u8; 32]) -> Self {
        Self { key: Key::new(key) }
    }

    pub fn from_slice(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Key::from_slice(key, LABEL)?,
        })
    }
}

impl Identified for Aes256CbcEncryptor {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl SymmetricCipher for Aes256CbcEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut iv = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv);

        let ciphertext = Encryptor::<Aes256>::new_from_slices(self.key.as_bytes(), &iv)
            .expect("key and iv lengths are fixed")
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        Ok(etm::pack(&iv, &ciphertext, self.key.as_bytes()))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (iv, body) = etm::unpack_and_verify(ciphertext, IV_LEN, self.key.as_bytes(), LABEL)?;

        Decryptor::<Aes256>::new_from_slices(self.key.as_bytes(), iv)
            .expect("key and iv lengths were verified")
            .decrypt_padded_vec_mut::<Pkcs7>(body)
            .map_err(|_| Error::DecryptionFailed { label: LABEL })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_even_for_empty_plaintext() {
        let encryptor = Aes256CbcEncryptor::new([5u8; 32]);
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
        let encryptor = Aes256CbcEncryptor::new([5u8; 32]);
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
        let blob = Aes256CbcEncryptor::new([5u8; 32])
            .encrypt(b"secret")
            .unwrap();
        let other = Aes256CbcEncryptor::new([6u8; 32]);
        assert_eq!(
            other.decrypt(&blob).unwrap_err(),
            Error::MacVerificationFailed { label: LABEL }
        );
    }

    #[test]
    fn key_length_is_checked() {
        assert_eq!(
            Aes256CbcEncryptor::from_slice(&[0u8; 33]).unwrap_err(),
            Error::InvalidKeyLength {
                label: LABEL,
                expected: 32,
                got: 33
            }
        );
    }
}
