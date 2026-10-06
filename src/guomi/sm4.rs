// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 国密 SM4-CBC（PKCS#7 填充）+ HMAC-SHA256（encrypt-then-MAC）；
//! 载荷：`v1 | IV(16) | MAC(32) | 密文`。密钥 16 字节。

use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use cbc::{Decryptor, Encryptor};
use rand_core::{OsRng, RngCore};
use sm4::Sm4;

use crate::contract::{Identified, SymmetricCipher};
use crate::error::{Error, Result};
use crate::internal::etm;
use crate::key::Key;

const LABEL: &str = "SM4";
const IV_LEN: usize = 16;

/// SM4-CBC 加密器。
#[derive(Debug)]
pub struct Sm4CbcEncryptor {
    key: Key<16>,
}

impl Sm4CbcEncryptor {
    pub const IDENTIFIER: &'static str = "sm4-cbc";

    pub fn new(key: [u8; 16]) -> Self {
        Self { key: Key::new(key) }
    }

    pub fn from_slice(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Key::from_slice(key, LABEL)?,
        })
    }
}

impl Identified for Sm4CbcEncryptor {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl SymmetricCipher for Sm4CbcEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut iv = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv);

        let ciphertext = Encryptor::<Sm4>::new_from_slices(self.key.as_bytes(), &iv)
            .expect("key and iv lengths are fixed")
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        Ok(etm::pack(&iv, &ciphertext, self.key.as_bytes()))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (iv, body) = etm::unpack_and_verify(ciphertext, IV_LEN, self.key.as_bytes(), LABEL)?;

        Decryptor::<Sm4>::new_from_slices(self.key.as_bytes(), iv)
            .expect("key and iv lengths were verified")
            .decrypt_padded_vec_mut::<Pkcs7>(body)
            .map_err(|_| Error::DecryptionFailed { label: LABEL })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper_detection() {
        let encryptor = Sm4CbcEncryptor::new([4u8; 16]);
        for plaintext in [b"".as_slice(), b"plain", b"0123456789abcdef"] {
            let blob = encryptor.encrypt(plaintext).unwrap();
            assert_eq!(encryptor.decrypt(&blob).unwrap(), plaintext);
        }

        let mut blob = encryptor.encrypt(b"data").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert_eq!(
            encryptor.decrypt(&blob).unwrap_err(),
            Error::MacVerificationFailed { label: LABEL }
        );
    }

    #[test]
    fn key_length_is_checked() {
        assert_eq!(
            Sm4CbcEncryptor::from_slice(&[0u8; 32]).unwrap_err(),
            Error::InvalidKeyLength {
                label: LABEL,
                expected: 16,
                got: 32
            }
        );
    }
}
