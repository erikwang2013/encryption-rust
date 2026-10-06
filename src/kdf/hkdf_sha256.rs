// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! HKDF-SHA256（RFC 5869）：从高熵密钥材料派生子密钥。

use hkdf::Hkdf;
use sha2::Sha256;

use crate::contract::{Identified, KeyDerivation};
use crate::error::{Error, Result};

/// RFC 5869 的输出上限：255 × HashLen。
const MAX_OUTPUT_LEN: usize = 255 * 32;

/// HKDF-SHA256 派生器（无状态，可复用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct HkdfSha256;

impl HkdfSha256 {
    pub const IDENTIFIER: &'static str = "hkdf-sha256";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for HkdfSha256 {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl KeyDerivation for HkdfSha256 {
    /// `salt` 为空时按 RFC 5869 使用全零盐；`info` 可为空。
    fn derive(&self, ikm: &[u8], salt: &[u8], length: usize, info: &[u8]) -> Result<Vec<u8>> {
        if length == 0 || length > MAX_OUTPUT_LEN {
            return Err(Error::InvalidOutputLength {
                requested: length,
                max: MAX_OUTPUT_LEN,
            });
        }

        let hkdf = if salt.is_empty() {
            Hkdf::<Sha256>::new(None, ikm)
        } else {
            Hkdf::<Sha256>::new(Some(salt), ikm)
        };

        let mut output = vec![0u8; length];
        hkdf.expand(info, &mut output)
            .map_err(|_| Error::InvalidOutputLength {
                requested: length,
                max: MAX_OUTPUT_LEN,
            })?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 附录 A.1（SHA-256 版本）的测试向量。
    #[test]
    fn matches_rfc5869_test_vector() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();

        let okm = HkdfSha256::new().derive(&ikm, &salt, 42, &info).unwrap();
        assert_eq!(
            crate::internal::hex_encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn empty_salt_and_limits() {
        let kdf = HkdfSha256::new();
        assert_eq!(kdf.derive(b"ikm", b"", 16, b"").unwrap().len(), 16);
        assert_eq!(
            kdf.derive(b"ikm", b"", 0, b"").unwrap_err(),
            Error::InvalidOutputLength {
                requested: 0,
                max: MAX_OUTPUT_LEN
            }
        );
        assert_eq!(
            kdf.derive(b"ikm", b"", MAX_OUTPUT_LEN + 1, b"")
                .unwrap_err(),
            Error::InvalidOutputLength {
                requested: MAX_OUTPUT_LEN + 1,
                max: MAX_OUTPUT_LEN
            }
        );
    }
}
