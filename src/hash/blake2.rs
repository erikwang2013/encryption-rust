// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! BLAKE2（RFC 7693）：BLAKE2b-512 输出 64 字节、BLAKE2s-256 输出 32 字节。
//!
//! 均为无密钥（unkeyed）模式；带密钥 / 加盐的 BLAKE2 不在本库范围。

use blake2::{Blake2b512, Blake2s256, Digest};

use crate::contract::{Hasher, Identified};
use crate::error::Result;

/// BLAKE2b-512 哈希器（无状态，可复用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Blake2b512Hasher;

impl Blake2b512Hasher {
    pub const IDENTIFIER: &'static str = "blake2b-512";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for Blake2b512Hasher {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl Hasher for Blake2b512Hasher {
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(Blake2b512::digest(data).to_vec())
    }
}

/// BLAKE2s-256 哈希器（无状态，可复用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Blake2s256Hasher;

impl Blake2s256Hasher {
    pub const IDENTIFIER: &'static str = "blake2s-256";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for Blake2s256Hasher {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl Hasher for Blake2s256Hasher {
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(Blake2s256::digest(data).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7693 附录 A 的 "abc" 向量：A.1 BLAKE2b-512、A.2 BLAKE2s-256。
    #[test]
    fn matches_rfc7693_appendix_vectors() {
        assert_eq!(
            Blake2b512Hasher::new().digest_hex(b"abc").unwrap(),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assert_eq!(
            Blake2s256Hasher::new().digest_hex(b"abc").unwrap(),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
        assert_eq!(Blake2b512Hasher::new().digest(b"abc").unwrap().len(), 64);
        assert_eq!(Blake2s256Hasher::new().digest(b"abc").unwrap().len(), 32);
    }

    /// digest_hex 输出为 2×摘要长度的小写十六进制。
    #[test]
    fn digest_hex_is_lowercase_hex() {
        let hex = Blake2b512Hasher::new().digest_hex(b"abc").unwrap();
        assert_eq!(hex.len(), 128);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );

        let hex = Blake2s256Hasher::new().digest_hex(b"abc").unwrap();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    /// 弱检查：不同输入给出不同摘要。
    #[test]
    fn distinct_inputs_distinct_digests() {
        let hasher = Blake2b512Hasher::new();
        assert_ne!(
            hasher.digest(b"abc").unwrap(),
            hasher.digest(b"abd").unwrap()
        );

        let hasher = Blake2s256Hasher::new();
        assert_ne!(
            hasher.digest(b"abc").unwrap(),
            hasher.digest(b"abd").unwrap()
        );
    }
}
