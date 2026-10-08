// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! SHA-3（FIPS 202）：SHA3-256 输出 32 字节、SHA3-512 输出 64 字节。
//!
//! 是 FIPS 202 标准化的 SHA-3（域分隔符 0x06），不是 Keccak 提交版
//! （0x01 填充，SHAKE 的前身）——两者对同一输入给出不同摘要。

use sha3::{Digest, Sha3_256, Sha3_512};

use crate::contract::{Hasher, Identified};
use crate::error::Result;

/// SHA3-256 哈希器（无状态，可复用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha3_256Hasher;

impl Sha3_256Hasher {
    pub const IDENTIFIER: &'static str = "sha3-256";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for Sha3_256Hasher {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl Hasher for Sha3_256Hasher {
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(Sha3_256::digest(data).to_vec())
    }
}

/// SHA3-512 哈希器（无状态，可复用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha3_512Hasher;

impl Sha3_512Hasher {
    pub const IDENTIFIER: &'static str = "sha3-512";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for Sha3_512Hasher {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl Hasher for Sha3_512Hasher {
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(Sha3_512::digest(data).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 202 发布时给出的 "abc" 示例摘要（NIST SHA-3 标准示例值）。
    #[test]
    fn matches_nist_example_vectors() {
        assert_eq!(
            Sha3_256Hasher::new().digest_hex(b"abc").unwrap(),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            Sha3_512Hasher::new().digest_hex(b"abc").unwrap(),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
        assert_eq!(Sha3_256Hasher::new().digest(b"abc").unwrap().len(), 32);
        assert_eq!(Sha3_512Hasher::new().digest(b"abc").unwrap().len(), 64);
    }

    /// digest_hex 输出为 2×摘要长度的小写十六进制。
    #[test]
    fn digest_hex_is_lowercase_hex() {
        let hex = Sha3_256Hasher::new().digest_hex(b"abc").unwrap();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );

        let hex = Sha3_512Hasher::new().digest_hex(b"abc").unwrap();
        assert_eq!(hex.len(), 128);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    /// 弱检查：不同输入给出不同摘要。
    #[test]
    fn distinct_inputs_distinct_digests() {
        let hasher = Sha3_256Hasher::new();
        assert_ne!(
            hasher.digest(b"abc").unwrap(),
            hasher.digest(b"abd").unwrap()
        );

        let hasher = Sha3_512Hasher::new();
        assert_ne!(
            hasher.digest(b"abc").unwrap(),
            hasher.digest(b"abd").unwrap()
        );
    }
}
