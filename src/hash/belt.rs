// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! Belt-Hash（STB 34.101.31，白俄罗斯国家标准）；输出 32 字节。

use belt_hash::{BeltHash, Digest};

use crate::contract::{Hasher, Identified};
use crate::error::Result;

/// Belt-Hash 哈希器（无状态，可复用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct BeltHashHasher;

impl BeltHashHasher {
    pub const IDENTIFIER: &'static str = "belt-hash";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for BeltHashHasher {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl Hasher for BeltHashHasher {
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(BeltHash::digest(data).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STB 34.101.31-2020 附录 A.11 表 A.23 测试 A.23-1：标准测试数据 H 的
    /// 前 13 字节（X = B194BAC80A08F53B366D008E58）。
    const X: [u8; 13] = [
        0xb1, 0x94, 0xba, 0xc8, 0x0a, 0x08, 0xf5, 0x3b, 0x36, 0x6d, 0x00, 0x8e, 0x58,
    ];

    #[test]
    fn matches_stb_appendix_vector() {
        let hasher = BeltHashHasher::new();
        assert_eq!(
            hasher.digest_hex(&X).unwrap(),
            "abef9725d4c5a83597a367d14494cc2542f20f659ddfecc961a3ec550cba8c75"
        );
        assert_eq!(hasher.digest(&X).unwrap().len(), 32);
    }

    /// digest_hex 输出为 2×摘要长度的小写十六进制。
    #[test]
    fn digest_hex_is_lowercase_hex() {
        let hex = BeltHashHasher::new().digest_hex(&X).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    /// 弱检查：不同输入给出不同摘要。
    #[test]
    fn distinct_inputs_distinct_digests() {
        let hasher = BeltHashHasher::new();
        assert_ne!(hasher.digest(&X).unwrap(), hasher.digest(b"abc").unwrap());
    }
}
