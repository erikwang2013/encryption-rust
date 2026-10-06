// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 国密 SM3 杂凑（GB/T 32905-2016）；输出 32 字节。

use sm3::{Digest, Sm3};

use crate::contract::{Hasher, Identified};
use crate::error::Result;

/// SM3 哈希器（无状态，可复用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Sm3Hasher;

impl Sm3Hasher {
    pub const IDENTIFIER: &'static str = "sm3";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for Sm3Hasher {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl Hasher for Sm3Hasher {
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(Sm3::digest(data).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GB/T 32905-2016 附录 A 的标准测试向量。
    #[test]
    fn matches_standard_vector() {
        let hasher = Sm3Hasher::new();
        assert_eq!(
            hasher.digest_hex(b"abc").unwrap(),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
        assert_eq!(hasher.digest(b"abc").unwrap().len(), 32);
    }
}
