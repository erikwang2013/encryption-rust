// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! SHA-256 哈希；输出 32 字节。

use sha2::{Digest, Sha256};

use crate::contract::{Hasher, Identified};
use crate::error::Result;

/// SHA-256 哈希器（无状态，可复用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha256Hasher;

impl Sha256Hasher {
    pub const IDENTIFIER: &'static str = "sha256";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for Sha256Hasher {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl Hasher for Sha256Hasher {
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(Sha256::digest(data).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_vector() {
        let hasher = Sha256Hasher::new();
        assert_eq!(
            hasher.digest_hex(b"abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hasher.digest(b"abc").unwrap().len(), 32);
    }
}
