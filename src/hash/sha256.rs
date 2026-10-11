// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! SHA-256 哈希；输出 32 字节。

use sha2::Sha256;

use crate::hash::{NamedDigest, hasher};

hasher!(Sha256Hasher, "sha256", "SHA-256 哈希器（无状态，可复用）。");

impl NamedDigest for Sha256Hasher {
    type Core = Sha256;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::Hasher;

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
