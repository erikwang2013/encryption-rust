// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! Streebog（ГОСТ Р 34.11-2012 / RFC 6986）：Streebog-256 输出 32 字节、
//! Streebog-512 输出 64 字节。

use streebog::{Digest, Streebog256, Streebog512};

use crate::contract::{Hasher, Identified};
use crate::error::Result;

/// Streebog-256 哈希器（无状态，可复用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Streebog256Hasher;

impl Streebog256Hasher {
    pub const IDENTIFIER: &'static str = "streebog-256";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for Streebog256Hasher {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl Hasher for Streebog256Hasher {
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(Streebog256::digest(data).to_vec())
    }
}

/// Streebog-512 哈希器（无状态，可复用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Streebog512Hasher;

impl Streebog512Hasher {
    pub const IDENTIFIER: &'static str = "streebog-512";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for Streebog512Hasher {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl Hasher for Streebog512Hasher {
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(Streebog512::digest(data).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ГОСТ Р 34.11-2012 附录 A.1（RFC 6986 A.1）的 M1 向量：63 字节 ASCII
    /// 数字串 "0123…012"（标准中记作 0x3231…，为小端字节序显示）。
    /// 断言值为**本库输出序**（RFC 打印值的逐字节反转）——GOST 传统的字节序
    /// 惯例，请勿按打印序「纠正」。
    const M1: &[u8; 63] = b"012345678901234567890123456789012345678901234567890123456789012";

    #[test]
    fn matches_standard_m1_vector() {
        assert_eq!(
            Streebog256Hasher::new().digest_hex(M1).unwrap(),
            "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"
        );
        assert_eq!(
            Streebog512Hasher::new().digest_hex(M1).unwrap(),
            "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa\
             00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48"
        );
        assert_eq!(Streebog256Hasher::new().digest(M1).unwrap().len(), 32);
        assert_eq!(Streebog512Hasher::new().digest(M1).unwrap().len(), 64);
    }

    /// digest_hex 输出为 2×摘要长度的小写十六进制。
    #[test]
    fn digest_hex_is_lowercase_hex() {
        let hex = Streebog256Hasher::new().digest_hex(b"abc").unwrap();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );

        let hex = Streebog512Hasher::new().digest_hex(b"abc").unwrap();
        assert_eq!(hex.len(), 128);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    /// 弱检查：不同输入给出不同摘要。
    #[test]
    fn distinct_inputs_distinct_digests() {
        let hasher = Streebog256Hasher::new();
        assert_ne!(hasher.digest(M1).unwrap(), hasher.digest(b"abc").unwrap());

        let hasher = Streebog512Hasher::new();
        assert_ne!(hasher.digest(M1).unwrap(), hasher.digest(b"abc").unwrap());
    }
}
