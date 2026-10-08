// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! BLAKE3 哈希；默认输出 32 字节。
//!
//! BLAKE3 支持任意长度扩展输出（XOF），但 [`Hasher`] 契约返回固定长度摘要，
//! 本库统一走官方默认的 32 字节（即扩展输出流的前 32 字节），不提供可变长度
//! 接口。blake3 crate 为独立实现，不依赖 RustCrypto digest trait 代际。

use crate::contract::{Hasher, Identified};
use crate::error::Result;

/// BLAKE3 哈希器（无状态，可复用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Blake3Hasher;

impl Blake3Hasher {
    pub const IDENTIFIER: &'static str = "blake3";

    pub fn new() -> Self {
        Self
    }
}

impl Identified for Blake3Hasher {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl Hasher for Blake3Hasher {
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(blake3::hash(data).as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 官方仓库 BLAKE3-team/BLAKE3 的 test_vectors/test_vectors.json 条目：
    /// input_len 0（空输入）与 input_len 1（单字节 0x00）。官方文件给出 131 字节
    /// 扩展输出，本库取默认 32 字节 = 其前 32 字节（两个文件字段的前 64 个十六
    /// 进制字符）。
    #[test]
    fn matches_official_test_vectors() {
        let hasher = Blake3Hasher::new();
        assert_eq!(
            hasher.digest_hex(b"").unwrap(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            hasher.digest_hex(&[0x00]).unwrap(),
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"
        );
        assert_eq!(hasher.digest(b"").unwrap().len(), 32);
    }

    /// digest_hex 输出为 2×摘要长度的小写十六进制。
    #[test]
    fn digest_hex_is_lowercase_hex() {
        let hex = Blake3Hasher::new().digest_hex(b"abc").unwrap();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    /// 弱检查：不同输入给出不同摘要。
    #[test]
    fn distinct_inputs_distinct_digests() {
        let hasher = Blake3Hasher::new();
        assert_ne!(
            hasher.digest(b"abc").unwrap(),
            hasher.digest(b"abd").unwrap()
        );
    }
}
