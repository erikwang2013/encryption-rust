// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 定长密钥材质：Drop 时清零，Debug 不打印内容。

use std::fmt;

use zeroize::Zeroize;

use crate::error::{Error, Result};

/// 定长密钥（如 `Key<32>`、`Key<16>`）。构造后不可变。
pub struct Key<const N: usize>([u8; N]);

impl<const N: usize> Key<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// 从切片构造；长度不符返回 [`Error::InvalidKeyLength`]。
    pub fn from_slice(bytes: &[u8], label: &'static str) -> Result<Self> {
        let array: [u8; N] = bytes.try_into().map_err(|_| Error::InvalidKeyLength {
            label,
            expected: N,
            got: bytes.len(),
        })?;
        Ok(Self(array))
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Drop for Key<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> fmt::Debug for Key<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key<{N}>(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_slice_checks_length() {
        let key = Key::<32>::from_slice(&[7u8; 32], "AES-256-GCM").unwrap();
        assert_eq!(key.as_bytes()[0], 7);

        let error = Key::<32>::from_slice(&[0u8; 16], "AES-256-GCM").unwrap_err();
        assert_eq!(
            error,
            Error::InvalidKeyLength {
                label: "AES-256-GCM",
                expected: 32,
                got: 16
            }
        );
    }

    #[test]
    fn debug_is_redacted() {
        let key = Key::<16>::new([0u8; 16]);
        assert_eq!(format!("{key:?}"), "Key<16>(***)");
    }
}
