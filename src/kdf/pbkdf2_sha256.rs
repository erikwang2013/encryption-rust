// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! PBKDF2-HMAC-SHA256：从人类可读口令派生密钥。
//!
//! 存储用户密码请改用 Argon2 / `password_hash` 等专用 API，本实现面向的
//! 是从口令派生加解密密钥的场景。

use sha2::Sha256;

use crate::contract::{Identified, PasswordBasedKdf};
use crate::error::{Error, Result};

/// PBKDF2-HMAC-SHA256 派生器。
#[derive(Debug, Clone, Copy)]
pub struct Pbkdf2Sha256 {
    iterations: u32,
}

impl Pbkdf2Sha256 {
    pub const IDENTIFIER: &'static str = "pbkdf2-sha256";

    /// 默认迭代次数（与原版一致：OWASP 建议量级，请按环境调整）。
    pub const DEFAULT_ITERATIONS: u32 = 310_000;

    /// 迭代次数必须为正。
    pub fn new(iterations: u32) -> Result<Self> {
        if iterations == 0 {
            return Err(Error::InvalidIterations);
        }
        Ok(Self { iterations })
    }

    /// 使用 [`Pbkdf2Sha256::DEFAULT_ITERATIONS`]。
    pub fn with_default_iterations() -> Self {
        Self {
            iterations: Self::DEFAULT_ITERATIONS,
        }
    }

    pub fn iterations(&self) -> u32 {
        self.iterations
    }
}

impl Default for Pbkdf2Sha256 {
    fn default() -> Self {
        Self::with_default_iterations()
    }
}

impl Identified for Pbkdf2Sha256 {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl PasswordBasedKdf for Pbkdf2Sha256 {
    fn derive_from_password(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
        if length == 0 {
            return Err(Error::InvalidOutputLength {
                requested: 0,
                max: usize::MAX,
            });
        }

        let mut output = vec![0u8; length];
        pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, self.iterations, &mut output);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6070 风格的公开测试向量（PBKDF2-HMAC-SHA256，c=1）。
    #[test]
    fn matches_known_vector() {
        let kdf = Pbkdf2Sha256::new(1).unwrap();
        let derived = kdf.derive_from_password(b"password", b"salt", 32).unwrap();
        assert_eq!(
            crate::internal::hex_encode(&derived),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn same_inputs_same_output_and_length_validation() {
        let kdf = Pbkdf2Sha256::with_default_iterations();
        assert_eq!(kdf.iterations(), 310_000);
        let first = kdf.derive_from_password(b"pw", b"salt", 16).unwrap();
        let second = kdf.derive_from_password(b"pw", b"salt", 16).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            kdf.derive_from_password(b"pw", b"salt", 0).unwrap_err(),
            Error::InvalidOutputLength {
                requested: 0,
                max: usize::MAX
            }
        );
    }

    #[test]
    fn zero_iterations_is_rejected() {
        assert_eq!(Pbkdf2Sha256::new(0).unwrap_err(), Error::InvalidIterations);
    }
}
