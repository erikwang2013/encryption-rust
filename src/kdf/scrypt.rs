// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! scrypt（RFC 7914）：从人类可读口令派生密钥。
//!
//! **默认参数为 [`Params::recommended()`]：log_n=17（N=2^17）、r=8、p=1，
//! 每次派生约 128 MiB 内存开销（128 × N × r 字节）——Web 场景必须评估 DoS
//! 面**：在按请求执行派生的接口上，等于给攻击者一个 128 MiB / 次的内存放大器，
//! 应在入口限流，或用 [`ScryptKdf::with_params`] 调低 log_n 换取更小的内存足迹。
//!
//! 盐值无长度下限（RFC 7914 §12 的官方向量即含空盐）；生产应使用随机盐，
//! 建议 ≥16 字节（与 RFC 9106 的建议一致）。

use scrypt::{Params, scrypt};

use crate::contract::{Identified, PasswordBasedKdf};
use crate::error::{Error, Result};

/// scrypt 派生器（可复用）。
#[derive(Debug, Clone, Copy)]
pub struct ScryptKdf {
    params: Params,
}

impl ScryptKdf {
    pub const IDENTIFIER: &'static str = "scrypt";

    /// 使用 [`Params::recommended()`]（log_n=17、r=8、p=1，约 128 MiB 内存/次）。
    pub fn new() -> Self {
        Self {
            params: Params::recommended(),
        }
    }

    /// 自定义参数：`N = 2^log_n`（内存与 CPU 随 N 线性增长），`r` 为块大小，
    /// `p` 为并行度。参数非法（如 log_n ≥ 64、r = 0、p = 0）返回
    /// [`Error::InvalidKdfParams`]。
    pub fn with_params(log_n: u8, r: u32, p: u32) -> Result<Self> {
        // Params 的 len 字段只在 password-hash 表示层使用，裸 scrypt() 不校验它，
        // 派生长度以 derive_from_password 的 length 参数为准，这里填推荐值。
        let params = Params::new(log_n, r, p, Params::RECOMMENDED_LEN)
            .map_err(|_| Error::InvalidKdfParams { label: "scrypt" })?;
        Ok(Self { params })
    }

    pub fn log_n(&self) -> u8 {
        self.params.log_n()
    }

    pub fn r(&self) -> u32 {
        self.params.r()
    }

    pub fn p(&self) -> u32 {
        self.params.p()
    }
}

impl Default for ScryptKdf {
    fn default() -> Self {
        Self::new()
    }
}

impl Identified for ScryptKdf {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl PasswordBasedKdf for ScryptKdf {
    fn derive_from_password(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
        if length == 0 {
            return Err(Error::InvalidOutputLength {
                requested: 0,
                max: usize::MAX,
            });
        }

        let mut output = vec![0u8; length];
        scrypt(password, salt, &self.params, &mut output)
            // scrypt() 只拒绝 0 长度与超过 (2^32−1)×32 的输出；前置校验后
            // 剩余失败仅为理论上限（先于它撞上分配失败），一并归入长度非法。
            .map_err(|_| Error::InvalidOutputLength {
                requested: length,
                max: usize::MAX,
            })?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7914 §12 官方测试向量：P=""、S=""、N=16、r=1、p=1、dkLen=64。
    ///
    /// N=16 即 log_n=4，与默认（log_n=17，约 128 MiB）相差甚远，正是
    /// [`ScryptKdf::with_params`] 存在的理由。
    #[test]
    fn matches_rfc7914_test_vector() {
        let kdf = ScryptKdf::with_params(4, 1, 1).unwrap();
        let derived = kdf.derive_from_password(b"", b"", 64).unwrap();
        assert_eq!(
            crate::internal::hex_encode(&derived),
            concat!(
                "77d6576238657b203b19ca42c18a0497",
                "f16b4844e3074ae8dfdffa3fede21442",
                "fcd0069ded0948f8326a753a0fc81f17",
                "e8d3e0fb2e0d3628cf35e20c38d18906"
            )
        );
    }

    /// RFC 7914 §12 第二组官方测试向量：P="password"、S="NaCl"、N=1024、r=8、
    /// p=16、dkLen=64（额外覆盖 p > 1 与非空盐）。
    #[test]
    fn matches_rfc7914_test_vector_par16() {
        let kdf = ScryptKdf::with_params(10, 8, 16).unwrap();
        let derived = kdf.derive_from_password(b"password", b"NaCl", 64).unwrap();
        assert_eq!(
            crate::internal::hex_encode(&derived),
            concat!(
                "fdbabe1c9d3472007856e7190d01e9fe",
                "7c6ad7cbc8237830e77376634b373162",
                "2eaf30d92e22a3886ff109279d9830da",
                "c727afb94a83ee6d8360cbdfa2cc0640"
            )
        );
    }

    /// 默认参数的构成（不在测试中真跑 128 MiB 派生，只钉参数）。
    #[test]
    fn default_params_are_recommended() {
        let kdf = ScryptKdf::default();
        assert_eq!((kdf.log_n(), kdf.r(), kdf.p()), (17, 8, 1));
    }

    #[test]
    fn same_inputs_same_output_and_length_validation() {
        let kdf = ScryptKdf::with_params(4, 1, 1).unwrap();
        let first = kdf.derive_from_password(b"pw", b"salt", 16).unwrap();
        let second = kdf.derive_from_password(b"pw", b"salt", 16).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 16);
        // 长度参数生效：不同 dkLen 产出对应长度的结果（末尾是 PBKDF2 收尾，
        // 短输出是长输出的前缀，故只断言长度不断言内容差异）。
        assert_eq!(
            kdf.derive_from_password(b"pw", b"salt", 64).unwrap().len(),
            64
        );
        assert_eq!(
            kdf.derive_from_password(b"pw", b"salt", 0).unwrap_err(),
            Error::InvalidOutputLength {
                requested: 0,
                max: usize::MAX
            }
        );
    }

    #[test]
    fn password_and_salt_both_affect_output() {
        let kdf = ScryptKdf::with_params(4, 1, 1).unwrap();
        let base = kdf.derive_from_password(b"pw", b"salt", 32).unwrap();
        assert_ne!(base, kdf.derive_from_password(b"pw2", b"salt", 32).unwrap());
        assert_ne!(base, kdf.derive_from_password(b"pw", b"salt2", 32).unwrap());
    }

    #[test]
    fn invalid_params_are_rejected() {
        assert_eq!(
            ScryptKdf::with_params(64, 1, 1).unwrap_err(),
            Error::InvalidKdfParams { label: "scrypt" }
        );
        assert_eq!(
            ScryptKdf::with_params(4, 0, 1).unwrap_err(),
            Error::InvalidKdfParams { label: "scrypt" }
        );
        assert_eq!(
            ScryptKdf::with_params(4, 1, 0).unwrap_err(),
            Error::InvalidKdfParams { label: "scrypt" }
        );
    }
}
