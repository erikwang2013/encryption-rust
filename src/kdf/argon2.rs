// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! Argon2id（RFC 9106）：从人类可读口令派生密钥。
//!
//! 固定 v19 版本；默认 [`Params::DEFAULT`] 即 m=19×1024 KiB（约 19 MiB 内存开销）、
//! t=2、p=1。需要更高强度或与外部约定对齐时用 [`Argon2Kdf::with_params`] 调参
//! （如 RFC 9106 §4 建议的 m=64 MiB、t=3、p=4）。
//!
//! 走 [`Argon2::hash_password_into`]（裸字节输出），不经过 PHC 字符串层。

use argon2::{Algorithm, Argon2, Params, Version};

use crate::contract::{Identified, PasswordBasedKdf};
use crate::error::{Error, Result};

/// 盐值下限：与 argon2 crate 的 `MIN_SALT_LEN` 一致（RFC 9106 建议 16 字节随机盐）。
const MIN_SALT_LEN: usize = 8;

/// 输出长度上限（RFC 9106 §3.1：tag 最长 2^32−1 字节）。
const MAX_OUTPUT_LEN: usize = u32::MAX as usize;

/// Argon2id 派生器（v19，可复用）。
#[derive(Debug, Clone)]
pub struct Argon2Kdf {
    inner: Argon2<'static>,
}

impl Argon2Kdf {
    pub const IDENTIFIER: &'static str = "argon2";

    /// 使用 [`Params::DEFAULT`]：m=19456 KiB（约 19 MiB）、t=2、p=1。
    pub fn new() -> Self {
        Self {
            inner: Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::DEFAULT),
        }
    }

    /// 自定义参数：`m_cost` 单位为 KiB（内存），`t_cost` 为迭代次数，`p_cost`
    /// 为并行度。参数非法（如 m < 8×p、t = 0、p = 0）返回
    /// [`Error::InvalidKdfParams`]。
    pub fn with_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        let params = Params::new(m_cost, t_cost, p_cost, None)
            .map_err(|_| Error::InvalidKdfParams { label: "Argon2" })?;
        Ok(Self {
            inner: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        })
    }
}

impl Default for Argon2Kdf {
    fn default() -> Self {
        Self::new()
    }
}

impl Identified for Argon2Kdf {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl PasswordBasedKdf for Argon2Kdf {
    /// `salt` 至少 8 字节（与 argon2 crate 的 `MIN_SALT_LEN` 一致，推荐 16 字节）。
    fn derive_from_password(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
        if salt.len() < MIN_SALT_LEN {
            // 选 InvalidKeyLength：既有错误集中最贴近的变体 —— 它表达「某输入的
            // 长度不满足算法要求」，expected/got 能直接指出盐值过短；Display 现为
            // 「{label} length must be {expected} (got {got})」，未含「至少」语义，
            // 与 ≥8 的实际约束略有出入，但仅在实际过短时出现，不会把合法长度误报为非法。
            return Err(Error::InvalidKeyLength {
                label: "argon2 salt",
                expected: MIN_SALT_LEN,
                got: salt.len(),
            });
        }

        if length == 0 || length > MAX_OUTPUT_LEN {
            return Err(Error::InvalidOutputLength {
                requested: length,
                max: MAX_OUTPUT_LEN,
            });
        }

        let mut output = vec![0u8; length];
        self.inner
            .hash_password_into(password, salt, &mut output)
            // 前置校验后剩余的长度类失败只有 1..=3（Argon2 的输出下限为 4 字节，
            // RFC 9106 §3.1）；错误变体没有 min 字段，一并归入输出长度非法。
            .map_err(|_| Error::InvalidOutputLength {
                requested: length,
                max: MAX_OUTPUT_LEN,
            })?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{AssociatedData, ParamsBuilder};

    /// RFC 9106 §5.3 官方测试向量（Argon2id v19）：
    /// m=32 KiB、t=3、p=4、tag 32 字节；P=01×32、S=02×16、K=03×8、X=04×12。
    ///
    /// 该向量带 secret（K）与 associated data（X）两个输入，而
    /// `PasswordBasedKdf::derive_from_password` 契约只有 password / salt 两个
    /// 槽位（contract.rs 不在本任务改动范围内），故官方向量用与
    /// [`Argon2Kdf::with_params`] 相同的构造链（ParamsBuilder + new_with_secret）
    /// 在 crate 层复现，钉住底层算法组合能产出 RFC 给出的完整 tag。
    #[test]
    fn matches_rfc9106_test_vector() {
        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .output_len(32)
            .data(AssociatedData::new(&[0x04u8; 12]).unwrap())
            .build()
            .unwrap();
        let secret = [0x03u8; 8];
        let ctx =
            Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();

        let mut tag = [0u8; 32];
        ctx.hash_password_into(&[0x01u8; 32], &[0x02u8; 16], &mut tag)
            .unwrap();
        assert_eq!(
            crate::internal::hex_encode(&tag),
            concat!(
                "0d640df58d78766c08c037a34a8b53c9",
                "d01ef0452d75b65eb52520e96b01e659"
            )
        );
    }

    /// 封装等价性（对照检查，非官方向量）：`with_params` 与裸 crate 同参构造
    /// 输出一致 —— 钉住 m/t/p 被原样透传。
    #[test]
    fn with_params_matches_reference_context() {
        let kdf = Argon2Kdf::with_params(32, 3, 4).unwrap();
        let reference = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(32, 3, 4, None).unwrap(),
        );

        let mut expected = [0u8; 32];
        reference
            .hash_password_into(b"password", b"0123456789abcdef", &mut expected)
            .unwrap();
        assert_eq!(
            kdf.derive_from_password(b"password", b"0123456789abcdef", 32)
                .unwrap(),
            expected
        );
    }

    /// 默认构造必须是 Argon2id + v19 + [`Params::DEFAULT`]，而不是
    /// `Argon2::default()`（那会是 Argon2d 变体，安全性不同）。
    #[test]
    fn default_matches_reference_context() {
        let reference = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::DEFAULT);
        let mut expected = [0u8; 32];
        reference
            .hash_password_into(b"pw", b"12345678", &mut expected)
            .unwrap();

        assert_eq!(
            Argon2Kdf::default()
                .derive_from_password(b"pw", b"12345678", 32)
                .unwrap(),
            expected
        );
    }

    #[test]
    fn same_inputs_same_output_and_length_validation() {
        let kdf = Argon2Kdf::with_params(32, 3, 4).unwrap();
        let first = kdf.derive_from_password(b"pw", b"salt1234", 16).unwrap();
        let second = kdf.derive_from_password(b"pw", b"salt1234", 16).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 16);

        // Argon2 的 tag 长度参与初始哈希，32 字节输出不以 16 字节输出为前缀。
        let long = kdf.derive_from_password(b"pw", b"salt1234", 32).unwrap();
        assert_eq!(long.len(), 32);
        assert_ne!(first, long[..16]);

        assert_eq!(
            kdf.derive_from_password(b"pw", b"salt1234", 0).unwrap_err(),
            Error::InvalidOutputLength {
                requested: 0,
                max: MAX_OUTPUT_LEN
            }
        );
    }

    #[test]
    fn password_and_salt_both_affect_output() {
        let kdf = Argon2Kdf::with_params(32, 3, 4).unwrap();
        let base = kdf.derive_from_password(b"pw", b"salt1234", 32).unwrap();
        assert_ne!(
            base,
            kdf.derive_from_password(b"pw2", b"salt1234", 32).unwrap()
        );
        assert_ne!(
            base,
            kdf.derive_from_password(b"pw", b"salt5678", 32).unwrap()
        );
    }

    #[test]
    fn short_salt_is_rejected() {
        let kdf = Argon2Kdf::new();
        assert_eq!(
            kdf.derive_from_password(b"pw", b"1234567", 32).unwrap_err(),
            Error::InvalidKeyLength {
                label: "argon2 salt",
                expected: 8,
                got: 7
            }
        );
        // 8 字节即下限，可通过（默认参数也顺带跑通一次）。
        assert_eq!(
            kdf.derive_from_password(b"pw", b"12345678", 32)
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn invalid_params_are_rejected() {
        assert_eq!(
            Argon2Kdf::with_params(4, 3, 4).unwrap_err(),
            Error::InvalidKdfParams { label: "Argon2" }
        );
        assert_eq!(
            Argon2Kdf::with_params(32, 0, 4).unwrap_err(),
            Error::InvalidKdfParams { label: "Argon2" }
        );
        assert_eq!(
            Argon2Kdf::with_params(32, 3, 0).unwrap_err(),
            Error::InvalidKdfParams { label: "Argon2" }
        );
    }
}
