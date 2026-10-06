// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 统一错误类型：对应 PHP 版的 `EncryptionException` 与
//! `UnsupportedNationalAlgorithmException`。
//!
//! 错误消息与 PHP 版保持同指：解密失败一律是「密钥不对或密文被改」，
//! 不区分原因，不向前端泄露细节。

use std::fmt;

/// 库统一错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// 密钥长度不符合算法要求。
    InvalidKeyLength {
        label: &'static str,
        expected: usize,
        got: usize,
    },
    /// 密文前缀不是本算法 / 本格式版本的标识。
    InvalidPrefix { label: &'static str },
    /// 密文长度不足（缺少 IV / MAC / tag）。
    TooShort { label: &'static str },
    /// encrypt-then-MAC 的 MAC 校验失败：密钥不对或密文被改，没有第三种解释。
    MacVerificationFailed { label: &'static str },
    /// 认证加密（GCM / XChaCha20-Poly1305）解密失败：密钥不对或密文被改。
    DecryptionFailed { label: &'static str },
    /// 加密失败（一般不应发生）。
    EncryptionFailed { label: &'static str },
    /// 标识未注册到注册表。
    UnknownIdentifier {
        kind: &'static str,
        identifier: String,
    },
    /// 主密钥必须是 32 字节。
    InvalidMasterKey { got: usize },
    /// 密钥材质非法（十六进制、长度或曲线点校验失败）。
    InvalidKey { label: &'static str },
    /// PBKDF2 迭代次数必须为正。
    InvalidIterations,
    /// 请求的输出长度非法（为 0 或超过算法上限）。
    InvalidOutputLength { requested: usize, max: usize },
    /// 十六进制字符串非法（奇数长度或含非十六进制字符）。
    InvalidHex,
    /// 国密算法（SM1 / SM7 / SM9）本库不提供实现。
    UnsupportedNationalAlgorithm {
        name: &'static str,
        hint: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKeyLength {
                label,
                expected,
                got,
            } => write!(
                f,
                "{label} key must be exactly {expected} bytes (got {got})."
            ),
            Error::InvalidPrefix { label } => write!(f, "Invalid {label} ciphertext prefix."),
            Error::TooShort { label } => write!(f, "{label} ciphertext too short."),
            Error::MacVerificationFailed { label } => write!(f, "{label} MAC verification failed."),
            Error::DecryptionFailed { label } => write!(f, "{label} decryption failed."),
            Error::EncryptionFailed { label } => write!(f, "{label} encryption failed."),
            Error::UnknownIdentifier { kind, identifier } => {
                write!(f, "Unknown {kind} identifier \"{identifier}\".")
            }
            Error::InvalidMasterKey { got } => {
                write!(f, "Master key must be exactly 32 bytes (got {got}).")
            }
            Error::InvalidKey { label } => write!(f, "Invalid {label} key."),
            Error::InvalidIterations => write!(f, "PBKDF2 iterations must be positive."),
            Error::InvalidOutputLength { requested, max } => {
                if *requested == 0 {
                    write!(f, "Output length must be positive.")
                } else {
                    write!(f, "Output length {requested} exceeds the maximum of {max}.")
                }
            }
            Error::InvalidHex => write!(f, "Invalid hex string."),
            Error::UnsupportedNationalAlgorithm { name, hint } => {
                write!(f, "{name} is not provided by this library: {hint}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// 库统一 Result。
pub type Result<T> = std::result::Result<T, Error>;
