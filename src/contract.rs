// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 能力契约（trait）：业务层唯一需要依赖的东西。
//!
//! 对应 PHP 版的 `Contract/` 命名空间。PHP 里 `EncryptorInterface` 是
//! `SymmetricCipherInterface` 的别名，Rust 侧只保留一个 [`SymmetricCipher`]。

use crate::error::Result;

/// 任何可注册进注册表的能力都带一个稳定标识（如 `aes-256-gcm`）。
pub trait Identified {
    fn identifier(&self) -> &str;
}

impl<T: Identified + ?Sized> Identified for Box<T> {
    fn identifier(&self) -> &str {
        (**self).identifier()
    }
}

/// 对称加密：同一实例绑定固定密钥，对二进制载荷加解密。
pub trait SymmetricCipher: Identified + Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// 非对称加密：每次调用传入密钥材料（十六进制，格式由实现决定，如 SM2）。
pub trait AsymmetricCipher: Identified + Send + Sync {
    /// 返回十六进制密文。
    fn encrypt(&self, plaintext: &[u8], public_key_hex: &str) -> Result<String>;

    fn decrypt(&self, ciphertext_hex: &str, private_key_hex: &str) -> Result<Vec<u8>>;
}

/// 哈希：单向摘要，无密钥。
pub trait Hasher: Identified + Send + Sync {
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// 十六进制摘要；实现只需要实现 [`Hasher::digest`]。
    fn digest_hex(&self, data: &[u8]) -> Result<String> {
        Ok(crate::internal::hex_encode(&self.digest(data)?))
    }
}

/// 基于密钥材料的派生（典型为 HKDF）：从 IKM + salt + info 得到任意长度输出。
pub trait KeyDerivation: Identified + Send + Sync {
    /// `ikm`：输入密钥材料（如主密钥、DH 共享秘密）；
    /// `salt`：盐值（可为空，但建议非空随机）；
    /// `info`：可选上下文信息（如协议标签）。
    fn derive(&self, ikm: &[u8], salt: &[u8], length: usize, info: &[u8]) -> Result<Vec<u8>>;
}

/// 基于口令的密钥派生（典型为 PBKDF2）：从人类可读口令得到固定长度密钥。
pub trait PasswordBasedKdf: Identified + Send + Sync {
    /// `salt`：随机盐（建议每用户 / 每密钥唯一）。
    fn derive_from_password(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>>;
}

/// 签名：消息签名与验签。密钥与签名均为十六进制，格式由实现决定
/// （本项目内统一：ECDSA / SM2 为定长 `r‖s`，Ed25519 为 64 字节定长）。
pub trait Signer: Identified + Send + Sync {
    /// 对消息签名，返回十六进制签名（失败不为原因分类）。
    fn sign(&self, message: &[u8], private_key_hex: &str) -> Result<String>;

    /// 验签；失败与格式错误一律 [`Error::VerificationFailed`]（不区分原因）。
    fn verify(&self, message: &[u8], signature_hex: &str, public_key_hex: &str) -> Result<()>;
}

/// 密钥封装（KEM，FIPS 203 ML-KEM）：公钥封装 → (密文, 共享密钥)；私钥解封装。
/// 公钥、私钥、密文与共享密钥均为十六进制。
pub trait KeyEncapsulation: Identified + Send + Sync {
    /// 生成密钥对，返回 `(公钥 hex, 私钥 hex)`。
    fn generate(&self) -> Result<(String, String)>;

    /// 用公钥封装，返回 `(密文 hex, 共享密钥 hex)`。
    fn encapsulate(&self, public_key_hex: &str) -> Result<(String, String)>;

    /// 用私钥解封装，返回共享密钥 hex。
    /// 注意：ML-KEM 对非法密文执行隐式拒绝（不报错，返回与封装端不同的
    /// 伪随机密钥），这是标准行为，不视为错误。
    fn decapsulate(&self, ciphertext_hex: &str, private_key_hex: &str) -> Result<String>;
}
