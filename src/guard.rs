// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 请求守卫：交给处理器的一个共享加密句柄。
//!
//! 框架集成层（axum / actix-web / rocket / poem / salvo / warp / bee-rust / e-cat）
//! 全都在这一层之上做薄适配 —— 把 [`Guard`] 按各自框架的惯例注入请求上下文，
//! 处理器拿到它就能加解密，不必把主密钥或 Manager 一路透传下去。
//!
//! ```no_run
//! use encryption::guard::Guard;
//!
//! let master_key = [7u8; 32]; // 生产环境从环境变量 / KMS 读取
//! let guard = Guard::from_master_key(&master_key, "aes-256-gcm")?;
//!
//! // 处理器里
//! let stored = guard.encrypt("13800138000".as_bytes())?;
//! assert_eq!(guard.decrypt(&stored)?, "13800138000".as_bytes());
//! # Ok::<(), encryption::Error>(())
//! ```
//!
//! # 为什么是 `Arc`
//!
//! 每个请求都要拿到同一个 Manager，而框架普遍要求注入的状态是 `Send + Sync + 'static`
//! 且常常要求 `Clone`。Manager 本身是只读的、构造后不再变，所以 `Arc` 共享即可 ——
//! 子密钥只在构造时派生一次，每请求零成本。

use std::sync::Arc;

use crate::error::Result;
use crate::manager::EncryptionManager;

/// 请求守卫：一个可跨请求共享、可跨线程克隆的加密句柄。
///
/// 构造之后的一切加解密都经由它转发到 [`EncryptionManager`]；克隆只是
/// `Arc` 引用计数递增，不含任何密钥拷贝。
#[derive(Debug, Clone)]
pub struct Guard {
    manager: Arc<EncryptionManager>,
}

impl Guard {
    /// 从一个已经建好的 Manager 构造。
    pub fn new(manager: EncryptionManager) -> Self {
        Self {
            manager: Arc::new(manager),
        }
    }

    /// 从 32 字节主密钥构造（内部走 [`crate::factory::EncryptionManagerFactory`]）。
    ///
    /// 构造时即完成全部校验（主密钥长度、默认算法是否注册），配置错了就在启动时炸。
    pub fn from_master_key(master_key: &[u8], default_identifier: &str) -> Result<Self> {
        Ok(Self::new(
            crate::factory::EncryptionManagerFactory::from_master_key(
                master_key,
                default_identifier,
            )?,
        ))
    }

    /// 共享的 Manager。总是存在。
    pub fn manager(&self) -> &EncryptionManager {
        &self.manager
    }

    /// 用默认算法加密。
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.manager.encrypt(plaintext)
    }

    /// 用默认算法解密。
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.manager.decrypt(ciphertext)
    }

    /// 用指定算法加密。
    pub fn encrypt_with(&self, identifier: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.manager.encrypt_with(identifier, plaintext)
    }

    /// 用指定算法解密。
    pub fn decrypt_with(&self, identifier: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.manager.decrypt_with(identifier, ciphertext)
    }

    /// 已注册算法标识（健康检查 / 日志用）。
    pub fn identifiers(&self) -> Vec<&str> {
        self.manager.registry().identifiers()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> Guard {
        Guard::from_master_key(&[7u8; 32], "aes-256-gcm").unwrap()
    }

    #[test]
    fn wraps_the_factory_and_forwards() {
        let guard = guard();
        assert_eq!(guard.identifiers().len(), 5);
        assert_eq!(guard.manager().default_identifier(), "aes-256-gcm");

        let blob = guard.encrypt(b"phone").unwrap();
        assert_eq!(guard.decrypt(&blob).unwrap(), b"phone");

        let blob = guard.encrypt_with("sm4-cbc", b"phone").unwrap();
        assert_eq!(guard.decrypt_with("sm4-cbc", &blob).unwrap(), b"phone");
    }

    #[test]
    fn clones_share_one_manager() {
        let guard = guard();
        let clone = guard.clone();
        let blob = guard.encrypt(b"shared").unwrap();
        assert_eq!(clone.decrypt(&blob).unwrap(), b"shared");
        assert_eq!(Arc::strong_count(&guard.manager), 2);
    }

    #[test]
    fn invalid_master_key_fails_at_construction() {
        assert!(Guard::from_master_key(&[0u8; 16], "aes-256-gcm").is_err());
        assert!(Guard::from_master_key(&[0u8; 32], "no-such-algorithm").is_err());
    }
}
