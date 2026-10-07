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

use base64::Engine as _;

use crate::error::{Error, Result};
use crate::manager::EncryptionManager;

/// 主密钥环境变量名。
const MASTER_KEY_ENV: &str = "ENCRYPTION_MASTER_KEY";
/// 默认算法环境变量名（可选）。
const ALGORITHM_ENV: &str = "ENCRYPTION_ALGORITHM";
/// 未指定 `ENCRYPTION_ALGORITHM` 时使用的算法。
const DEFAULT_ALGORITHM: &str = "aes-256-gcm";

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

    /// 从进程环境变量构造。
    ///
    /// 读取 `ENCRYPTION_MASTER_KEY`（必需）与 `ENCRYPTION_ALGORITHM`（可选，
    /// 缺省 `aes-256-gcm`）。主密钥值的格式见 [`Self::from_env_with`]。
    pub fn from_env() -> Result<Self> {
        Self::from_env_with(|key| std::env::var(key).ok())
    }

    /// 从可注入的查找函数构造：测试与自定义配置源（KMS / 配置中心）走这里。
    ///
    /// 主密钥取值 `lookup("ENCRYPTION_MASTER_KEY")`，格式为显式前缀
    /// `hex:<十六进制>` / `base64:<Base64>`；无前缀时自动判定：去掉首尾空白后
    /// 恰为 64 个十六进制字符按 hex，否则按 Base64。解码后必须恰好 32 字节，
    /// 否则 [`Error::InvalidMasterKey`]；算法名未注册时冒泡
    /// [`Error::UnknownIdentifier`]。
    ///
    /// ```
    /// use encryption::guard::Guard;
    ///
    /// // 假 lookup：真实场景用 std::env::var 或配置中心
    /// let lookup = |key: &str| match key {
    ///     "ENCRYPTION_MASTER_KEY" => Some("00".repeat(32)), // 裸 hex（64 位）
    ///     _ => None,
    /// };
    ///
    /// let guard = Guard::from_env_with(lookup)?;
    /// assert_eq!(guard.manager().default_identifier(), "aes-256-gcm");
    ///
    /// let blob = guard.encrypt("13800138000".as_bytes())?;
    /// assert_eq!(guard.decrypt(&blob)?, "13800138000".as_bytes());
    /// # Ok::<(), encryption::Error>(())
    /// ```
    pub fn from_env_with<F: Fn(&str) -> Option<String>>(lookup: F) -> Result<Self> {
        let raw = lookup(MASTER_KEY_ENV).ok_or(Error::MissingConfig {
            key: MASTER_KEY_ENV,
        })?;
        let algorithm = lookup(ALGORITHM_ENV).unwrap_or_else(|| DEFAULT_ALGORITHM.to_owned());
        Self::from_master_key(&decode_master_key(&raw)?, &algorithm)
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

/// 解析主密钥取值：显式前缀 `hex:` / `base64:`，无前缀自动判定，
/// 解码失败或长度不为 32 字节一律 [`Error::InvalidMasterKey`]。
fn decode_master_key(raw: &str) -> Result<[u8; 32]> {
    let value = raw.trim();
    let (is_hex, payload) = if let Some(hex) = value.strip_prefix("hex:") {
        (true, hex)
    } else if let Some(b64) = value.strip_prefix("base64:") {
        (false, b64)
    } else if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        (true, value)
    } else {
        (false, value)
    };

    let decoded = if is_hex {
        crate::internal::hex_decode(payload).ok()
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(payload)
            .ok()
    }
    // 解码失败时字节长度未知，got 记 0。
    .ok_or(Error::InvalidMasterKey { got: 0 })?;

    decoded
        .try_into()
        .map_err(|v: Vec<u8>| Error::InvalidMasterKey { got: v.len() })
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

    /// 假 lookup：从一对固定取值里查，不碰 std::env。
    fn fake_env(entries: Vec<(&str, String)>) -> impl Fn(&str) -> Option<String> {
        move |key| {
            entries
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.clone())
        }
    }

    fn roundtrip(guard: &Guard) {
        let blob = guard.encrypt(b"phone").unwrap();
        assert_eq!(guard.decrypt(&blob).unwrap(), b"phone");
    }

    #[test]
    fn from_env_hex_prefix() {
        let hex = "07".repeat(32);
        let lookup = fake_env(vec![(MASTER_KEY_ENV, format!("hex:{hex}"))]);
        let guard = Guard::from_env_with(lookup).unwrap();
        assert_eq!(guard.manager().default_identifier(), "aes-256-gcm");
        roundtrip(&guard);
    }

    #[test]
    fn from_env_base64_prefix() {
        // [7u8; 32] 的 Base64
        let b64 = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
        let lookup = fake_env(vec![(MASTER_KEY_ENV, format!("base64:{b64}"))]);
        let guard = Guard::from_env_with(lookup).unwrap();
        roundtrip(&guard);
    }

    #[test]
    fn from_env_bare_hex_auto_detected() {
        let hex = "00".repeat(32);
        let lookup = fake_env(vec![(MASTER_KEY_ENV, hex)]);
        let guard = Guard::from_env_with(lookup).unwrap();
        roundtrip(&guard);
    }

    #[test]
    fn from_env_missing_master_key() {
        let err = Guard::from_env_with(fake_env(vec![])).unwrap_err();
        assert_eq!(
            err,
            Error::MissingConfig {
                key: "ENCRYPTION_MASTER_KEY"
            }
        );
    }

    #[test]
    fn from_env_wrong_length() {
        // 16 字节（hex: 前缀）→ InvalidMasterKey { got: 16 }
        let lookup = fake_env(vec![(MASTER_KEY_ENV, format!("hex:{}", "00".repeat(16)))]);
        assert_eq!(
            Guard::from_env_with(lookup).unwrap_err(),
            Error::InvalidMasterKey { got: 16 }
        );

        // 24 字节（base64: 前缀）→ InvalidMasterKey { got: 24 }
        let lookup = fake_env(vec![(MASTER_KEY_ENV, format!("base64:{}", "A".repeat(32)))]);
        assert_eq!(
            Guard::from_env_with(lookup).unwrap_err(),
            Error::InvalidMasterKey { got: 24 }
        );

        // 非法 hex → 解码失败，got 记 0
        let lookup = fake_env(vec![(MASTER_KEY_ENV, "hex:zz".to_owned())]);
        assert_eq!(
            Guard::from_env_with(lookup).unwrap_err(),
            Error::InvalidMasterKey { got: 0 }
        );
    }

    #[test]
    fn from_env_respects_algorithm() {
        let lookup = fake_env(vec![
            (MASTER_KEY_ENV, "07".repeat(32)),
            (ALGORITHM_ENV, "sm4-cbc".to_owned()),
        ]);
        let guard = Guard::from_env_with(lookup).unwrap();
        assert_eq!(guard.manager().default_identifier(), "sm4-cbc");
        roundtrip(&guard);
    }

    #[test]
    fn from_env_unknown_algorithm_bubbles() {
        let lookup = fake_env(vec![
            (MASTER_KEY_ENV, "07".repeat(32)),
            (ALGORITHM_ENV, "no-such-algorithm".to_owned()),
        ]);
        assert!(matches!(
            Guard::from_env_with(lookup).unwrap_err(),
            Error::UnknownIdentifier { .. }
        ));
    }
}
