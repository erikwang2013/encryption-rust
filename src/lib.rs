// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 可插拔密码学组件库的 Rust 实现：在统一契约下提供对称加密、非对称加密、
//! 哈希与密钥派生（HKDF / PBKDF2），包含 AES/Sodium 与国密 SM2/SM3/SM4/ZUC 等实现。
//!
//! 架构与原版（PHP 包 `erikwang2013/encryption`）一致：契约（trait）→ 注册表
//! （Registry）→ 门面（Manager）→ 实现；[`EncryptionManagerFactory::from_master_key`]
//! 从 32 字节主密钥按用途标签派生各算法子密钥。
//!
//! crate 采用 Rust 独立格式：密文不与 PHP 版字节级互通（见 README「与原版的差异」）。

pub mod asymmetric;
pub mod contract;
pub mod encryptor;
pub mod error;
pub mod factory;
pub mod guard;
pub mod guomi;
pub mod hash;
pub mod integrations;
pub mod kdf;
pub mod key;
pub mod manager;
pub mod registry;

/// 项目宠物「Locky」：NAME / TAGLINE / ASCII / SVG。
pub mod pet;

// 常用类型提根：`encryption::Error` / `encryption::Result`（与兄弟项目一致）。
pub use error::{Error, Result};

mod internal;
