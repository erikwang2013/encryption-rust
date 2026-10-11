// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! AES-256-CBC + HMAC-SHA256（兼容旧环境，CBC + PKCS#7 填充）。
//!
//! 载荷：`v1 | IV(16) | MAC(32) | 密文`。密钥 32 字节。
//!
//! 实现见 [`super::cbc_hmac`]：六个 CBC-HMAC 标识（本文件、`aria256cbc`、
//! `kuznyechikcbc`、`threefish512cbc`、`guomi::Sm4CbcEncryptor`）此前是六份
//! 逐字节相同的代码，现共用同一个泛型实现。本文件只保留历史类型名与模块路径。

pub use super::cbc_hmac::Aes256CbcEncryptor;
