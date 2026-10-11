// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 国密 SM4-CBC + HMAC-SHA256（encrypt-then-MAC，PKCS#7 填充）；
//! 载荷：`v1 | IV(16) | MAC(32) | 密文`。密钥 16 字节。
//!
//! 实现见 [`crate::encryptor::cbc_hmac`]：六个 CBC-HMAC 标识共用同一个泛型
//! [`crate::encryptor::CbcHmacEncryptor`]，本文件只保留历史类型名。

pub use crate::encryptor::cbc_hmac::Sm4CbcEncryptor;
