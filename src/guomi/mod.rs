// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 国密实现（对应 PHP 版 `Guomi/`）：SM3 哈希、SM4-CBC、ZUC-128 流密码、
//! SM2 非对称加解密，以及不提供实现的 SM1 / SM7 / SM9 占位。

mod sm2;
mod sm3;
mod sm4;
mod zuc;

pub mod unavailable;

pub use sm2::{KeyPairHex, Sm2AsymmetricCipher, Sm2Service};
pub use sm3::Sm3Hasher;
pub use sm4::Sm4CbcEncryptor;
pub use zuc::Zuc128Encryptor;
