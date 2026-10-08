// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 国密实现（对应 PHP 版 `Guomi/`）：SM3 哈希、SM4-CBC 与 SM4-GCM、ZUC-128 /
//! ZUC-256 流密码、SM2 非对称加解密与签名 / 验签，以及不提供实现的
//! SM1 / SM7 / SM9 占位。

mod sm2;
mod sm3;
mod sm4;
mod sm4_gcm;
mod zuc;
mod zuc256;

pub mod unavailable;

pub use sm2::{DEFAULT_DIST_ID, KeyPairHex, Sm2AsymmetricCipher, Sm2Service, Sm2Signer};
pub use sm3::Sm3Hasher;
pub use sm4::Sm4CbcEncryptor;
pub use sm4_gcm::Sm4GcmEncryptor;
pub use zuc::Zuc128Encryptor;
pub use zuc256::Zuc256Encryptor;
