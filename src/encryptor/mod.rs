// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 对称加密实现（对应 PHP 版 `Encryptor/`）。

mod aes256cbc;
mod aes256gcm;
mod sodium_xchacha20;

pub use aes256cbc::Aes256CbcEncryptor;
pub use aes256gcm::Aes256GcmEncryptor;
pub use sodium_xchacha20::SodiumXChaCha20Encryptor;
