// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 对称加密实现（对应 PHP 版 `Encryptor/`）。

mod aes256cbc;
mod aes256gcm;
mod aria256cbc;
mod camellia256cbc;
mod kuznyechikcbc;
mod salsa20;
mod sodium_xchacha20;
mod threefish512cbc;

pub use aes256cbc::Aes256CbcEncryptor;
pub use aes256gcm::Aes256GcmEncryptor;
pub use aria256cbc::Aria256CbcEncryptor;
pub use camellia256cbc::Camellia256CbcEncryptor;
pub use kuznyechikcbc::Kuznyechik256CbcEncryptor;
pub use salsa20::Salsa20Encryptor;
pub use sodium_xchacha20::SodiumXChaCha20Encryptor;
pub use threefish512cbc::Threefish512CbcEncryptor;
