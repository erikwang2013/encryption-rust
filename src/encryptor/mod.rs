// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 对称加密实现（对应 PHP 版 `Encryptor/`）。
//!
//! CBC + HMAC（encrypt-then-MAC）一族共用一个泛型实现 [`cbc_hmac::CbcHmacEncryptor`]：
//! AES / Camellia / ARIA / Kuznyechik / Threefish-512 / SM4 只是泛型参数不同，
//! 各自的历史类型名由 `cbc_hmac` 里的别名保持。

mod aes256cbc;
mod aes256gcm;
mod aes256gcm_siv;
mod aria256cbc;
mod camellia256cbc;
pub mod cbc_hmac;
mod chacha20poly1305_ietf;
mod kuznyechikcbc;
mod salsa20;
mod sodium_xchacha20;
mod threefish512cbc;

pub use aes256cbc::Aes256CbcEncryptor;
pub use aes256gcm::Aes256GcmEncryptor;
pub use aes256gcm_siv::Aes256GcmSivEncryptor;
pub use aria256cbc::Aria256CbcEncryptor;
pub use camellia256cbc::Camellia256CbcEncryptor;
pub use chacha20poly1305_ietf::ChaCha20Poly1305IetfEncryptor;
pub use kuznyechikcbc::Kuznyechik256CbcEncryptor;
pub use salsa20::Salsa20Encryptor;
pub use sodium_xchacha20::SodiumXChaCha20Encryptor;
pub use threefish512cbc::Threefish512CbcEncryptor;
