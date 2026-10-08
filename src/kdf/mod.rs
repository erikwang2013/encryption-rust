// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 密钥派生实现（对应 PHP 版 `Kdf/`）。

mod argon2;
mod hkdf_sha256;
mod pbkdf2_sha256;
mod scrypt;

pub use argon2::Argon2Kdf;
pub use hkdf_sha256::HkdfSha256;
pub use pbkdf2_sha256::Pbkdf2Sha256;
pub use scrypt::ScryptKdf;
