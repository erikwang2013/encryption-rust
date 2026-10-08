// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 哈希实现（对应 PHP 版 `Hash/`；SM3 位于 `guomi/`）。

mod belt;
mod blake2;
mod blake3;
mod sha256;
mod sha3;
mod streebog;

pub use belt::BeltHashHasher;
pub use blake2::{Blake2b512Hasher, Blake2s256Hasher};
pub use blake3::Blake3Hasher;
pub use sha3::{Sha3_256Hasher, Sha3_512Hasher};
pub use sha256::Sha256Hasher;
pub use streebog::{Streebog256Hasher, Streebog512Hasher};
