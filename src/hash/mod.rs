// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 哈希实现（对应 PHP 版 `Hash/`；SM3 位于 `guomi/`）。

mod sha256;

pub use sha256::Sha256Hasher;
