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

use sha2::Digest;

use crate::contract::{Hasher, Identified};
use crate::error::Result;

/// 哈希器与底层摘要之间的桥：声明 `Core` 即由 blanket impl 获得 [`Hasher`]。
///
/// `Core` 走 RustCrypto `digest` **0.10** 代际：sha2 / sha3 / blake2 / streebog /
/// belt-hash 转出的是同一个 `Digest` trait，故一个 blanket 覆盖全部（bound 写作
/// `sha2::Digest` 只是取路径，本 crate 未直接依赖 `digest`）。SM3（`sm3` crate
/// 属 digest 0.11 代际）与 BLAKE3（独立实现，不走 digest trait）不适用，
/// 二者各自实现 [`Hasher`]。
pub trait NamedDigest {
    /// 提供摘要的底层实现。
    type Core: Digest;
}

impl<D: NamedDigest + Identified + Send + Sync> Hasher for D {
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(D::Core::digest(data).to_vec())
    }
}

/// 生成无状态哈希器 ZST：固有 `IDENTIFIER` / `new()` 加 `Identified`
/// （`Identified` 不能走 blanket——会与 `Box<T>` 的既有实现冲突）；
/// 摘要来源由各文件以 `NamedDigest`（SM3 / BLAKE3 则各自实现 `Hasher`）补上。
macro_rules! hasher {
    ($name:ident, $identifier:literal, $doc:literal $(,)?) => {
        #[doc = $doc]
        #[derive(Debug, Default, Clone, Copy)]
        pub struct $name;

        impl $name {
            pub const IDENTIFIER: &'static str = $identifier;

            pub fn new() -> Self {
                Self
            }
        }

        impl $crate::contract::Identified for $name {
            fn identifier(&self) -> &str {
                Self::IDENTIFIER
            }
        }
    };
}

pub(crate) use hasher;
