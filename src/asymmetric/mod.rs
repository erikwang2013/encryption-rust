// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 非对称实现：RSA-OAEP 加密，以及 ECDSA / Ed25519 签名与 ECDH / X25519 密钥协商。
//!
//! - [`rsa`]：RSA-OAEP（SHA-256，RFC 8017），实现 [`crate::contract::AsymmetricCipher`]；
//! - [`ecdsa`]：ECDSA P-256（SHA-256）/ P-384（SHA-384）/ secp256k1（SHA-256），
//!   实现 [`crate::contract::Signer`]；
//! - [`ed25519`]：Ed25519（RFC 8032），实现 [`crate::contract::Signer`]；
//! - [`ecdh`]：P-256 / P-384 / secp256k1 的静态 ECDH，实现 [`crate::contract::KeyAgreement`]；
//! - [`x25519`]：X25519（RFC 7748），实现 [`crate::contract::KeyAgreement`]。
//!
//! 各模块的十六进制长度约定见模块文档；密钥生成一律使用系统 CSPRNG。

pub mod ecdh;
pub mod ecdsa;
pub mod ed25519;
pub mod rsa;
pub mod x25519;

pub use rsa::{RsaOaepSha256Cipher, RsaOaepSha256Service};

/// 非对称密钥对（十六进制）：私钥与公钥的具体格式随算法（见各模块文档）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPairHex {
    pub private_key_hex: String,
    pub public_key_hex: String,
}
