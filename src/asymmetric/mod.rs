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
///
/// `Debug` 打码：私钥永远不打印（与 [`crate::key::Key`] 同款遮蔽）。本库
/// 「Debug 遮蔽」的安全默认值对密钥材质一律生效，密钥生成接口的返回值也不例外。
#[derive(Clone, PartialEq, Eq)]
pub struct KeyPairHex {
    pub private_key_hex: String,
    pub public_key_hex: String,
}

impl std::fmt::Debug for KeyPairHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPairHex")
            .field("private_key_hex", &"***")
            .field("public_key_hex", &self.public_key_hex)
            .finish()
    }
}

impl KeyPairHex {
    /// 公钥（hex），可安全写日志。
    pub fn public_only(&self) -> &str {
        &self.public_key_hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 私钥不得出现在 `Debug` 输出里——这是 README 声明的安全默认值，
    /// 也是 `Key<N>` 已做到的遮蔽。所有 `generate_key_pair_hex()` 返回本类型。
    #[test]
    fn debug_redacts_the_private_key() {
        let pair = KeyPairHex {
            private_key_hex: "deadbeef".repeat(8),
            public_key_hex: "cafebabe".repeat(8),
        };
        let text = format!("{pair:?}");
        assert!(!text.contains("deadbeef"), "私钥泄漏进 Debug: {text}");
        assert!(text.contains("cafebabe"), "公钥应照常打印: {text}");
        assert!(text.contains("***"));
    }

    /// `Debug` 遮蔽不改变值语义：比较与克隆照旧。
    #[test]
    fn debug_redaction_keeps_value_semantics() {
        let pair = KeyPairHex {
            private_key_hex: "aa".repeat(32),
            public_key_hex: "bb".repeat(33),
        };
        assert_eq!(pair.clone(), pair);
        assert_eq!(pair.public_only(), pair.public_key_hex);
    }
}
