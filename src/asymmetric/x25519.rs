// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! X25519 密钥协商（RFC 7748）。
//!
//! 私钥（裸标量）/ 对方公钥（Montgomery u 坐标）/ 共享秘密均为 32 字节
//! （64 位十六进制）；私钥在运算时按 RFC 7748 做 clamp。
//!
//! 全零共享秘密（对方给出小阶点，如全零 u 坐标）会被拒绝为
//! [`Error::InvalidKey`]——见 `SharedSecret::was_contributory`。

use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::asymmetric::KeyPairHex;
use crate::contract::{Identified, KeyAgreement};
use crate::error::{Error, Result};
use crate::internal::{hex_decode, hex_encode};

const LABEL: &str = "X25519";

/// X25519 密钥协商器（实现 [`crate::contract::KeyAgreement`]）。
#[derive(Debug, Default, Clone, Copy)]
pub struct X25519Agreement;

impl X25519Agreement {
    pub const IDENTIFIER: &'static str = "x25519";

    pub fn new() -> Self {
        Self
    }

    /// 导出共享秘密（32 字节 hex）；对方公钥是小阶点（共享秘密全零）时拒绝。
    fn agree_hex(private_key_hex: &str, peer_public_key_hex: &str) -> Result<String> {
        let private_bytes =
            parse_32_bytes(private_key_hex).map_err(|_| Error::InvalidKey { label: LABEL })?;
        let peer_bytes =
            parse_32_bytes(peer_public_key_hex).map_err(|_| Error::InvalidKey { label: LABEL })?;

        let shared_secret =
            StaticSecret::from(private_bytes).diffie_hellman(&PublicKey::from(peer_bytes));
        if !shared_secret.was_contributory() {
            return Err(Error::InvalidKey { label: LABEL });
        }
        Ok(hex_encode(shared_secret.as_bytes()))
    }

    /// 生成密钥对（私钥 / 公钥均为 32 字节 hex）；随机源为系统 CSPRNG。
    pub fn generate_key_pair_hex() -> Result<KeyPairHex> {
        let secret = StaticSecret::random_from_rng(OsRng);
        Ok(KeyPairHex {
            private_key_hex: hex_encode(secret.as_bytes()),
            public_key_hex: hex_encode(PublicKey::from(&secret).as_bytes()),
        })
    }
}

/// 十六进制 → 定长 32 字节（标量 / u 坐标都是 32 字节）。
fn parse_32_bytes(hex: &str) -> Result<[u8; 32]> {
    hex_decode(hex)?.try_into().map_err(|_| Error::InvalidHex)
}

impl Identified for X25519Agreement {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl KeyAgreement for X25519Agreement {
    fn agree(&self, private_key_hex: &str, peer_public_key_hex: &str) -> Result<String> {
        Self::agree_hex(private_key_hex, peer_public_key_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KAT：RFC 7748 §5.2（X25519 定值向量）——alice / bob 私钥与对端公钥
    /// 导出的共享秘密是同一个定值 K。
    #[test]
    fn rfc7748_5_2_shared_secret_matches_vector() {
        const ALICE_PRIVATE: &str =
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        const ALICE_PUBLIC: &str =
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        const BOB_PRIVATE: &str =
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        const SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

        let agreement = X25519Agreement::new();
        assert_eq!(agreement.agree(ALICE_PRIVATE, BOB_PUBLIC).unwrap(), SHARED);
        assert_eq!(agreement.agree(BOB_PRIVATE, ALICE_PUBLIC).unwrap(), SHARED);
        // 两把私钥与对方的公钥交叉相乘，结果相同（对称性）。
        assert_eq!(
            agreement.agree(ALICE_PRIVATE, BOB_PUBLIC).unwrap(),
            agreement.agree(BOB_PRIVATE, ALICE_PUBLIC).unwrap(),
        );
    }

    /// KAT：RFC 7748 §6.1（Curve25519 标量乘定值向量，含 clamp 行为）。
    #[test]
    fn rfc7748_6_1_scalar_multiplication_matches_vector() {
        const SCALAR: &str = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
        const U_COORDINATE: &str =
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
        const OUTPUT: &str = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";

        assert_eq!(
            X25519Agreement::new().agree(SCALAR, U_COORDINATE).unwrap(),
            OUTPUT
        );
    }

    #[test]
    fn keypair_roundtrip_and_hex_shapes() {
        let alice = X25519Agreement::generate_key_pair_hex().unwrap();
        let bob = X25519Agreement::generate_key_pair_hex().unwrap();
        assert_eq!(alice.private_key_hex.len(), 64);
        assert_eq!(alice.public_key_hex.len(), 64);

        let agreement = X25519Agreement::new();
        let left = agreement
            .agree(&alice.private_key_hex, &bob.public_key_hex)
            .unwrap();
        let right = agreement
            .agree(&bob.private_key_hex, &alice.public_key_hex)
            .unwrap();
        assert_eq!(left, right);
        assert_eq!(left.len(), 64);

        // 换一把私钥 → 共享秘密不同。
        let mallory = X25519Agreement::generate_key_pair_hex().unwrap();
        assert_ne!(
            agreement
                .agree(&mallory.private_key_hex, &bob.public_key_hex)
                .unwrap(),
            left
        );
    }

    /// 小阶点（全零 u 坐标）→ 共享秘密全零，必须拒绝。
    #[test]
    fn low_order_peer_public_key_is_rejected() {
        let alice = X25519Agreement::generate_key_pair_hex().unwrap();
        assert_eq!(
            X25519Agreement::new()
                .agree(&alice.private_key_hex, &"00".repeat(32))
                .unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
    }

    #[test]
    fn malformed_keys_are_rejected() {
        let alice = X25519Agreement::generate_key_pair_hex().unwrap();
        let agreement = X25519Agreement::new();

        assert_eq!(
            agreement.agree("zz", &alice.public_key_hex).unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
        // 31 字节：长度不对。
        assert_eq!(
            agreement
                .agree(&alice.private_key_hex[..62], &alice.public_key_hex)
                .unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
    }

    #[test]
    fn identifier_is_stable() {
        assert_eq!(X25519Agreement::new().identifier(), "x25519");
    }
}
