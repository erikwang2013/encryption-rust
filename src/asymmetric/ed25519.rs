// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! Ed25519 签名 / 验签（RFC 8032）。
//!
//! 十六进制约定：
//! - 私钥：32 字节 seed hex（64 位，即 ed25519-dalek `SigningKey` 的序列化形式）；
//! - 公钥：32 字节裸公钥 hex（64 位，压缩 Edwards-y 编码）；
//! - 签名：64 字节定长 hex（128 位）。
//!
//! 签名不消耗随机源（Ed25519 本身确定性）；验签走 ed25519-dalek 的
//! `verify_strict`：RFC 8032 判定之外，额外拒绝**小阶公钥**与非规范 R 编码——
//! 公钥若来自不可信来源，普通 `verify` 允许小阶公钥使任意消息「验签通过」，
//! 本库按防御姿态选择严格模式（诚实签名方不受影响）。

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use rand_core::OsRng;

use crate::asymmetric::KeyPairHex;
use crate::contract::{Identified, Signer};
use crate::error::{Error, Result};
use crate::internal::{hex_decode, hex_encode};

const LABEL: &str = "Ed25519";

/// Ed25519 签名器（实现 [`crate::contract::Signer`]）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Signer;

impl Ed25519Signer {
    pub const IDENTIFIER: &'static str = "ed25519";

    pub fn new() -> Self {
        Self
    }

    /// 对消息签名，返回 64 字节定长签名 hex。
    fn sign_hex(message: &[u8], private_key_hex: &str) -> Result<String> {
        let seed =
            parse_32_bytes(private_key_hex).map_err(|_| Error::InvalidKey { label: LABEL })?;
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(hex_encode(&signing_key.sign(message).to_bytes()))
    }

    /// 验签；格式错误、密钥非法、签名不对一律 [`Error::VerificationFailed`]。
    fn verify_hex(message: &[u8], signature_hex: &str, public_key_hex: &str) -> Result<()> {
        let public_bytes = parse_32_bytes(public_key_hex)
            .map_err(|_| Error::VerificationFailed { label: LABEL })?;
        let verifying_key = VerifyingKey::from_bytes(&public_bytes)
            .map_err(|_| Error::VerificationFailed { label: LABEL })?;
        let signature_bytes =
            hex_decode(signature_hex).map_err(|_| Error::VerificationFailed { label: LABEL })?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| Error::VerificationFailed { label: LABEL })?;
        verifying_key
            .verify_strict(message, &signature)
            .map_err(|_| Error::VerificationFailed { label: LABEL })
    }

    /// 生成密钥对：私钥 = seed hex，公钥 = 裸公钥 hex；随机源为系统 CSPRNG。
    pub fn generate_key_pair_hex() -> Result<KeyPairHex> {
        let signing_key = SigningKey::generate(&mut OsRng);
        Ok(KeyPairHex {
            private_key_hex: hex_encode(&signing_key.to_bytes()),
            public_key_hex: hex_encode(signing_key.verifying_key().as_bytes()),
        })
    }
}

/// 十六进制 → 定长 32 字节（seed / 公钥都是 32 字节）。
fn parse_32_bytes(hex: &str) -> Result<[u8; 32]> {
    hex_decode(hex)?.try_into().map_err(|_| Error::InvalidHex)
}

impl Identified for Ed25519Signer {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8], private_key_hex: &str) -> Result<String> {
        Self::sign_hex(message, private_key_hex)
    }

    fn verify(&self, message: &[u8], signature_hex: &str, public_key_hex: &str) -> Result<()> {
        Self::verify_hex(message, signature_hex, public_key_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KAT：RFC 8032 §7.1 TEST 1 —— 空消息。
    /// 向量出处 RFC 8032 §7.1（seed / 公钥 / 签名均为 RFC 原文定值）。
    #[test]
    fn rfc8032_test1_empty_message() {
        const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        const PUBLIC_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        const SIGNATURE: &str = concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );

        let signer = Ed25519Signer::new();
        let signature = signer.sign(b"", SEED).unwrap();
        assert_eq!(signature, SIGNATURE);

        signer.verify(b"", SIGNATURE, PUBLIC_KEY).unwrap();
        // 篡改一个字节 → 必败。
        let mut tampered = SIGNATURE.to_string();
        let last = tampered.len() - 1;
        let flipped = if tampered.as_bytes()[last] == b'0' {
            '1'
        } else {
            '0'
        };
        tampered.replace_range(last.., &flipped.to_string());
        assert!(signer.verify(b"", &tampered, PUBLIC_KEY).is_err());
    }

    /// KAT：RFC 8032 §7.1 TEST 3 —— 2 字节消息 `af82`。
    #[test]
    fn rfc8032_test3_two_byte_message() {
        const SEED: &str = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
        const PUBLIC_KEY: &str = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
        const SIGNATURE: &str = concat!(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        );
        let message = hex_decode("af82").unwrap();

        let signer = Ed25519Signer::new();
        assert_eq!(signer.sign(&message, SEED).unwrap(), SIGNATURE);
        signer.verify(&message, SIGNATURE, PUBLIC_KEY).unwrap();
        // 换消息 → 必败。
        assert!(signer.verify(b"af83", SIGNATURE, PUBLIC_KEY).is_err());
    }

    #[test]
    fn keypair_roundtrip_and_hex_shapes() {
        let pair = Ed25519Signer::generate_key_pair_hex().unwrap();
        assert_eq!(pair.private_key_hex.len(), 64);
        assert_eq!(pair.public_key_hex.len(), 64);

        let signer = Ed25519Signer::new();
        let message = "非 ASCII 消息 🎉".as_bytes();
        let signature = signer.sign(message, &pair.private_key_hex).unwrap();
        assert_eq!(signature.len(), 128);
        signer
            .verify(message, &signature, &pair.public_key_hex)
            .unwrap();

        // 换一把密钥 / 换消息 → 必败。
        let other = Ed25519Signer::generate_key_pair_hex().unwrap();
        assert!(
            signer
                .verify(message, &signature, &other.public_key_hex)
                .is_err()
        );
        assert!(
            signer
                .verify(b"changed", &signature, &pair.public_key_hex)
                .is_err()
        );
    }

    #[test]
    fn signatures_are_deterministic() {
        let pair = Ed25519Signer::generate_key_pair_hex().unwrap();
        let signer = Ed25519Signer::new();
        assert_eq!(
            signer.sign(b"same", &pair.private_key_hex).unwrap(),
            signer.sign(b"same", &pair.private_key_hex).unwrap(),
        );
    }

    #[test]
    fn malformed_keys_are_rejected() {
        let pair = Ed25519Signer::generate_key_pair_hex().unwrap();
        let signer = Ed25519Signer::new();

        assert_eq!(
            signer.sign(b"x", "zz").unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
        // 31 字节 seed：长度不对。
        assert_eq!(
            signer.sign(b"x", &pair.private_key_hex[..62]).unwrap_err(),
            Error::InvalidKey { label: LABEL }
        );
        assert_eq!(
            signer.verify(b"x", "00", &pair.public_key_hex).unwrap_err(),
            Error::VerificationFailed { label: LABEL }
        );
        assert_eq!(
            signer
                .verify(b"x", "00", &pair.public_key_hex[..62])
                .unwrap_err(),
            Error::VerificationFailed { label: LABEL }
        );
    }

    #[test]
    fn identifier_is_stable() {
        assert_eq!(Ed25519Signer::new().identifier(), "ed25519");
    }
}
