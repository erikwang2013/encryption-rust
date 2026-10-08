// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! ECDSA 签名 / 验签：P-256（SHA-256）、P-384（SHA-384）、secp256k1（SHA-256）。
//!
//! 十六进制约定（与国密 SM2 一致）：
//! - 私钥：裸标量定长 hex（P-256 / secp256k1 64 位，P-384 96 位）；
//! - 公钥：SEC1 非压缩点 `04‖X‖Y` hex（P-256 / secp256k1 130 位，P-384 194 位）；
//! - 签名：定长 `r‖s` hex（P-256 / secp256k1 128 位，P-384 192 位）。
//!
//! 签名 nonce 走 RFC 6979 确定性路径：`ecdsa` 0.16 的 `Signer` 实现即 RFC 6979 §3.2
//! 算法（已在 ecdsa-0.16.9 源码确认），同私钥 + 同消息的签名逐字节可复现，
//! 不消耗随机源（RFC 6979 附录 A.2.5 定值向量已入测试）。
//!
//! **low-s 归一化**：签名输出前对 `s` 取 `min(s, n−s)`（BIP-62 惯例），消除
//! `(r, s)` / `(r, n−s)` 双解延展性——同一消息 + 密钥只有唯一签名字节串，
//! 适合以签名字节做去重 / 缓存键的场景。RFC 6979 原始向量中 s 高于 n/2 的
//! 条目，测试按归一化后的期望值断言（r 不变，n−s 已独立复算核对）。

use rand_core::OsRng;

// signature 2.2.0 在依赖图里只有一份实例，从 p256 的再导出引入一次即可
// 供三条曲线共用（p384 / k256 的 ecdsa 模块再导出的是同一批类型）。
use p256::ecdsa::signature::{Signer as _, Verifier as _};

use crate::asymmetric::KeyPairHex;
use crate::contract::{Identified, Signer};
use crate::error::{Error, Result};
use crate::internal::{hex_decode, hex_encode};

/// 为 `$curve`（p256 / p384 / k256）生成一个实现 [`Signer`] 的签名器。
macro_rules! ecdsa_signer {
    ($(#[$doc:meta])* $name:ident, $label:literal, $identifier:literal, $curve:ident) => {
        $(#[$doc])*
        #[derive(Debug, Default, Clone, Copy)]
        pub struct $name;

        impl $name {
            pub const IDENTIFIER: &'static str = $identifier;

            pub fn new() -> Self {
                Self
            }

            /// 对消息签名（RFC 6979 确定性 nonce + low-s 归一化），返回定长 `r‖s` hex。
            fn sign_hex(message: &[u8], private_key_hex: &str) -> Result<String> {
                let private_bytes = hex_decode(private_key_hex)
                    .map_err(|_| Error::InvalidKey { label: $label })?;
                let signing_key = $curve::ecdsa::SigningKey::from_slice(&private_bytes)
                    .map_err(|_| Error::InvalidKey { label: $label })?;
                // 标注签名类型：`SigningKey` 对 `Signer` 有多个实现（定长与 DER）。
                // try_sign 而非 sign：签名路径理论失败返回错误，不 panic（与 SM2 同款）。
                let signature: $curve::ecdsa::Signature = signing_key
                    .try_sign(message)
                    .map_err(|_| Error::SignFailed { label: $label })?;
                // low-s 归一化（BIP-62 惯例）：`(r, s)` 与 `(r, n−s)` 只保留一个。
                let signature = signature.normalize_s().unwrap_or(signature);
                Ok(hex_encode(signature.to_bytes().as_slice()))
            }

            /// 验签；格式错误、密钥非法、签名不对一律
            /// [`Error::VerificationFailed`]（不区分原因）。
            fn verify_hex(
                message: &[u8],
                signature_hex: &str,
                public_key_hex: &str,
            ) -> Result<()> {
                let public_bytes = hex_decode(public_key_hex)
                    .map_err(|_| Error::VerificationFailed { label: $label })?;
                let verifying_key = $curve::ecdsa::VerifyingKey::from_sec1_bytes(&public_bytes)
                    .map_err(|_| Error::VerificationFailed { label: $label })?;
                let signature_bytes = hex_decode(signature_hex)
                    .map_err(|_| Error::VerificationFailed { label: $label })?;
                let signature = $curve::ecdsa::Signature::from_slice(&signature_bytes)
                    .map_err(|_| Error::VerificationFailed { label: $label })?;
                verifying_key
                    .verify(message, &signature)
                    .map_err(|_| Error::VerificationFailed { label: $label })
            }

            /// 生成密钥对：私钥 = 标量 hex，公钥 = SEC1 非压缩点 `04‖X‖Y` hex；
            /// 随机源为系统 CSPRNG。
            pub fn generate_key_pair_hex() -> Result<KeyPairHex> {
                let signing_key = $curve::ecdsa::SigningKey::random(&mut OsRng);
                let public_key = signing_key.verifying_key().to_encoded_point(false);
                Ok(KeyPairHex {
                    private_key_hex: hex_encode(signing_key.to_bytes().as_slice()),
                    public_key_hex: hex_encode(public_key.as_bytes()),
                })
            }
        }

        impl Identified for $name {
            fn identifier(&self) -> &str {
                Self::IDENTIFIER
            }
        }

        impl Signer for $name {
            fn sign(&self, message: &[u8], private_key_hex: &str) -> Result<String> {
                Self::sign_hex(message, private_key_hex)
            }

            fn verify(
                &self,
                message: &[u8],
                signature_hex: &str,
                public_key_hex: &str,
            ) -> Result<()> {
                Self::verify_hex(message, signature_hex, public_key_hex)
            }
        }
    };
}

ecdsa_signer!(
    /// ECDSA P-256（SHA-256）签名器。
    EcdsaP256Signer,
    "ECDSA P-256",
    "ecdsa-p256-sha256",
    p256
);

ecdsa_signer!(
    /// ECDSA P-384（SHA-384）签名器。
    EcdsaP384Signer,
    "ECDSA P-384",
    "ecdsa-p384-sha384",
    p384
);

ecdsa_signer!(
    /// ECDSA secp256k1（SHA-256）签名器。
    EcdsaSecp256k1Signer,
    "ECDSA secp256k1",
    "ecdsa-secp256k1-sha256",
    k256
);

#[cfg(test)]
mod tests {
    use super::*;

    /// roundtrip + 篡改必败 + 错密钥必败 + 形状检查（签名与私钥等长）。
    fn assert_roundtrip(signer: &dyn Signer, pair: &KeyPairHex, other: &KeyPairHex) {
        assert_eq!(
            pair.private_key_hex.len() * 2 + 2,
            pair.public_key_hex.len()
        );
        assert!(pair.public_key_hex.starts_with("04"));

        let signature = signer.sign(b"payload", &pair.private_key_hex).unwrap();
        assert_eq!(signature.len(), pair.private_key_hex.len() * 2);
        signer
            .verify(b"payload", &signature, &pair.public_key_hex)
            .unwrap();

        // 消息被改 → 必败。
        let error = signer
            .verify(b"payloaD", &signature, &pair.public_key_hex)
            .unwrap_err();
        assert!(matches!(error, Error::VerificationFailed { .. }));

        // 换成另一把密钥的公钥 → 必败。
        let error = signer
            .verify(b"payload", &signature, &other.public_key_hex)
            .unwrap_err();
        assert!(matches!(error, Error::VerificationFailed { .. }));
    }

    #[test]
    fn p256_roundtrip_and_hex_shapes() {
        let pair = EcdsaP256Signer::generate_key_pair_hex().unwrap();
        let other = EcdsaP256Signer::generate_key_pair_hex().unwrap();
        assert_eq!(pair.private_key_hex.len(), 64);
        assert_eq!(pair.public_key_hex.len(), 130);
        assert_roundtrip(&EcdsaP256Signer::new(), &pair, &other);
    }

    #[test]
    fn p384_roundtrip_and_hex_shapes() {
        let pair = EcdsaP384Signer::generate_key_pair_hex().unwrap();
        let other = EcdsaP384Signer::generate_key_pair_hex().unwrap();
        assert_eq!(pair.private_key_hex.len(), 96);
        assert_eq!(pair.public_key_hex.len(), 194);
        assert_roundtrip(&EcdsaP384Signer::new(), &pair, &other);
    }

    #[test]
    fn secp256k1_roundtrip_and_hex_shapes() {
        let pair = EcdsaSecp256k1Signer::generate_key_pair_hex().unwrap();
        let other = EcdsaSecp256k1Signer::generate_key_pair_hex().unwrap();
        assert_eq!(pair.private_key_hex.len(), 64);
        assert_eq!(pair.public_key_hex.len(), 130);
        assert_roundtrip(&EcdsaSecp256k1Signer::new(), &pair, &other);
    }

    /// KAT：RFC 6979 附录 A.2.5（ECDSA 256 位 / SHA-256）。
    /// 向量出处 RFC 6979 §A.2.5；x / Ux / Uy / (r, s) 均为 RFC 原文定值。
    #[test]
    fn rfc6979_p256_sample_matches_vector() {
        const X: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
        const PUBLIC_KEY: &str = concat!(
            "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
            "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        );
        // RFC 原文 s = f7cb…cda8（高于 n/2）；本库输出做 low-s 归一化，
        // 期望值 = r ‖ (n − s)，n−s 由独立 Python 复算核对。
        const EXPECTED: &str = concat!(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
            "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9",
        );
        // RFC 向量本体（未归一化）也必须可验签——两种形态都合法。
        const VECTOR: &str = concat!(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
        );

        let signer = EcdsaP256Signer::new();
        let signature = signer.sign(b"sample", X).unwrap();
        assert_eq!(signature, EXPECTED);

        // 向量中的公钥（`04‖Ux‖Uy`）必须能验出签名（归一化前后两种形态都合法）；换消息必败。
        signer.verify(b"sample", &signature, PUBLIC_KEY).unwrap();
        signer.verify(b"sample", VECTOR, PUBLIC_KEY).unwrap();
        assert!(signer.verify(b"sampl3", &signature, PUBLIC_KEY).is_err());
    }

    /// KAT：RFC 6979 附录 A.2.5 的另一条定值向量（消息 "test"，SHA-256）。
    #[test]
    fn rfc6979_p256_test_message_matches_vector() {
        const X: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
        const EXPECTED: &str = concat!(
            "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
            "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
        );

        let signature = EcdsaP256Signer::new().sign(b"test", X).unwrap();
        assert_eq!(signature, EXPECTED);
    }

    /// KAT：RFC 6979 附录 A.2.6（ECDSA 384 位 / SHA-384），消息 "sample"。
    #[test]
    fn rfc6979_p384_sample_matches_vector() {
        const X: &str = concat!(
            "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8",
            "96d5724e4c70a825f872c9ea60d2edf5",
        );
        // RFC 原文 s 高于 n/2；本库做 low-s 归一化，期望值 = r ‖ (n − s)，
        // n−s 由独立 Python 复算核对。
        const EXPECTED: &str = concat!(
            "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c",
            "81a648152e44acf96e36dd1e80fabe46",
            "6610b514ea0e87315e01bf24d9fcec70ecf18bf5e69dbad9a727ea302393848f",
            "b4f04c6cd0423fdc7169525094629eab",
        );

        let signature = EcdsaP384Signer::new().sign(b"sample", X).unwrap();
        assert_eq!(signature, EXPECTED);
    }

    /// KAT：secp256k1（RFC 6979 §3.2 确定性 k，私钥 x = 1，消息 "Satoshi Nakamoto"）。
    /// 向量出处：独立 Python（RFC 6979 §3.2 HMAC-DRBG + secp256k1 点乘）复算，
    /// 与社区广泛使用的 Trezor 测试向量（同为 low-s 形态）逐字节一致。
    /// RFC 6979 / RFC 5903 均未收录 secp256k1 的附录定值，这是该曲线唯一的外部锚点。
    #[test]
    fn rfc6979_secp256k1_satoshi_vector_matches() {
        const X: &str = "0000000000000000000000000000000000000000000000000000000000000001";
        const EXPECTED: &str = concat!(
            "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8",
            "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5",
        );
        // 私钥 1 的公钥即基点 G。
        const PUBLIC_KEY: &str = concat!(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        );

        let signer = EcdsaSecp256k1Signer::new();
        let signature = signer.sign(b"Satoshi Nakamoto", X).unwrap();
        assert_eq!(signature, EXPECTED);

        signer
            .verify(b"Satoshi Nakamoto", &signature, PUBLIC_KEY)
            .unwrap();
        assert!(
            signer
                .verify(b"Satoshi Nakamot0", &signature, PUBLIC_KEY)
                .is_err()
        );
    }

    /// RFC 6979 是确定性签名：同私钥 + 同消息，签名逐字节一致。
    #[test]
    fn signatures_are_deterministic() {
        let pair = EcdsaP256Signer::generate_key_pair_hex().unwrap();
        let signer = EcdsaP256Signer::new();
        assert_eq!(
            signer.sign(b"same", &pair.private_key_hex).unwrap(),
            signer.sign(b"same", &pair.private_key_hex).unwrap(),
        );
    }

    #[test]
    fn malformed_keys_are_rejected() {
        let pair = EcdsaP256Signer::generate_key_pair_hex().unwrap();
        let signer = EcdsaP256Signer::new();

        // 非十六进制 / 长度不对的私钥。
        assert_eq!(
            signer.sign(b"x", "zz").unwrap_err(),
            Error::InvalidKey {
                label: "ECDSA P-256"
            }
        );
        assert_eq!(
            signer.sign(b"x", "abcd").unwrap_err(),
            Error::InvalidKey {
                label: "ECDSA P-256"
            }
        );
        // 公钥不是曲线上的点 / 签名长度不对：一律 VerificationFailed。
        let signature = signer.sign(b"x", &pair.private_key_hex).unwrap();
        assert_eq!(
            signer.verify(b"x", &signature, "04deadbeef").unwrap_err(),
            Error::VerificationFailed {
                label: "ECDSA P-256"
            }
        );
        assert_eq!(
            signer.verify(b"x", "00", &pair.public_key_hex).unwrap_err(),
            Error::VerificationFailed {
                label: "ECDSA P-256"
            }
        );
    }

    #[test]
    fn identifiers_are_stable() {
        assert_eq!(EcdsaP256Signer::new().identifier(), "ecdsa-p256-sha256");
        assert_eq!(EcdsaP384Signer::new().identifier(), "ecdsa-p384-sha384");
        assert_eq!(
            EcdsaSecp256k1Signer::new().identifier(),
            "ecdsa-secp256k1-sha256"
        );
    }
}
