// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 静态 ECDH 密钥协商：P-256 / P-384 / secp256k1。
//!
//! 十六进制约定（与 ECDSA 部分一致）：
//! - 私钥：裸标量定长 hex（P-256 / secp256k1 64 位，P-384 96 位）；
//! - 对方公钥：SEC1 非压缩点 `04‖X‖Y` hex（130 / 194 位），仅接受非压缩形式；
//! - 共享秘密：ECDH 原始 x 坐标定长 hex（64 / 96 位）。
//!
//! 私钥为 0 或超出阶、公钥不在曲线上（含无法编码的无穷远点）一律拒绝为
//! [`Error::InvalidKey`]。定值向量见各测试（RFC 5903 §8.1 / §8.2）。

use rand_core::OsRng;

// sec1 的 `ToEncodedPoint` 通过 p256 再导出引入一次，三条曲线共用同一份 trait。
use p256::elliptic_curve::sec1::ToEncodedPoint;

use crate::asymmetric::KeyPairHex;
use crate::contract::{Identified, KeyAgreement};
use crate::error::{Error, Result};
use crate::internal::{hex_decode, hex_encode};

/// 为 `$curve`（p256 / p384 / k256）生成一个实现 [`KeyAgreement`] 的协商器。
macro_rules! ecdh_agreement {
    ($(#[$doc:meta])* $name:ident, $label:literal, $identifier:literal, $curve:ident) => {
        $(#[$doc])*
        #[derive(Debug, Default, Clone, Copy)]
        pub struct $name;

        impl $name {
            pub const IDENTIFIER: &'static str = $identifier;

            pub fn new() -> Self {
                Self
            }

            /// 以己方私钥与对方公钥导出共享秘密（ECDH 原始 x 坐标 hex）。
            fn agree_hex(private_key_hex: &str, peer_public_key_hex: &str) -> Result<String> {
                let private_bytes = hex_decode(private_key_hex)
                    .map_err(|_| Error::InvalidKey { label: $label })?;
                let secret_key = $curve::SecretKey::from_slice(&private_bytes)
                    .map_err(|_| Error::InvalidKey { label: $label })?;
                let peer_bytes = hex_decode(peer_public_key_hex)
                    .map_err(|_| Error::InvalidKey { label: $label })?;
                let peer_key = $curve::PublicKey::from_sec1_bytes(&peer_bytes)
                    .map_err(|_| Error::InvalidKey { label: $label })?;

                let shared_secret =
                    $curve::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), peer_key.as_affine());
                Ok(hex_encode(shared_secret.raw_secret_bytes()))
            }

            /// 生成密钥对：私钥 = 标量 hex，公钥 = SEC1 非压缩点 `04‖X‖Y` hex；
            /// 随机源为系统 CSPRNG。
            pub fn generate_key_pair_hex() -> Result<KeyPairHex> {
                let secret_key = $curve::SecretKey::random(&mut OsRng);
                let public_key = secret_key.public_key().to_encoded_point(false);
                Ok(KeyPairHex {
                    private_key_hex: hex_encode(secret_key.to_bytes().as_slice()),
                    public_key_hex: hex_encode(public_key.as_bytes()),
                })
            }
        }

        impl Identified for $name {
            fn identifier(&self) -> &str {
                Self::IDENTIFIER
            }
        }

        impl KeyAgreement for $name {
            fn agree(&self, private_key_hex: &str, peer_public_key_hex: &str) -> Result<String> {
                Self::agree_hex(private_key_hex, peer_public_key_hex)
            }
        }
    };
}

ecdh_agreement!(
    /// ECDH P-256。
    EcdhP256,
    "ECDH P-256",
    "ecdh-p256",
    p256
);

ecdh_agreement!(
    /// ECDH P-384。
    EcdhP384,
    "ECDH P-384",
    "ecdh-p384",
    p384
);

ecdh_agreement!(
    /// ECDH secp256k1。
    EcdhSecp256k1,
    "ECDH secp256k1",
    "ecdh-secp256k1",
    k256
);

#[cfg(test)]
mod tests {
    use super::*;

    /// roundtrip + 形状检查 + 双向一致 + 错私钥不同 + 非法点拒绝。
    fn assert_agreement(agreement: &dyn KeyAgreement) {
        let alice = keypair_for(agreement).unwrap();
        let bob = keypair_for(agreement).unwrap();
        let scalar_len = alice.private_key_hex.len();
        assert_eq!(alice.public_key_hex.len(), scalar_len * 2 + 2);
        assert!(alice.public_key_hex.starts_with("04"));

        let left = agreement
            .agree(&alice.private_key_hex, &bob.public_key_hex)
            .unwrap();
        let right = agreement
            .agree(&bob.private_key_hex, &alice.public_key_hex)
            .unwrap();
        assert_eq!(left, right);
        // 共享秘密是原始 x 坐标：与标量同长（32 / 48 字节）。
        assert_eq!(left.len(), scalar_len);

        let mallory = keypair_for(agreement).unwrap();
        assert_ne!(
            agreement
                .agree(&mallory.private_key_hex, &bob.public_key_hex)
                .unwrap(),
            left
        );

        // 非曲线上的点（全零坐标）与坏长度公钥都拒绝。
        let zeros = format!("04{}", "00".repeat(scalar_len));
        assert!(matches!(
            agreement.agree(&alice.private_key_hex, &zeros).unwrap_err(),
            Error::InvalidKey { .. }
        ));
        assert!(matches!(
            agreement
                .agree(&alice.private_key_hex, "04deadbeef")
                .unwrap_err(),
            Error::InvalidKey { .. }
        ));
        // 私钥为 0 也拒绝（不属于 [1, n-1]）。
        assert!(matches!(
            agreement
                .agree(&"00".repeat(scalar_len), &bob.public_key_hex)
                .unwrap_err(),
            Error::InvalidKey { .. }
        ));
    }

    /// 同一实现另生一对密钥（协商器本身不绑定密钥，按标识分派）。
    fn keypair_for(agreement: &dyn KeyAgreement) -> Result<KeyPairHex> {
        match agreement.identifier() {
            "ecdh-p256" => EcdhP256::generate_key_pair_hex(),
            "ecdh-p384" => EcdhP384::generate_key_pair_hex(),
            "ecdh-secp256k1" => EcdhSecp256k1::generate_key_pair_hex(),
            other => panic!("unexpected identifier {other}"),
        }
    }

    #[test]
    fn p256_roundtrip_and_hex_shapes() {
        assert_agreement(&EcdhP256::new());
    }

    #[test]
    fn p384_roundtrip_and_hex_shapes() {
        assert_agreement(&EcdhP384::new());
    }

    #[test]
    fn secp256k1_roundtrip_and_hex_shapes() {
        assert_agreement(&EcdhSecp256k1::new());
    }

    /// KAT：RFC 5903 §8.1（256 位随机 ECP 组 / NIST P-256）。
    /// i / r 为双方私钥，g^r / g^i 为对端公钥，共享秘密 = girx。
    #[test]
    fn rfc5903_8_1_p256_shared_secret_matches_vector() {
        const INITIATOR_PRIVATE: &str =
            "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433";
        const INITIATOR_PUBLIC: &str = concat!(
            "04dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180",
            "5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3",
        );
        const RESPONDER_PRIVATE: &str =
            "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53";
        const RESPONDER_PUBLIC: &str = concat!(
            "04d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63",
            "56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab",
        );
        const SHARED: &str = "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de";

        let agreement = EcdhP256::new();
        assert_eq!(
            agreement
                .agree(INITIATOR_PRIVATE, RESPONDER_PUBLIC)
                .unwrap(),
            SHARED
        );
        assert_eq!(
            agreement
                .agree(RESPONDER_PRIVATE, INITIATOR_PUBLIC)
                .unwrap(),
            SHARED
        );
    }

    /// KAT：RFC 5903 §8.2（384 位随机 ECP 组 / NIST P-384）。
    #[test]
    fn rfc5903_8_2_p384_shared_secret_matches_vector() {
        const INITIATOR_PRIVATE: &str = concat!(
            "099f3c7034d4a2c699884d73a375a67f7624ef7c6b3c0f160647b67414dce655",
            "e35b538041e649ee3faef896783ab194",
        );
        const INITIATOR_PUBLIC: &str = concat!(
            "04667842d7d180ac2cde6f74f37551f55755c7645c20ef73e31634fe72b4c55ee6",
            "de3ac808acb4bdb4c88732aee95f41aa",
            "9482ed1fc0eeb9cafc4984625ccfc23f65032149e0e144ada024181535a0f38e",
            "eb9fcff3c2c947dae69b4c634573a81c",
        );
        const RESPONDER_PRIVATE: &str = concat!(
            "41cb0779b4bdb85d47846725fbec3c9430fab46cc8dc5060855cc9bda0aa2942",
            "e0308312916b8ed2960e4bd55a7448fc",
        );
        const RESPONDER_PUBLIC: &str = concat!(
            "04e558dbef53eecde3d3fccfc1aea08a89a987475d12fd950d83cfa41732bc509d",
            "0d1ac43a0336def96fda41d0774a3571",
            "dcfbec7aacf3196472169e838430367f66eebe3c6e70c416dd5f0c68759dd1ff",
            "f83fa40142209dff5eaad96db9e6386c",
        );
        const SHARED: &str = concat!(
            "11187331c279962d93d604243fd592cb9d0a926f422e47187521287e7156c5c4",
            "d603135569b9e9d09cf5d4a270f59746",
        );

        let agreement = EcdhP384::new();
        assert_eq!(
            agreement
                .agree(INITIATOR_PRIVATE, RESPONDER_PUBLIC)
                .unwrap(),
            SHARED
        );
        assert_eq!(
            agreement
                .agree(RESPONDER_PRIVATE, INITIATOR_PUBLIC)
                .unwrap(),
            SHARED
        );
    }

    #[test]
    fn identifiers_are_stable() {
        assert_eq!(EcdhP256::new().identifier(), "ecdh-p256");
        assert_eq!(EcdhP384::new().identifier(), "ecdh-p384");
        assert_eq!(EcdhSecp256k1::new().identifier(), "ecdh-secp256k1");
    }
}
