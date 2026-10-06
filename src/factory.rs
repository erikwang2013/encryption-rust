// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 主密钥工厂：从 32 字节主密钥派生各算法独立子密钥，避免同一密钥跨算法复用
//! （对应 PHP 版 `EncryptionManagerFactory`）。
//!
//! 派生方案只有**修正后的参数顺序**一种：`HMAC-SHA256(key = 主密钥, msg = 用途标签)`。
//! 原版历史遗留的 v1 反序方案（标签作 key）不复刻——本 crate 采用 Rust 独立格式。

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::contract::SymmetricCipher;
use crate::encryptor::{Aes256CbcEncryptor, Aes256GcmEncryptor, SodiumXChaCha20Encryptor};
use crate::error::{Error, Result};
use crate::guomi::{Sm4CbcEncryptor, Zuc128Encryptor};
use crate::manager::EncryptionManager;
use crate::registry::Registry;

// 用途标签（与原版一致；标签不承载秘密，秘密始终是主密钥）。
const LABEL_AES_GCM: &[u8] = b"dgn:derive:aes-gcm";
const LABEL_AES_CBC: &[u8] = b"dgn:derive:aes-cbc";
const LABEL_SM4: &[u8] = b"dgn:derive:sm4";
const LABEL_ZUC: &[u8] = b"dgn:derive:zuc";
const LABEL_SODIUM: &[u8] = b"dgn:derive:sodium";

/// 从一把主密钥构建 [`EncryptionManager`]。
///
/// 一次性注册 `aes-256-gcm`、`aes-256-cbc-hmac`、`sodium-xchacha20`
/// （以及国密的 `sm4-cbc`、`zuc-128`）；`default_identifier` 必须已注册。
pub struct EncryptionManagerFactory;

impl EncryptionManagerFactory {
    pub fn from_master_key(
        master_key: &[u8],
        default_identifier: &str,
    ) -> Result<EncryptionManager> {
        let master_key: [u8; 32] = master_key.try_into().map_err(|_| Error::InvalidMasterKey {
            got: master_key.len(),
        })?;

        let mut registry: Registry<Box<dyn SymmetricCipher>> = Registry::new("symmetric cipher");
        registry.register(Box::new(Aes256GcmEncryptor::new(derive_subkey(
            &master_key,
            LABEL_AES_GCM,
        ))));
        registry.register(Box::new(Aes256CbcEncryptor::new(derive_subkey(
            &master_key,
            LABEL_AES_CBC,
        ))));
        registry.register(Box::new(SodiumXChaCha20Encryptor::new(derive_subkey(
            &master_key,
            LABEL_SODIUM,
        ))));
        registry.register(Box::new(Sm4CbcEncryptor::new(derive_subkey_16(
            &master_key,
            LABEL_SM4,
        ))));
        registry.register(Box::new(Zuc128Encryptor::new(derive_subkey_16(
            &master_key,
            LABEL_ZUC,
        ))));

        EncryptionManager::new(registry, default_identifier)
    }
}

/// 子密钥 = `HMAC-SHA256(key = 主密钥, msg = 用途标签)`。
fn derive_subkey(master_key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(master_key).expect("HMAC accepts any key size");
    mac.update(label);
    mac.finalize().into_bytes().into()
}

/// SM4 / ZUC 用 16 字节子密钥：取派生结果前 16 字节（与原版一致）。
fn derive_subkey_16(master_key: &[u8; 32], label: &[u8]) -> [u8; 16] {
    let full = derive_subkey(master_key, label);
    full[..16].try_into().expect("slice is exactly 16 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_validates_master_key_and_default() {
        assert_eq!(
            EncryptionManagerFactory::from_master_key(&[0u8; 31], "aes-256-gcm").unwrap_err(),
            Error::InvalidMasterKey { got: 31 }
        );
        assert_eq!(
            EncryptionManagerFactory::from_master_key(&[0u8; 32], "aes-512").unwrap_err(),
            Error::UnknownIdentifier {
                kind: "symmetric cipher",
                identifier: "aes-512".to_string()
            }
        );
    }

    #[test]
    fn factory_registers_all_five_and_they_roundtrip() {
        let manager =
            EncryptionManagerFactory::from_master_key(&[42u8; 32], "aes-256-gcm").unwrap();
        let expected = [
            "aes-256-cbc-hmac",
            "aes-256-gcm",
            "sm4-cbc",
            "sodium-xchacha20",
            "zuc-128",
        ];
        assert_eq!(manager.registry().identifiers(), expected);

        for identifier in expected {
            let blob = manager.encrypt_with(identifier, b"cross-check").unwrap();
            assert_eq!(
                manager.decrypt_with(identifier, &blob).unwrap(),
                b"cross-check"
            );
        }
    }

    #[test]
    fn subkeys_are_independent_per_algorithm() {
        let manager =
            EncryptionManagerFactory::from_master_key(&[42u8; 32], "aes-256-gcm").unwrap();
        let blob = manager.encrypt_with("aes-256-gcm", b"secret").unwrap();
        // 同一把主密钥，但换了算法：密文结构不同 / 密钥不同，解不开。
        assert!(manager.decrypt_with("aes-256-cbc-hmac", &blob).is_err());
        assert!(manager.decrypt_with("sm4-cbc", &blob).is_err());
    }
}
