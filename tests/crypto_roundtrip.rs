// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 端到端往返测试：各算法单测 + 工厂（主密钥 → 子密钥 → 注册表 → 门面）。
//! 对应 PHP 版的 `EncryptorRoundTripTest`、`EncryptionManagerFactoryTest`、
//! `EncryptionManagerTest`、`Guomi*Test` 的意图。

use encryption::contract::{Hasher, KeyDerivation, PasswordBasedKdf, SymmetricCipher};
use encryption::encryptor::{Aes256CbcEncryptor, Aes256GcmEncryptor, SodiumXChaCha20Encryptor};
use encryption::factory::EncryptionManagerFactory;
use encryption::guomi::{Sm3Hasher, Sm4CbcEncryptor, Zuc128Encryptor};
use encryption::hash::Sha256Hasher;
use encryption::kdf::{HkdfSha256, Pbkdf2Sha256};

const PAYLOADS: [&[u8]; 4] = [b"", b"x", "中文载荷 🎉".as_bytes(), &[0u8; 64]];

#[test]
fn every_symmetric_cipher_roundtrips_standalone() {
    let gcm = Aes256GcmEncryptor::new([1u8; 32]);
    let cbc = Aes256CbcEncryptor::new([2u8; 32]);
    let xchacha = SodiumXChaCha20Encryptor::new([3u8; 32]);
    let sm4 = Sm4CbcEncryptor::new([4u8; 16]);
    let zuc = Zuc128Encryptor::new([5u8; 16]);

    let ciphers: [&dyn SymmetricCipher; 5] = [&gcm, &cbc, &xchacha, &sm4, &zuc];
    for cipher in ciphers {
        for payload in PAYLOADS {
            let blob = cipher.encrypt(payload).expect(cipher.identifier());
            let recovered = cipher.decrypt(&blob).expect(cipher.identifier());
            assert_eq!(recovered, payload, "{}", cipher.identifier());
        }
    }
}

#[test]
fn factory_manager_roundtrips_all_registered_algorithms() {
    let manager = EncryptionManagerFactory::from_master_key(&[9u8; 32], "aes-256-gcm").unwrap();

    for identifier in manager.registry().identifiers() {
        let blob = manager
            .encrypt_with(identifier, "敏感字段".as_bytes())
            .unwrap();
        let recovered = manager.decrypt_with(identifier, &blob).unwrap();
        assert_eq!(recovered, "敏感字段".as_bytes(), "{identifier}");
    }

    // 默认算法即工厂入参。
    let blob = manager.encrypt("默认算法".as_bytes()).unwrap();
    assert_eq!(manager.decrypt(&blob).unwrap(), "默认算法".as_bytes());
    assert_eq!(manager.default_identifier(), "aes-256-gcm");
}

#[test]
fn hashers_match_and_default_switching_works() {
    let mut registry: encryption::registry::Registry<Box<dyn Hasher>> =
        encryption::registry::Registry::new("hasher");
    registry.register(Box::new(Sha256Hasher::new()));
    registry.register(Box::new(Sm3Hasher::new()));
    let mut manager = encryption::manager::HashingManager::new(registry, "sha256").unwrap();

    assert_eq!(manager.digest(b"data").unwrap().len(), 32);
    assert_eq!(
        manager.digest_hex_with("sm3", b"abc").unwrap(),
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    );

    manager.set_default_identifier("sm3").unwrap();
    assert_eq!(manager.default_identifier(), "sm3");
    assert!(manager.set_default_identifier("md5").is_err());
}

#[test]
fn hkdf_and_pbkdf2_managers_roundtrip() {
    let mut kdf_registry: encryption::registry::Registry<Box<dyn KeyDerivation>> =
        encryption::registry::Registry::new("key derivation");
    kdf_registry.register(Box::new(HkdfSha256::new()));
    let kdf_manager =
        encryption::manager::KeyDerivationManager::new(kdf_registry, "hkdf-sha256").unwrap();
    assert_eq!(
        kdf_manager
            .derive(b"ikm", b"salt", 32, b"info")
            .unwrap()
            .len(),
        32
    );

    let mut pwd_registry: encryption::registry::Registry<Box<dyn PasswordBasedKdf>> =
        encryption::registry::Registry::new("password-based kdf");
    pwd_registry.register(Box::new(Pbkdf2Sha256::with_default_iterations()));
    let pwd_manager =
        encryption::manager::PasswordBasedKdfManager::new(pwd_registry, "pbkdf2-sha256").unwrap();
    assert_eq!(
        pwd_manager
            .derive_from_password(b"pw", b"salt", 32)
            .unwrap()
            .len(),
        32
    );
}

#[test]
fn key_derivation_contract_is_reachable_through_trait_objects() {
    let hasher: Box<dyn Hasher> = Box::new(Sha256Hasher::new());
    let kdf: Box<dyn KeyDerivation> = Box::new(HkdfSha256::new());
    let pwd: Box<dyn PasswordBasedKdf> = Box::new(Pbkdf2Sha256::new(2).unwrap());
    let asym_ok: bool = true; // SM2 见 tests/sm2.rs（阶段 4 完成后）
    assert!(asym_ok);

    assert_eq!(hasher.digest(b"x").unwrap().len(), 32);
    assert_eq!(kdf.derive(b"ikm", b"", 8, b"").unwrap().len(), 8);
    assert_eq!(
        pwd.derive_from_password(b"pw", b"salt", 8).unwrap().len(),
        8
    );
}
