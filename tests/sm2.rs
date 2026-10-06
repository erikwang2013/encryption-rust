// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! SM2 通过非对称门面的端到端测试；对应 PHP 版的 `GuomiSm2Test`、
//! `AsymmetricCipherRegistryTest`、`AsymmetricCryptoManagerTest` 意图。

use encryption::contract::AsymmetricCipher;
use encryption::error::Error;
use encryption::guomi::{Sm2AsymmetricCipher, Sm2Service};
use encryption::manager::AsymmetricCryptoManager;
use encryption::registry::Registry;

#[test]
fn asymmetric_manager_roundtrips_sm2() {
    let mut registry: Registry<Box<dyn AsymmetricCipher>> = Registry::new("asymmetric cipher");
    registry.register(Box::new(Sm2AsymmetricCipher::new()));
    let manager = AsymmetricCryptoManager::new(registry, "sm2").unwrap();

    let pair = Sm2Service::generate_key_pair_hex().unwrap();
    let ciphertext = manager
        .encrypt("非对称载荷".as_bytes(), &pair.public_key_hex)
        .unwrap();
    let plaintext = manager.decrypt(&ciphertext, &pair.private_key_hex).unwrap();

    assert_eq!(plaintext, "非对称载荷".as_bytes());
    assert_eq!(manager.default_identifier(), "sm2");
}

#[test]
fn every_encryption_uses_a_fresh_ephemeral_key() {
    let pair = Sm2Service::generate_key_pair_hex().unwrap();
    let first = Sm2Service::encrypt(b"same", &pair.public_key_hex).unwrap();
    let second = Sm2Service::encrypt(b"same", &pair.public_key_hex).unwrap();
    assert_ne!(first, second);
    assert_eq!(
        Sm2Service::decrypt(&first, &pair.private_key_hex).unwrap(),
        b"same"
    );
    assert_eq!(
        Sm2Service::decrypt(&second, &pair.private_key_hex).unwrap(),
        b"same"
    );
}

#[test]
fn unknown_identifier_reports_structured_error() {
    let mut registry: Registry<Box<dyn AsymmetricCipher>> = Registry::new("asymmetric cipher");
    registry.register(Box::new(Sm2AsymmetricCipher::new()));
    let manager = AsymmetricCryptoManager::new(registry, "sm2").unwrap();

    assert_eq!(
        manager.encrypt_with("rsa", b"x", "04").unwrap_err(),
        Error::UnknownIdentifier {
            kind: "asymmetric cipher",
            identifier: "rsa".to_string()
        }
    );
}
