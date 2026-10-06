// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 跨算法不变量：互不通用、篡改必败、IV/nonce 每次都新、插件可扩展。
//! 对应 PHP 版的 `CryptoPrimitivesTest`、`EncryptThenMacBlobTest` 的意图。

use encryption::contract::{Identified, SymmetricCipher};
use encryption::error::{Error, Result};
use encryption::factory::EncryptionManagerFactory;
use encryption::guomi::Zuc128Encryptor;
use encryption::registry::Registry;

#[test]
fn same_plaintext_yields_different_ciphertext_every_time() {
    let manager = EncryptionManagerFactory::from_master_key(&[7u8; 32], "aes-256-gcm").unwrap();

    for identifier in manager.registry().identifiers() {
        let first = manager.encrypt_with(identifier, b"same input").unwrap();
        let second = manager.encrypt_with(identifier, b"same input").unwrap();
        assert_ne!(first, second, "{identifier} 必用新的 IV / nonce");
    }
}

#[test]
fn ciphertext_from_one_algorithm_never_decrypts_with_another() {
    let manager = EncryptionManagerFactory::from_master_key(&[7u8; 32], "aes-256-gcm").unwrap();
    let identifiers = manager.registry().identifiers().to_vec();

    for source in &identifiers {
        let blob = manager.encrypt_with(source, b"secret").unwrap();
        for target in &identifiers {
            if target == source {
                continue;
            }
            assert!(
                manager.decrypt_with(target, &blob).is_err(),
                "{source} 的密文不该被 {target} 解开"
            );
        }
    }
}

#[test]
fn tampered_blobs_are_rejected() {
    let manager = EncryptionManagerFactory::from_master_key(&[7u8; 32], "aes-256-gcm").unwrap();

    for identifier in manager.registry().identifiers() {
        let blob = manager.encrypt_with(identifier, b"payload").unwrap();

        // 改前缀 → 前缀错误（zuc 也带 v1 前缀）。
        let mut broken_prefix = blob.clone();
        broken_prefix[0] = b'v';
        broken_prefix[1] = b'9';
        assert!(
            manager.decrypt_with(identifier, &broken_prefix).is_err(),
            "{identifier}"
        );

        // 截断 → 太短。
        assert!(
            manager.decrypt_with(identifier, &blob[..3]).is_err(),
            "{identifier}"
        );

        // 翻转密文最后一字节 → 认证失败。
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(
            manager.decrypt_with(identifier, &tampered).is_err(),
            "{identifier}"
        );
    }
}

#[test]
fn custom_cipher_plugins_can_be_registered() {
    /// 演示用的玩具加密（XOR 循环密钥）；正式项目请实现契约接入真实算法。
    struct XorDemoCipher {
        key: [u8; 16],
    }

    impl Identified for XorDemoCipher {
        fn identifier(&self) -> &str {
            "xor-demo"
        }
    }

    impl SymmetricCipher for XorDemoCipher {
        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            Ok(plaintext
                .iter()
                .zip(self.key.iter().cycle())
                .map(|(byte, key)| byte ^ key)
                .collect())
        }

        fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            self.encrypt(ciphertext)
        }
    }

    let manager = EncryptionManagerFactory::from_master_key(&[7u8; 32], "aes-256-gcm").unwrap();
    let mut manager = manager;
    manager
        .registry_mut()
        .register(Box::new(XorDemoCipher { key: [3u8; 16] }));

    let blob = manager.encrypt_with("xor-demo", b"plugin data").unwrap();
    assert_eq!(
        manager.decrypt_with("xor-demo", &blob).unwrap(),
        b"plugin data"
    );
}

#[test]
fn unknown_identifiers_report_structured_errors() {
    let manager = EncryptionManagerFactory::from_master_key(&[7u8; 32], "aes-256-gcm").unwrap();
    assert_eq!(
        manager.encrypt_with("no-such-cipher", b"x").unwrap_err(),
        Error::UnknownIdentifier {
            kind: "symmetric cipher",
            identifier: "no-such-cipher".to_string()
        }
    );
}

#[test]
fn zuc_handles_non_word_aligned_lengths() {
    // ZUC 密钥流按 4 字节字生成：长度不整除 4 时取前缀字节，尾巴不能丢。
    let cipher = Zuc128Encryptor::new([1u8; 16]);
    for length in 0..16usize {
        let payload = vec![0xabu8; length];
        let blob = cipher.encrypt(&payload).unwrap();
        assert_eq!(cipher.decrypt(&blob).unwrap(), payload, "length={length}");
    }
}

#[test]
fn registry_reports_unknown_identifiers() {
    let registry: Registry<Box<dyn SymmetricCipher>> = Registry::new("symmetric cipher");
    assert!(registry.get("missing").is_err());
    assert!(registry.identifiers().is_empty());
}
