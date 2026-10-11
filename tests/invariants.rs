// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 跨算法不变量：互不通用、篡改必败、IV/nonce 每次都新、插件可扩展。
//! 对应 PHP 版的 `CryptoPrimitivesTest`、`EncryptThenMacBlobTest` 的意图。
//!
//! 三个不变量都遍历注册表，所以用 [`EncryptionManagerFactory::from_master_key_all`]
//! 建 Manager —— 它注册全部十四个对称算法（五个默认 + 九个扩展）。此前用
//! `from_master_key`（五个）时，另外九个扩展算法**不在**这些不变量的覆盖面内，
//! 而它们恰恰是手工装配最容易配错密钥的那批。

use encryption::contract::{Identified, SymmetricCipher};
use encryption::error::{Error, Result};
use encryption::factory::EncryptionManagerFactory;
use encryption::guomi::Zuc128Encryptor;
use encryption::registry::Registry;

/// 全部十四个对称算法标识（工厂全量注册的结果）。
const ALL_IDENTIFIERS: usize = 14;

#[test]
fn same_plaintext_yields_different_ciphertext_every_time() {
    let manager = EncryptionManagerFactory::from_master_key_all(&[7u8; 32], "aes-256-gcm").unwrap();
    assert_eq!(manager.registry().identifiers().len(), ALL_IDENTIFIERS);

    for identifier in manager.registry().identifiers() {
        let first = manager.encrypt_with(identifier, b"same input").unwrap();
        let second = manager.encrypt_with(identifier, b"same input").unwrap();
        assert_ne!(first, second, "{identifier} 必用新的 IV / nonce");
    }
}

#[test]
fn ciphertext_from_one_algorithm_never_decrypts_with_another() {
    let manager = EncryptionManagerFactory::from_master_key_all(&[7u8; 32], "aes-256-gcm").unwrap();
    let identifiers = manager.registry().identifiers().to_vec();
    assert_eq!(identifiers.len(), ALL_IDENTIFIERS);

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
    let manager = EncryptionManagerFactory::from_master_key_all(&[7u8; 32], "aes-256-gcm").unwrap();

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

/// `from_master_key` 的默认集**冻结**在五个算法：存量数据的子密钥由这套标签
/// 派生，多注册或少注册都会改变既有部署的行为。
#[test]
fn from_master_key_still_registers_exactly_the_five_frozen_defaults() {
    let manager = EncryptionManagerFactory::from_master_key(&[7u8; 32], "aes-256-gcm").unwrap();
    assert_eq!(
        manager.registry().identifiers(),
        [
            "aes-256-cbc-hmac",
            "aes-256-gcm",
            "sm4-cbc",
            "sodium-xchacha20",
            "zuc-128"
        ]
    );
}

/// 全量工厂 = 默认五个 + 扩展九个，且**默认五个的注册结果逐字节不变**
/// （同一主密钥下，两种构造方式对同一个默认算法必须给出同一把子密钥）。
///
/// 注意不能断言「默认五个是排序后的前五个」：注册表是 `BTreeMap`，按字典序
/// 排列，`aes-256-gcm-siv` / `aria-…` / `camellia-…` 都排在 `sm4-cbc` 前面。
/// 要断言的是**包含关系**，而不是位置关系。
#[test]
fn from_master_key_all_adds_the_extensions_without_disturbing_the_defaults() {
    let master = [7u8; 32];
    let five = EncryptionManagerFactory::from_master_key(&master, "aes-256-gcm").unwrap();
    let all = EncryptionManagerFactory::from_master_key_all(&master, "aes-256-gcm").unwrap();

    let five_ids = five.registry().identifiers();
    let all_ids = all.registry().identifiers();

    assert_eq!(all_ids.len(), ALL_IDENTIFIERS);
    assert_eq!(five_ids.len(), ALL_IDENTIFIERS - 9);

    // 默认五个全部在场。注册表是 BTreeMap，键天然唯一，重复不可能出现。
    for identifier in &five_ids {
        assert!(all_ids.contains(identifier), "{identifier} 缺席全量工厂");
    }

    // 默认算法的子密钥未被扰动：五算法工厂产出的密文，全量工厂必须能解开
    // （AES-256-GCM 是认证加密，子密钥差一位就解密失败）。
    for identifier in &five_ids {
        let blob = five.encrypt_with(identifier, b"cross-factory").unwrap();
        assert_eq!(
            all.decrypt_with(identifier, &blob).unwrap(),
            b"cross-factory",
            "{identifier} 的子密钥在两种构造方式下不一致"
        );
    }
}

/// 扩展算法各自拿到**独立**子密钥：同一主密钥下，任一扩展的密文不得被其他
/// 扩展（或默认算法）解开。这正是「扩展算法此前只能手工装配、极易复用别人的
/// 子密钥」所违反的那条不变量。
#[test]
fn every_derived_subkey_is_independent_across_all_fourteen() {
    let manager = EncryptionManagerFactory::from_master_key_all(&[7u8; 32], "aes-256-gcm").unwrap();
    let identifiers = manager.registry().identifiers().to_vec();

    for source in &identifiers {
        let blob = manager.encrypt_with(source, b"subkey-separation").unwrap();
        for target in &identifiers {
            if target == source {
                continue;
            }
            assert!(
                manager.decrypt_with(target, &blob).is_err(),
                "{source} 的密文被 {target} 解开了——两者子密钥相同"
            );
        }
    }
}

/// 扩展算法的子密钥随**主密钥**变化：换一把主密钥必须解不开。
#[test]
fn extension_ciphertexts_do_not_survive_a_master_key_change() {
    let original =
        EncryptionManagerFactory::from_master_key_all(&[7u8; 32], "aes-256-gcm").unwrap();
    let rotated = EncryptionManagerFactory::from_master_key_all(&[8u8; 32], "aes-256-gcm").unwrap();

    for identifier in original.registry().identifiers() {
        let blob = original.encrypt_with(identifier, b"rotate me").unwrap();
        assert!(
            rotated.decrypt_with(identifier, &blob).is_err(),
            "{identifier} 换主密钥后仍能解开——子密钥没跟着主密钥走"
        );
    }
}
