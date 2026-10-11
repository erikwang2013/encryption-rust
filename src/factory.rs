// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 主密钥工厂：从 32 字节主密钥派生各算法独立子密钥，避免同一密钥跨算法复用
//! （对应 PHP 版 `EncryptionManagerFactory`）。
//!
//! # 两套派生方案
//!
//! 共同的不变量：**每个算法一把独立子密钥** —— 同主密钥 + 同标签恒得同一子密钥，
//! 不同算法（标签与构造都不同）的子密钥互不相通，因此密钥永不跨算法复用。
//! 两套方案只在构造与冻结状态上不同：
//!
//! 1. **旧标签（五个默认算法，冻结）**：
//!    `子密钥 = HMAC-SHA256(key = 主密钥, msg = 用途标签)`，16 字节密钥取派生
//!    结果前 16 字节。这五个标签自 1.x 起被存量密文绑定 —— 改标签或改参数顺序
//!    都会让存量数据再也解不开，故永不改动。也不复刻原版历史遗留的 v1 反序方案
//!    （标签作 key）—— 本 crate 采用 Rust 独立格式。
//! 2. **扩展标签（九个扩展算法）**：HKDF-Expand（RFC 5869），域与旧标签隔离：
//!    `PRK = HMAC-SHA256(key = 主密钥, msg = "dgn:derive-ext")`（扩展域专用
//!    PRK，标签同样不承载秘密），`子密钥 = HKDF-Expand(PRK, info = 标签,
//!    L = 密钥长度)`。
//!
//! 扩展为何用 HKDF 而非再截一段 HMAC：Threefish-512 需要 64 字节密钥，单次
//! HMAC-SHA256 只给 32 字节；HKDF-Expand 正是「一次提取、按需多块展开」的标准
//! 构造（上限 255 × 32 字节），不必为超出块长的情形自造串联规则。
//!
//! 扩展标签统一命名 `dgn:derive-ext:<注册标识>`，与旧标签（`dgn:derive:` 前缀、
//! 无 `-ext`）以及彼此都不重名。

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::contract::SymmetricCipher;
use crate::encryptor::{
    Aes256CbcEncryptor, Aes256GcmEncryptor, Aes256GcmSivEncryptor, Aria256CbcEncryptor,
    Camellia256CbcEncryptor, ChaCha20Poly1305IetfEncryptor, Kuznyechik256CbcEncryptor,
    Salsa20Encryptor, SodiumXChaCha20Encryptor, Threefish512CbcEncryptor,
};
use crate::error::{Error, Result};
use crate::guomi::{Sm4CbcEncryptor, Sm4GcmEncryptor, Zuc128Encryptor, Zuc256Encryptor};
use crate::manager::EncryptionManager;
use crate::registry::Registry;

// 旧用途标签（与原版一致，**冻结不可改**；标签不承载秘密，秘密始终是主密钥）。
const LABEL_AES_GCM: &[u8] = b"dgn:derive:aes-gcm";
const LABEL_AES_CBC: &[u8] = b"dgn:derive:aes-cbc";
const LABEL_SM4: &[u8] = b"dgn:derive:sm4";
const LABEL_ZUC: &[u8] = b"dgn:derive:zuc";
const LABEL_SODIUM: &[u8] = b"dgn:derive:sodium";

/// 扩展域的 PRK 标签：`PRK = HMAC-SHA256(key = 主密钥, msg = 本常量)`。
const LABEL_PRK_EXT: &[u8] = b"dgn:derive-ext";

// 扩展标签：HKDF-Expand 的 info，命名统一为 `dgn:derive-ext:<注册标识>`。
const LABEL_CHACHA20_POLY1305_IETF: &[u8] = b"dgn:derive-ext:chacha20-poly1305-ietf";
const LABEL_AES_GCM_SIV: &[u8] = b"dgn:derive-ext:aes-256-gcm-siv";
const LABEL_CAMELLIA: &[u8] = b"dgn:derive-ext:camellia-256-cbc-hmac";
const LABEL_ARIA: &[u8] = b"dgn:derive-ext:aria-256-cbc-hmac";
const LABEL_THREEFISH: &[u8] = b"dgn:derive-ext:threefish-512-cbc-hmac";
const LABEL_KUZNYECHIK: &[u8] = b"dgn:derive-ext:kuznyechik-256-cbc-hmac";
const LABEL_SALSA20: &[u8] = b"dgn:derive-ext:salsa20";
const LABEL_SM4_GCM: &[u8] = b"dgn:derive-ext:sm4-gcm";
const LABEL_ZUC256: &[u8] = b"dgn:derive-ext:zuc-256";

/// 从一把主密钥构建 [`EncryptionManager`]。
///
/// [`EncryptionManagerFactory::from_master_key`] 注册五个默认算法
/// （`aes-256-gcm`、`aes-256-cbc-hmac`、`sodium-xchacha20` 与国密的
/// `sm4-cbc`、`zuc-128`），行为与 1.x 完全一致；
/// [`EncryptionManagerFactory::from_master_key_all`] 再补上九个扩展算法（共
/// 十四个）；[`EncryptionManagerFactory::register_extensions`] 只把九个扩展
/// 注册进已有注册表，便于自行组合。各方法的 `default_identifier` 必须已注册。
pub struct EncryptionManagerFactory;

impl EncryptionManagerFactory {
    /// 五个默认算法（与 1.x 行为一致，存量密文照旧解开）。
    pub fn from_master_key(
        master_key: &[u8],
        default_identifier: &str,
    ) -> Result<EncryptionManager> {
        let master_key = master_key_32(master_key)?;

        let mut registry: Registry<Box<dyn SymmetricCipher>> = Registry::new("symmetric cipher");
        register_default_ciphers(&mut registry, &master_key);

        EncryptionManager::new(registry, default_identifier)
    }

    /// 全部十四个算法：五个默认算法 + 九个扩展算法。
    ///
    /// 与 [`Self::from_master_key`] 相比，五个默认算法的子密钥逐字节相同
    /// （同一套冻结标签派生），扩展算法各用 HKDF 派生的独立子密钥。
    ///
    /// ```
    /// use encryption::factory::EncryptionManagerFactory;
    ///
    /// let manager =
    ///     EncryptionManagerFactory::from_master_key_all(&[7u8; 32], "aes-256-gcm")?;
    /// assert_eq!(manager.registry().identifiers().len(), 14);
    ///
    /// let blob = manager.encrypt_with("threefish-512-cbc-hmac", b"data")?;
    /// assert_eq!(
    ///     manager.decrypt_with("threefish-512-cbc-hmac", &blob)?,
    ///     b"data"
    /// );
    /// # Ok::<(), encryption::Error>(())
    /// ```
    pub fn from_master_key_all(
        master_key: &[u8],
        default_identifier: &str,
    ) -> Result<EncryptionManager> {
        let master_key = master_key_32(master_key)?;

        let mut registry: Registry<Box<dyn SymmetricCipher>> = Registry::new("symmetric cipher");
        register_default_ciphers(&mut registry, &master_key);
        register_extension_ciphers(&mut registry, &master_key);

        EncryptionManager::new(registry, default_identifier)
    }

    /// 把九个扩展算法注册进已有注册表，供自行组合（例如在
    /// [`Self::from_master_key`] 的五个默认算法之上按需扩展，或与自研算法共存）。
    /// 主密钥必须为 32 字节，否则 [`Error::InvalidMasterKey`]。
    ///
    /// ```
    /// use encryption::factory::EncryptionManagerFactory;
    ///
    /// let mut manager = EncryptionManagerFactory::from_master_key(&[7u8; 32], "aes-256-gcm")?;
    /// EncryptionManagerFactory::register_extensions(manager.registry_mut(), &[7u8; 32])?;
    /// assert_eq!(manager.registry().identifiers().len(), 14);
    /// # Ok::<(), encryption::Error>(())
    /// ```
    pub fn register_extensions(
        registry: &mut Registry<Box<dyn SymmetricCipher>>,
        master_key: &[u8],
    ) -> Result<()> {
        let master_key = master_key_32(master_key)?;
        register_extension_ciphers(registry, &master_key);
        Ok(())
    }
}

/// 校验主密钥长度并转成定长数组；拷贝包在 [`Zeroizing`] 里，作用域结束
/// （含提前返回）即清零，堆/栈残留里不留主密钥。
fn master_key_32(master_key: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let key: [u8; 32] = master_key.try_into().map_err(|_| Error::InvalidMasterKey {
        got: master_key.len(),
    })?;
    Ok(Zeroizing::new(key))
}

/// 五个默认算法（旧标签派生）。
fn register_default_ciphers(
    registry: &mut Registry<Box<dyn SymmetricCipher>>,
    master_key: &[u8; 32],
) {
    registry.register(Box::new(Aes256GcmEncryptor::new(derive_subkey(
        master_key,
        LABEL_AES_GCM,
    ))));
    registry.register(Box::new(Aes256CbcEncryptor::new(derive_subkey(
        master_key,
        LABEL_AES_CBC,
    ))));
    registry.register(Box::new(SodiumXChaCha20Encryptor::new(derive_subkey(
        master_key,
        LABEL_SODIUM,
    ))));
    registry.register(Box::new(Sm4CbcEncryptor::new(derive_subkey_16(
        master_key, LABEL_SM4,
    ))));
    registry.register(Box::new(Zuc128Encryptor::new(derive_subkey_16(
        master_key, LABEL_ZUC,
    ))));
}

/// 九个扩展算法（HKDF-Expand 派生）。
fn register_extension_ciphers(
    registry: &mut Registry<Box<dyn SymmetricCipher>>,
    master_key: &[u8; 32],
) {
    registry.register(Box::new(ChaCha20Poly1305IetfEncryptor::new(
        derive_subkey_ext(master_key, LABEL_CHACHA20_POLY1305_IETF),
    )));
    registry.register(Box::new(Aes256GcmSivEncryptor::new(derive_subkey_ext(
        master_key,
        LABEL_AES_GCM_SIV,
    ))));
    registry.register(Box::new(Camellia256CbcEncryptor::new(derive_subkey_ext(
        master_key,
        LABEL_CAMELLIA,
    ))));
    registry.register(Box::new(Aria256CbcEncryptor::new(derive_subkey_ext(
        master_key, LABEL_ARIA,
    ))));
    registry.register(Box::new(Threefish512CbcEncryptor::new(derive_subkey_ext(
        master_key,
        LABEL_THREEFISH,
    ))));
    registry.register(Box::new(Kuznyechik256CbcEncryptor::new(derive_subkey_ext(
        master_key,
        LABEL_KUZNYECHIK,
    ))));
    registry.register(Box::new(Salsa20Encryptor::new(derive_subkey_ext(
        master_key,
        LABEL_SALSA20,
    ))));
    registry.register(Box::new(Sm4GcmEncryptor::new(derive_subkey_ext(
        master_key,
        LABEL_SM4_GCM,
    ))));
    registry.register(Box::new(Zuc256Encryptor::new(derive_subkey_ext(
        master_key,
        LABEL_ZUC256,
    ))));
}

/// 旧标签子密钥 = `HMAC-SHA256(key = 主密钥, msg = 用途标签)`。
fn derive_subkey(master_key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(master_key).expect("HMAC accepts any key size");
    mac.update(label);
    mac.finalize().into_bytes().into()
}

/// SM4 / ZUC 旧标签用 16 字节子密钥：取派生结果前 16 字节（与原版一致）。
fn derive_subkey_16(master_key: &[u8; 32], label: &[u8]) -> [u8; 16] {
    let full = Zeroizing::new(derive_subkey(master_key, label));
    full[..16].try_into().expect("slice is exactly 16 bytes")
}

/// 扩展子密钥 = `HKDF-Expand(PRK, info = 标签, L = N)`，其中
/// `PRK = HMAC-SHA256(key = 主密钥, msg = [`LABEL_PRK_EXT`])`。
fn derive_subkey_ext<const N: usize>(master_key: &[u8; 32], label: &[u8]) -> [u8; N] {
    let prk = Zeroizing::new(derive_subkey(master_key, LABEL_PRK_EXT));
    let hkdf = Hkdf::<Sha256>::from_prk(prk.as_slice()).expect("PRK is 32 bytes (= HashLen)");

    let mut subkey = [0u8; N];
    hkdf.expand(label, &mut subkey)
        .expect("N in {16, 32, 64} is far below the HKDF limit of 255 * 32");
    subkey
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        crate::internal::hex_encode(bytes)
    }

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

    /// 五个旧标签的已知答案向量：**冻结存量数据的兼容契约**。
    ///
    /// 常量用外部独立实现计算（Python `hmac.new(master, msg, sha256)`，
    /// 主密钥 `[0x2a; 32]`），并与本实现的输出逐字节比对 —— 任何人改动标签
    /// 常量或 HMAC 参数顺序，这里都会红，而存量密文不会被静默破坏。
    #[test]
    fn legacy_subkeys_are_frozen() {
        let master = [42u8; 32];
        let cases: [(&[u8], &str); 5] = [
            (
                LABEL_AES_GCM,
                "8c40365a67198f254b99a3e59b5da02762b2368432e436807d52646764709efa",
            ),
            (
                LABEL_AES_CBC,
                "e2b808949cc38e4be732924c88c56738a607cbd63e1e6a81ff89cada485da4b5",
            ),
            (
                LABEL_SODIUM,
                "24f1543b4d2d3a48c835f3d10bd758e7ad94f55fed8b0fb64fa5e29fa5ff834d",
            ),
            (
                LABEL_SM4,
                "a0a1e7c2645d1eed02f2fc43eca98992009424fb80e8314b5218be6f4b831f97",
            ),
            (
                LABEL_ZUC,
                "e2ac939b959fff17dd6d7a1df705b5e00840364974c0482c30419661f4195b88",
            ),
        ];
        for (label, expected) in cases {
            assert_eq!(
                hex(&derive_subkey(&master, label)),
                expected,
                "label {}",
                String::from_utf8_lossy(label)
            );
        }
        // 16 字节旧标签 = 32 字节派生结果的前 16 字节。
        assert_eq!(
            hex(&derive_subkey_16(&master, LABEL_SM4)),
            "a0a1e7c2645d1eed02f2fc43eca98992"
        );
        assert_eq!(
            hex(&derive_subkey_16(&master, LABEL_ZUC)),
            "e2ac939b959fff17dd6d7a1df705b5e0"
        );
    }

    /// 扩展域的已知答案向量（PRK + 九个子密钥），算法与旧标签同法外部计算
    /// （Python `hmac` + RFC 5869 HKDF-Expand，后者以 RFC 5869 A.1/A.2 官方向量
    /// 自校），再与本实现比对。改标签、改 PRK 常量、改 HKDF 参数都会红。
    #[test]
    fn extension_subkeys_are_frozen() {
        let master = [42u8; 32];
        assert_eq!(
            hex(&derive_subkey(&master, LABEL_PRK_EXT)),
            "d13e7885aa737fe03fd1aff45bfee04971cb42a65c6d83df6c81251b4a48e76a"
        );

        assert_eq!(
            hex(&derive_subkey_ext::<32>(
                &master,
                LABEL_CHACHA20_POLY1305_IETF
            )),
            "b72beef1f703fbc67add7c0045129406a7e33bed2f44bf1ba5cfdbca46983f3c"
        );
        assert_eq!(
            hex(&derive_subkey_ext::<32>(&master, LABEL_AES_GCM_SIV)),
            "4ea65b0fec0a961de6c8f4a3a4e1d4a1a422d8e494ed976d51c6136ab3c65d84"
        );
        assert_eq!(
            hex(&derive_subkey_ext::<32>(&master, LABEL_CAMELLIA)),
            "64fc1e0b8ba07c51e5b3bcfc43be3d370f1d26276957d0b07144f6e3b12bbf21"
        );
        assert_eq!(
            hex(&derive_subkey_ext::<32>(&master, LABEL_ARIA)),
            "ae167985194b12afb4ee564310e23573767f06e8ac12967914b9ad651ef88b34"
        );
        assert_eq!(
            hex(&derive_subkey_ext::<64>(&master, LABEL_THREEFISH)),
            concat!(
                "951afa424d5221c2de5f5f7f9be38e23",
                "1eb96fc1842c25b04804c8cc50b7f131",
                "4849ff963922f5ec93d127536f52c310",
                "1920c5477ad5f04ad8ad122efd4c3b87"
            )
        );
        assert_eq!(
            hex(&derive_subkey_ext::<32>(&master, LABEL_KUZNYECHIK)),
            "20825902f56afe01bc183dce96fd7d8f4a68d7e9854be51a73b9d5d1c3e3d887"
        );
        assert_eq!(
            hex(&derive_subkey_ext::<32>(&master, LABEL_SALSA20)),
            "c059a09ff49bb3c6916beb350354091b27f80c4708da3ae7d17364f1d7a6898b"
        );
        assert_eq!(
            hex(&derive_subkey_ext::<16>(&master, LABEL_SM4_GCM)),
            "3b02d8456195d02a514fdbeb5d5ff8a8"
        );
        assert_eq!(
            hex(&derive_subkey_ext::<32>(&master, LABEL_ZUC256)),
            "832ef3816ff4fde09aecce478f817d2ff878000567ffb7c7a585c21071775a4c"
        );
    }

    /// 标签不重名 + 子密钥两两不同：一处失守就会让两个算法共用密钥。
    #[test]
    fn labels_and_subkeys_are_distinct() {
        let master = [42u8; 32];
        let legacy_labels = [
            LABEL_AES_GCM,
            LABEL_AES_CBC,
            LABEL_SM4,
            LABEL_ZUC,
            LABEL_SODIUM,
        ];
        let ext_labels = [
            LABEL_CHACHA20_POLY1305_IETF,
            LABEL_AES_GCM_SIV,
            LABEL_CAMELLIA,
            LABEL_ARIA,
            LABEL_THREEFISH,
            LABEL_KUZNYECHIK,
            LABEL_SALSA20,
            LABEL_SM4_GCM,
            LABEL_ZUC256,
        ];

        let mut labels: Vec<&[u8]> = legacy_labels.to_vec();
        labels.extend(ext_labels.iter().copied());
        for (i, first) in labels.iter().enumerate() {
            for second in &labels[i + 1..] {
                assert_ne!(first, second, "用途标签必须互不重名");
            }
        }

        let mut subkeys: Vec<Vec<u8>> = legacy_labels
            .iter()
            .map(|label| derive_subkey(&master, label).to_vec())
            .collect();
        subkeys.extend(
            ext_labels
                .iter()
                .map(|label| derive_subkey_ext::<64>(&master, label).to_vec()),
        );
        assert_eq!(subkeys.len(), 14);
        for (i, first) in subkeys.iter().enumerate() {
            for second in &subkeys[i + 1..] {
                // 16 字节标签取前缀，与各自算法实际使用的子密钥一致。
                assert_ne!(
                    &first[..16],
                    &second[..16],
                    "任一算法的子密钥前缀都不得与其他算法相同"
                );
            }
        }
    }

    /// 十四个算法全部注册且往返；默认算法校验与主密钥校验不变。
    #[test]
    fn all_fourteen_roundtrip_and_validate() {
        assert_eq!(
            EncryptionManagerFactory::from_master_key_all(&[0u8; 31], "aes-256-gcm").unwrap_err(),
            Error::InvalidMasterKey { got: 31 }
        );
        assert_eq!(
            EncryptionManagerFactory::from_master_key_all(&[0u8; 32], "aes-512").unwrap_err(),
            Error::UnknownIdentifier {
                kind: "symmetric cipher",
                identifier: "aes-512".to_string()
            }
        );

        let manager =
            EncryptionManagerFactory::from_master_key_all(&[42u8; 32], "aes-256-gcm").unwrap();
        let expected = [
            "aes-256-cbc-hmac",
            "aes-256-gcm",
            "aes-256-gcm-siv",
            "aria-256-cbc-hmac",
            "camellia-256-cbc-hmac",
            "chacha20-poly1305-ietf",
            "kuznyechik-256-cbc-hmac",
            "salsa20",
            "sm4-cbc",
            "sm4-gcm",
            "sodium-xchacha20",
            "threefish-512-cbc-hmac",
            "zuc-128",
            "zuc-256",
        ];
        assert_eq!(manager.registry().identifiers(), expected);

        for identifier in expected {
            let blob = manager.encrypt_with(identifier, b"cross-check").unwrap();
            assert_eq!(
                manager.decrypt_with(identifier, &blob).unwrap(),
                b"cross-check",
                "{identifier}"
            );
        }
    }

    /// 扩展不改变旧标签派生：两个工厂（五算法 / 十四算法）对五个默认算法的
    /// 子密钥逐字节相同 —— 用公开 API 交叉解密验证（同子密钥才解得开）。
    #[test]
    fn legacy_subkeys_are_unchanged_when_extensions_are_added() {
        let five = EncryptionManagerFactory::from_master_key(&[42u8; 32], "aes-256-gcm").unwrap();
        let all =
            EncryptionManagerFactory::from_master_key_all(&[42u8; 32], "aes-256-gcm").unwrap();

        for identifier in five.registry().identifiers() {
            let from_five = five.encrypt_with(identifier, b"shared subkey").unwrap();
            assert_eq!(
                all.decrypt_with(identifier, &from_five).unwrap(),
                b"shared subkey",
                "{identifier}"
            );
            let from_all = all.encrypt_with(identifier, b"shared subkey").unwrap();
            assert_eq!(
                five.decrypt_with(identifier, &from_all).unwrap(),
                b"shared subkey",
                "{identifier}"
            );
        }
    }

    /// 组合用法：先建五算法管理器，再把扩展注册进去，结果与
    /// [`EncryptionManagerFactory::from_master_key_all`] 等价。
    #[test]
    fn register_extensions_composes_into_existing_registry() {
        assert_eq!(
            EncryptionManagerFactory::register_extensions(
                &mut Registry::new("symmetric cipher"),
                &[0u8; 16]
            )
            .unwrap_err(),
            Error::InvalidMasterKey { got: 16 }
        );

        let mut manager =
            EncryptionManagerFactory::from_master_key(&[42u8; 32], "aes-256-gcm").unwrap();
        EncryptionManagerFactory::register_extensions(manager.registry_mut(), &[42u8; 32]).unwrap();
        assert_eq!(manager.registry().identifiers().len(), 14);

        let all =
            EncryptionManagerFactory::from_master_key_all(&[42u8; 32], "aes-256-gcm").unwrap();
        assert_eq!(
            manager.registry().identifiers(),
            all.registry().identifiers()
        );

        // 组合路径派生的子密钥与 from_master_key_all 一致：交叉解密。
        for identifier in manager.registry().identifiers() {
            let composed = manager.encrypt_with(identifier, b"composed").unwrap();
            assert_eq!(
                all.decrypt_with(identifier, &composed).unwrap(),
                b"composed",
                "{identifier}"
            );
        }
    }
}
