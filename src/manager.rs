// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 门面（Manager）：注册表 + 默认标识的组合，业务层的常用入口。
//!
//! 对应 PHP 版的 `EncryptionManager`、`AsymmetricCryptoManager`、`HashingManager`、
//! `KeyDerivationManager`、`PasswordBasedKdfManager`。每个门面提供「用默认算法」与
//! 「显式指定 `*_with(identifier, ...)`」两组方法。

use crate::contract::{
    AsymmetricCipher, Hasher, KeyDerivation, KeyEncapsulation, PasswordBasedKdf, SymmetricCipher,
};
use crate::error::{Error, Result};
use crate::registry::Registry;

/// 校验并设置默认标识。
fn check_default(registry_has: bool, kind: &'static str, identifier: &str) -> Result<()> {
    if registry_has {
        Ok(())
    } else {
        Err(Error::UnknownIdentifier {
            kind,
            identifier: identifier.to_string(),
        })
    }
}

/// 对称加密门面。
#[derive(Debug)]
pub struct EncryptionManager {
    registry: Registry<Box<dyn SymmetricCipher>>,
    default_identifier: String,
}

impl EncryptionManager {
    /// `default_identifier` 必须已注册，否则返回 [`Error::UnknownIdentifier`]。
    pub fn new(
        registry: Registry<Box<dyn SymmetricCipher>>,
        default_identifier: impl Into<String>,
    ) -> Result<Self> {
        let default_identifier = default_identifier.into();
        check_default(
            registry.has(&default_identifier),
            registry_kind(),
            &default_identifier,
        )?;
        Ok(Self {
            registry,
            default_identifier,
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_with(&self.default_identifier, plaintext)
    }

    pub fn encrypt_with(&self, identifier: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.registry.get(identifier)?.encrypt(plaintext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_with(&self.default_identifier, ciphertext)
    }

    pub fn decrypt_with(&self, identifier: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.registry.get(identifier)?.decrypt(ciphertext)
    }

    pub fn registry(&self) -> &Registry<Box<dyn SymmetricCipher>> {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut Registry<Box<dyn SymmetricCipher>> {
        &mut self.registry
    }

    pub fn default_identifier(&self) -> &str {
        &self.default_identifier
    }

    pub fn set_default_identifier(&mut self, identifier: impl Into<String>) -> Result<()> {
        let identifier = identifier.into();
        check_default(self.registry.has(&identifier), registry_kind(), &identifier)?;
        self.default_identifier = identifier;
        Ok(())
    }
}

fn registry_kind() -> &'static str {
    "symmetric cipher"
}

/// 非对称加密门面。
#[derive(Debug)]
pub struct AsymmetricCryptoManager {
    registry: Registry<Box<dyn AsymmetricCipher>>,
    default_identifier: String,
}

impl AsymmetricCryptoManager {
    pub fn new(
        registry: Registry<Box<dyn AsymmetricCipher>>,
        default_identifier: impl Into<String>,
    ) -> Result<Self> {
        let default_identifier = default_identifier.into();
        check_default(
            registry.has(&default_identifier),
            "asymmetric cipher",
            &default_identifier,
        )?;
        Ok(Self {
            registry,
            default_identifier,
        })
    }

    /// 返回十六进制密文。
    pub fn encrypt(&self, plaintext: &[u8], public_key_hex: &str) -> Result<String> {
        self.encrypt_with(&self.default_identifier, plaintext, public_key_hex)
    }

    pub fn encrypt_with(
        &self,
        identifier: &str,
        plaintext: &[u8],
        public_key_hex: &str,
    ) -> Result<String> {
        self.registry
            .get(identifier)?
            .encrypt(plaintext, public_key_hex)
    }

    pub fn decrypt(&self, ciphertext_hex: &str, private_key_hex: &str) -> Result<Vec<u8>> {
        self.decrypt_with(&self.default_identifier, ciphertext_hex, private_key_hex)
    }

    pub fn decrypt_with(
        &self,
        identifier: &str,
        ciphertext_hex: &str,
        private_key_hex: &str,
    ) -> Result<Vec<u8>> {
        self.registry
            .get(identifier)?
            .decrypt(ciphertext_hex, private_key_hex)
    }

    pub fn registry(&self) -> &Registry<Box<dyn AsymmetricCipher>> {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut Registry<Box<dyn AsymmetricCipher>> {
        &mut self.registry
    }

    pub fn default_identifier(&self) -> &str {
        &self.default_identifier
    }

    pub fn set_default_identifier(&mut self, identifier: impl Into<String>) -> Result<()> {
        let identifier = identifier.into();
        check_default(
            self.registry.has(&identifier),
            "asymmetric cipher",
            &identifier,
        )?;
        self.default_identifier = identifier;
        Ok(())
    }
}

/// 哈希门面。
#[derive(Debug)]
pub struct HashingManager {
    registry: Registry<Box<dyn Hasher>>,
    default_identifier: String,
}

impl HashingManager {
    pub fn new(
        registry: Registry<Box<dyn Hasher>>,
        default_identifier: impl Into<String>,
    ) -> Result<Self> {
        let default_identifier = default_identifier.into();
        check_default(
            registry.has(&default_identifier),
            "hasher",
            &default_identifier,
        )?;
        Ok(Self {
            registry,
            default_identifier,
        })
    }

    pub fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.digest_with(&self.default_identifier, data)
    }

    pub fn digest_with(&self, identifier: &str, data: &[u8]) -> Result<Vec<u8>> {
        self.registry.get(identifier)?.digest(data)
    }

    pub fn digest_hex(&self, data: &[u8]) -> Result<String> {
        self.digest_hex_with(&self.default_identifier, data)
    }

    pub fn digest_hex_with(&self, identifier: &str, data: &[u8]) -> Result<String> {
        self.registry.get(identifier)?.digest_hex(data)
    }

    pub fn registry(&self) -> &Registry<Box<dyn Hasher>> {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut Registry<Box<dyn Hasher>> {
        &mut self.registry
    }

    pub fn default_identifier(&self) -> &str {
        &self.default_identifier
    }

    pub fn set_default_identifier(&mut self, identifier: impl Into<String>) -> Result<()> {
        let identifier = identifier.into();
        check_default(self.registry.has(&identifier), "hasher", &identifier)?;
        self.default_identifier = identifier;
        Ok(())
    }
}

/// 密钥派生（HKDF）门面。
#[derive(Debug)]
pub struct KeyDerivationManager {
    registry: Registry<Box<dyn KeyDerivation>>,
    default_identifier: String,
}

impl KeyDerivationManager {
    pub fn new(
        registry: Registry<Box<dyn KeyDerivation>>,
        default_identifier: impl Into<String>,
    ) -> Result<Self> {
        let default_identifier = default_identifier.into();
        check_default(
            registry.has(&default_identifier),
            "key derivation",
            &default_identifier,
        )?;
        Ok(Self {
            registry,
            default_identifier,
        })
    }

    pub fn derive(&self, ikm: &[u8], salt: &[u8], length: usize, info: &[u8]) -> Result<Vec<u8>> {
        self.derive_with(&self.default_identifier, ikm, salt, length, info)
    }

    pub fn derive_with(
        &self,
        identifier: &str,
        ikm: &[u8],
        salt: &[u8],
        length: usize,
        info: &[u8],
    ) -> Result<Vec<u8>> {
        self.registry
            .get(identifier)?
            .derive(ikm, salt, length, info)
    }

    pub fn registry(&self) -> &Registry<Box<dyn KeyDerivation>> {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut Registry<Box<dyn KeyDerivation>> {
        &mut self.registry
    }

    pub fn default_identifier(&self) -> &str {
        &self.default_identifier
    }

    pub fn set_default_identifier(&mut self, identifier: impl Into<String>) -> Result<()> {
        let identifier = identifier.into();
        check_default(
            self.registry.has(&identifier),
            "key derivation",
            &identifier,
        )?;
        self.default_identifier = identifier;
        Ok(())
    }
}

/// 口令派生（PBKDF2）门面。
#[derive(Debug)]
pub struct PasswordBasedKdfManager {
    registry: Registry<Box<dyn PasswordBasedKdf>>,
    default_identifier: String,
}

impl PasswordBasedKdfManager {
    pub fn new(
        registry: Registry<Box<dyn PasswordBasedKdf>>,
        default_identifier: impl Into<String>,
    ) -> Result<Self> {
        let default_identifier = default_identifier.into();
        check_default(
            registry.has(&default_identifier),
            "password-based kdf",
            &default_identifier,
        )?;
        Ok(Self {
            registry,
            default_identifier,
        })
    }

    pub fn derive_from_password(
        &self,
        password: &[u8],
        salt: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        self.derive_from_password_with(&self.default_identifier, password, salt, length)
    }

    pub fn derive_from_password_with(
        &self,
        identifier: &str,
        password: &[u8],
        salt: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        self.registry
            .get(identifier)?
            .derive_from_password(password, salt, length)
    }

    pub fn registry(&self) -> &Registry<Box<dyn PasswordBasedKdf>> {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut Registry<Box<dyn PasswordBasedKdf>> {
        &mut self.registry
    }

    pub fn default_identifier(&self) -> &str {
        &self.default_identifier
    }

    pub fn set_default_identifier(&mut self, identifier: impl Into<String>) -> Result<()> {
        let identifier = identifier.into();
        check_default(
            self.registry.has(&identifier),
            "password-based kdf",
            &identifier,
        )?;
        self.default_identifier = identifier;
        Ok(())
    }
}

/// 密钥封装（KEM）门面。
#[derive(Debug)]
pub struct KeyEncapsulationManager {
    registry: Registry<Box<dyn KeyEncapsulation>>,
    default_identifier: String,
}

impl KeyEncapsulationManager {
    pub fn new(
        registry: Registry<Box<dyn KeyEncapsulation>>,
        default_identifier: impl Into<String>,
    ) -> Result<Self> {
        let default_identifier = default_identifier.into();
        check_default(
            registry.has(&default_identifier),
            "key encapsulation",
            &default_identifier,
        )?;
        Ok(Self {
            registry,
            default_identifier,
        })
    }

    /// 生成密钥对，返回 `(公钥 hex, 私钥 hex)`。
    pub fn generate(&self) -> Result<(String, String)> {
        self.generate_with(&self.default_identifier)
    }

    pub fn generate_with(&self, identifier: &str) -> Result<(String, String)> {
        self.registry.get(identifier)?.generate()
    }

    /// 用公钥封装，返回 `(密文 hex, 共享密钥 hex)`。
    pub fn encapsulate(&self, public_key_hex: &str) -> Result<(String, String)> {
        self.encapsulate_with(&self.default_identifier, public_key_hex)
    }

    pub fn encapsulate_with(
        &self,
        identifier: &str,
        public_key_hex: &str,
    ) -> Result<(String, String)> {
        self.registry.get(identifier)?.encapsulate(public_key_hex)
    }

    /// 用私钥解封装，返回共享密钥 hex（非法密文按隐式拒绝语义不报错）。
    pub fn decapsulate(&self, ciphertext_hex: &str, private_key_hex: &str) -> Result<String> {
        self.decapsulate_with(&self.default_identifier, ciphertext_hex, private_key_hex)
    }

    pub fn decapsulate_with(
        &self,
        identifier: &str,
        ciphertext_hex: &str,
        private_key_hex: &str,
    ) -> Result<String> {
        self.registry
            .get(identifier)?
            .decapsulate(ciphertext_hex, private_key_hex)
    }

    pub fn registry(&self) -> &Registry<Box<dyn KeyEncapsulation>> {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut Registry<Box<dyn KeyEncapsulation>> {
        &mut self.registry
    }

    pub fn default_identifier(&self) -> &str {
        &self.default_identifier
    }

    pub fn set_default_identifier(&mut self, identifier: impl Into<String>) -> Result<()> {
        let identifier = identifier.into();
        check_default(
            self.registry.has(&identifier),
            "key encapsulation",
            &identifier,
        )?;
        self.default_identifier = identifier;
        Ok(())
    }
}
