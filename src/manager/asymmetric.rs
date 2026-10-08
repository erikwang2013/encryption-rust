// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 非对称能力门面：签名（[`SignatureManager`]）与密钥协商（[`KeyAgreementManager`]）。
//!
//! 与 [`super`] 里的门面同构；单独成文件是为了让 `manager.rs` 保持在 500 行以内。

use super::check_default;
use crate::contract::{KeyAgreement, Signer};
use crate::error::Result;
use crate::registry::Registry;

/// 签名门面。
#[derive(Debug)]
pub struct SignatureManager {
    registry: Registry<Box<dyn Signer>>,
    default_identifier: String,
}

impl SignatureManager {
    pub fn new(
        registry: Registry<Box<dyn Signer>>,
        default_identifier: impl Into<String>,
    ) -> Result<Self> {
        let default_identifier = default_identifier.into();
        check_default(
            registry.has(&default_identifier),
            "signer",
            &default_identifier,
        )?;
        Ok(Self {
            registry,
            default_identifier,
        })
    }

    /// 返回十六进制签名。
    pub fn sign(&self, message: &[u8], private_key_hex: &str) -> Result<String> {
        self.sign_with(&self.default_identifier, message, private_key_hex)
    }

    pub fn sign_with(
        &self,
        identifier: &str,
        message: &[u8],
        private_key_hex: &str,
    ) -> Result<String> {
        self.registry
            .get(identifier)?
            .sign(message, private_key_hex)
    }

    pub fn verify(&self, message: &[u8], signature_hex: &str, public_key_hex: &str) -> Result<()> {
        self.verify_with(
            &self.default_identifier,
            message,
            signature_hex,
            public_key_hex,
        )
    }

    pub fn verify_with(
        &self,
        identifier: &str,
        message: &[u8],
        signature_hex: &str,
        public_key_hex: &str,
    ) -> Result<()> {
        self.registry
            .get(identifier)?
            .verify(message, signature_hex, public_key_hex)
    }

    pub fn registry(&self) -> &Registry<Box<dyn Signer>> {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut Registry<Box<dyn Signer>> {
        &mut self.registry
    }

    pub fn default_identifier(&self) -> &str {
        &self.default_identifier
    }

    pub fn set_default_identifier(&mut self, identifier: impl Into<String>) -> Result<()> {
        let identifier = identifier.into();
        check_default(self.registry.has(&identifier), "signer", &identifier)?;
        self.default_identifier = identifier;
        Ok(())
    }
}

/// 密钥协商门面。
#[derive(Debug)]
pub struct KeyAgreementManager {
    registry: Registry<Box<dyn KeyAgreement>>,
    default_identifier: String,
}

impl KeyAgreementManager {
    pub fn new(
        registry: Registry<Box<dyn KeyAgreement>>,
        default_identifier: impl Into<String>,
    ) -> Result<Self> {
        let default_identifier = default_identifier.into();
        check_default(
            registry.has(&default_identifier),
            "key agreement",
            &default_identifier,
        )?;
        Ok(Self {
            registry,
            default_identifier,
        })
    }

    /// 返回定长共享秘密的十六进制。
    pub fn agree(&self, private_key_hex: &str, peer_public_key_hex: &str) -> Result<String> {
        self.agree_with(
            &self.default_identifier,
            private_key_hex,
            peer_public_key_hex,
        )
    }

    pub fn agree_with(
        &self,
        identifier: &str,
        private_key_hex: &str,
        peer_public_key_hex: &str,
    ) -> Result<String> {
        self.registry
            .get(identifier)?
            .agree(private_key_hex, peer_public_key_hex)
    }

    pub fn registry(&self) -> &Registry<Box<dyn KeyAgreement>> {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut Registry<Box<dyn KeyAgreement>> {
        &mut self.registry
    }

    pub fn default_identifier(&self) -> &str {
        &self.default_identifier
    }

    pub fn set_default_identifier(&mut self, identifier: impl Into<String>) -> Result<()> {
        let identifier = identifier.into();
        check_default(self.registry.has(&identifier), "key agreement", &identifier)?;
        self.default_identifier = identifier;
        Ok(())
    }
}
