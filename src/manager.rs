// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 门面（Manager）：注册表 + 默认标识的组合，业务层的常用入口。
//!
//! 对应 PHP 版的 `EncryptionManager`、`AsymmetricCryptoManager`、`HashingManager`、
//! `KeyDerivationManager`、`PasswordBasedKdfManager`。每个门面提供「用默认算法」与
//! 「显式指定 `*_with(identifier, ...)`」两组方法。
//!
//! 八个门面（本文件的六个 + `asymmetric` 子模块的两个）结构完全同构：都是
//! `Registry<Box<dyn 能力>>` 加一个默认标识，默认方法一律转发给 `*_with`。
//! 因此它们统一由 `manager_facade!` 宏生成——调用点只声明门面名、能力 trait、
//! 错误消息里的能力名，以及一张「默认方法 → `*_with` 方法」的转发表；
//! 加一个门面是加一段声明，不是把几十行样板再抄一遍。

use crate::error::{Error, Result};

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

// 门面生成宏——上面八个门面共同的形状：
//
//   struct 名 { registry: Registry<Box<dyn 能力>>, default_identifier: String }
//   new / registry / registry_mut / default_identifier / set_default_identifier
//   x(&self, ...)          → x_with(&self.default_identifier, ...)
//   x_with(&self, id, ...) → registry.get(id)?.x(...)
//
// 三处 Rust 细节决定了它的写法：
//
// - `macro_rules!` 是**文本作用域**：`mod asymmetric;` 里的调用得写在本定义之后，
//   这就是下面 mod 声明跟在宏后面的原因，不是排版随意。
// - 宏体在**展开处**解析路径，参数里的类型在**调用处**解析；所以宏体一律写
//   `$crate::...`，调用点一律写 `crate::...`，谁都不依赖调用方模块里的 `use`。
// - `concat_idents!` 不稳定，`x` 与 `x_with` 的名字只能成对显式传入（`x with x_with`）。
macro_rules! manager_facade {
    (
        $(#[$struct_doc:meta])*
        $name:ident, $capability:path, $kind:literal,
        $(
            $(#[$method_doc:meta])*
            $method:ident with $with:ident ( $($arg:ident: $ty:ty),* $(,)? )
                -> $ret:ty
        ),* $(,)?
    ) => {
        $(#[$struct_doc])*
        #[derive(Debug)]
        pub struct $name {
            registry: $crate::registry::Registry<Box<dyn $capability>>,
            default_identifier: String,
        }

        impl $name {
            /// `default_identifier` 必须已注册，否则返回
            /// [`crate::error::Error::UnknownIdentifier`]。
            pub fn new(
                registry: $crate::registry::Registry<Box<dyn $capability>>,
                default_identifier: impl Into<String>,
            ) -> $crate::error::Result<Self> {
                let default_identifier = default_identifier.into();
                $crate::manager::check_default(
                    registry.has(&default_identifier),
                    $kind,
                    &default_identifier,
                )?;
                Ok(Self {
                    registry,
                    default_identifier,
                })
            }

            $(
                $(#[$method_doc])*
                pub fn $method(&self, $($arg: $ty),*) -> $ret {
                    self.$with(&self.default_identifier $(, $arg)*)
                }

                pub fn $with(&self, identifier: &str $(, $arg: $ty)*) -> $ret {
                    self.registry.get(identifier)?.$method($($arg),*)
                }
            )*

            pub fn registry(&self) -> &$crate::registry::Registry<Box<dyn $capability>> {
                &self.registry
            }

            pub fn registry_mut(
                &mut self,
            ) -> &mut $crate::registry::Registry<Box<dyn $capability>> {
                &mut self.registry
            }

            pub fn default_identifier(&self) -> &str {
                &self.default_identifier
            }

            pub fn set_default_identifier(
                &mut self,
                identifier: impl Into<String>,
            ) -> $crate::error::Result<()> {
                let identifier = identifier.into();
                $crate::manager::check_default(
                    self.registry.has(&identifier),
                    $kind,
                    &identifier,
                )?;
                self.default_identifier = identifier;
                Ok(())
            }
        }
    };
}

mod asymmetric;
pub use asymmetric::{KeyAgreementManager, SignatureManager};

manager_facade! {
    /// 对称加密门面。
    EncryptionManager, crate::contract::SymmetricCipher, "symmetric cipher",
    encrypt with encrypt_with(plaintext: &[u8])
        -> crate::error::Result<Vec<u8>>,
    decrypt with decrypt_with(ciphertext: &[u8])
        -> crate::error::Result<Vec<u8>>,
}

manager_facade! {
    /// 非对称加密门面。
    AsymmetricCryptoManager, crate::contract::AsymmetricCipher, "asymmetric cipher",
    /// 返回十六进制密文。
    encrypt with encrypt_with(plaintext: &[u8], public_key_hex: &str)
        -> crate::error::Result<String>,
    decrypt with decrypt_with(ciphertext_hex: &str, private_key_hex: &str)
        -> crate::error::Result<Vec<u8>>,
}

manager_facade! {
    /// 哈希门面。
    HashingManager, crate::contract::Hasher, "hasher",
    digest with digest_with(data: &[u8])
        -> crate::error::Result<Vec<u8>>,
    digest_hex with digest_hex_with(data: &[u8])
        -> crate::error::Result<String>,
}

manager_facade! {
    /// 密钥派生（HKDF）门面。
    KeyDerivationManager, crate::contract::KeyDerivation, "key derivation",
    derive with derive_with(ikm: &[u8], salt: &[u8], length: usize, info: &[u8])
        -> crate::error::Result<Vec<u8>>,
}

manager_facade! {
    /// 口令派生（PBKDF2）门面。
    PasswordBasedKdfManager, crate::contract::PasswordBasedKdf, "password-based kdf",
    derive_from_password with derive_from_password_with(
        password: &[u8], salt: &[u8], length: usize
    ) -> crate::error::Result<Vec<u8>>,
}

manager_facade! {
    /// 密钥封装（KEM）门面。
    KeyEncapsulationManager, crate::contract::KeyEncapsulation, "key encapsulation",
    /// 生成密钥对，返回 `(公钥 hex, 私钥 hex)`。
    generate with generate_with()
        -> crate::error::Result<(String, String)>,
    /// 用公钥封装，返回 `(密文 hex, 共享密钥 hex)`。
    encapsulate with encapsulate_with(public_key_hex: &str)
        -> crate::error::Result<(String, String)>,
    /// 用私钥解封装，返回共享密钥 hex（非法密文按隐式拒绝语义不报错）。
    decapsulate with decapsulate_with(ciphertext_hex: &str, private_key_hex: &str)
        -> crate::error::Result<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        AsymmetricCipher, Hasher, KeyAgreement, KeyDerivation, KeyEncapsulation, PasswordBasedKdf,
        Signer, SymmetricCipher,
    };
    use crate::registry::Registry;

    /// 八个门面的 `kind` 文案全部钉死：空注册表 + 未注册的默认标识必然报错，
    /// 改宏时若动到文案（或漏传 `$kind`），这里先红。
    ///
    /// 注册表自己的 kind 故意取 "unused"：断言只可能由 `check_default` 收到的
    /// 文案满足，不会与 `Registry::new` 的参数巧合通过。
    #[test]
    fn unknown_default_kind_is_pinned_for_every_facade() {
        fn unknown(kind: &'static str) -> Error {
            Error::UnknownIdentifier {
                kind,
                identifier: "missing".to_string(),
            }
        }

        assert_eq!(
            EncryptionManager::new(
                Registry::<Box<dyn SymmetricCipher>>::new("unused"),
                "missing"
            )
            .unwrap_err(),
            unknown("symmetric cipher")
        );
        assert_eq!(
            AsymmetricCryptoManager::new(
                Registry::<Box<dyn AsymmetricCipher>>::new("unused"),
                "missing"
            )
            .unwrap_err(),
            unknown("asymmetric cipher")
        );
        assert_eq!(
            HashingManager::new(Registry::<Box<dyn Hasher>>::new("unused"), "missing").unwrap_err(),
            unknown("hasher")
        );
        assert_eq!(
            KeyDerivationManager::new(Registry::<Box<dyn KeyDerivation>>::new("unused"), "missing")
                .unwrap_err(),
            unknown("key derivation")
        );
        assert_eq!(
            PasswordBasedKdfManager::new(
                Registry::<Box<dyn PasswordBasedKdf>>::new("unused"),
                "missing"
            )
            .unwrap_err(),
            unknown("password-based kdf")
        );
        assert_eq!(
            KeyEncapsulationManager::new(
                Registry::<Box<dyn KeyEncapsulation>>::new("unused"),
                "missing"
            )
            .unwrap_err(),
            unknown("key encapsulation")
        );
        assert_eq!(
            SignatureManager::new(Registry::<Box<dyn Signer>>::new("unused"), "missing")
                .unwrap_err(),
            unknown("signer")
        );
        assert_eq!(
            KeyAgreementManager::new(Registry::<Box<dyn KeyAgreement>>::new("unused"), "missing")
                .unwrap_err(),
            unknown("key agreement")
        );
    }
}
