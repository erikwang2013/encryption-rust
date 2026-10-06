// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 标识 → 实现的存储，各注册表共用（对应 PHP 版 `AbstractRegistry`）。

use std::collections::BTreeMap;
use std::fmt;

use crate::contract::Identified;
use crate::error::{Error, Result};

/// 泛型注册表：`Registry<Box<dyn SymmetricCipher>>` 等。
///
/// 注册表按 `item.identifier()` 存储；相同标识重复注册以最后一次为准。
/// `kind` 仅用于错误消息（如 "symmetric cipher"）。
pub struct Registry<T> {
    kind: &'static str,
    items: BTreeMap<String, T>,
}

impl<T: Identified> Registry<T> {
    /// `kind`：错误消息里的能力名称，如 "symmetric cipher"。
    pub fn new(kind: &'static str) -> Self {
        Self {
            kind,
            items: BTreeMap::new(),
        }
    }

    /// 以 `item.identifier()` 为键注册/覆盖。
    pub fn register(&mut self, item: T) -> &mut Self {
        let identifier = item.identifier().to_string();
        self.items.insert(identifier, item);
        self
    }

    pub fn has(&self, identifier: &str) -> bool {
        self.items.contains_key(identifier)
    }

    pub fn get(&self, identifier: &str) -> Result<&T> {
        self.items
            .get(identifier)
            .ok_or_else(|| Error::UnknownIdentifier {
                kind: self.kind,
                identifier: identifier.to_string(),
            })
    }

    /// 已注册标识，按字典序。
    pub fn identifiers(&self) -> Vec<&str> {
        self.items.keys().map(String::as_str).collect()
    }
}

/// 只打印能力名与标识列表；不要求 `T: Debug`（实现内部持有密钥）。
impl<T: Identified> fmt::Debug for Registry<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry")
            .field("kind", &self.kind)
            .field("identifiers", &self.identifiers())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Dummy(&'static str);

    impl Identified for Dummy {
        fn identifier(&self) -> &str {
            self.0
        }
    }

    #[test]
    fn register_get_has_identifiers() {
        let mut registry = Registry::new("dummy");
        registry.register(Dummy("a")).register(Dummy("b"));

        assert!(registry.has("a"));
        assert_eq!(registry.get("a").unwrap().identifier(), "a");
        assert_eq!(registry.identifiers(), vec!["a", "b"]);
    }

    #[test]
    fn unknown_identifier_is_an_error() {
        let registry: Registry<Dummy> = Registry::new("dummy");
        let error = registry.get("missing").unwrap_err();
        assert_eq!(
            error,
            Error::UnknownIdentifier {
                kind: "dummy",
                identifier: "missing".to_string()
            }
        );
    }

    #[test]
    fn re_registering_same_identifier_overwrites() {
        let mut registry = Registry::new("dummy");
        registry.register(Dummy("a"));
        registry.register(Dummy("a"));
        assert_eq!(registry.identifiers(), vec!["a"]);
    }
}
