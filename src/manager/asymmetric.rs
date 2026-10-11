// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 非对称能力门面：签名（[`SignatureManager`]）与密钥协商（[`KeyAgreementManager`]）。
//!
//! 与 [`super`] 里其余六个门面同构，同样由 `manager_facade!` 宏生成；单独成文件
//! 只是按用途分组——签名与协商属于非对称能力，与 [`super`] 的加密 / 哈希 / 派生
//! 门面分开放更好翻。两个调用点写在 `manager.rs` 的宏定义之后：`macro_rules!`
//! 是文本作用域，先定义后调用的顺序不是排版随意。

manager_facade! {
    /// 签名门面。
    SignatureManager, crate::contract::Signer, "signer",
    /// 返回十六进制签名。
    sign with sign_with(message: &[u8], private_key_hex: &str)
        -> crate::error::Result<String>,
    verify with verify_with(message: &[u8], signature_hex: &str, public_key_hex: &str)
        -> crate::error::Result<()>,
}

manager_facade! {
    /// 密钥协商门面。
    KeyAgreementManager, crate::contract::KeyAgreement, "key agreement",
    /// 返回定长共享秘密的十六进制。
    agree with agree_with(private_key_hex: &str, peer_public_key_hex: &str)
        -> crate::error::Result<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asymmetric::ed25519::Ed25519Signer;
    use crate::asymmetric::x25519::X25519Agreement;
    use crate::contract::{KeyAgreement, Signer};
    use crate::error::Error;
    use crate::registry::Registry;

    /// 签名门面是纯转发：签一次、验一次通过，被改过的消息验签失败。
    #[test]
    fn signature_manager_round_trips_and_rejects_tampering() {
        let mut registry: Registry<Box<dyn Signer>> = Registry::new("signer");
        registry.register(Box::new(Ed25519Signer::new()));
        let mut manager = SignatureManager::new(registry, Ed25519Signer::IDENTIFIER).unwrap();

        let pair = Ed25519Signer::generate_key_pair_hex().unwrap();
        let signature = manager.sign(b"message", &pair.private_key_hex).unwrap();
        manager
            .verify(b"message", &signature, &pair.public_key_hex)
            .unwrap();
        assert!(
            manager
                .verify(b"tampered", &signature, &pair.public_key_hex)
                .is_err()
        );

        // 默认标识改不动：`set_default_identifier` 与 `new` 用同一个 kind 文案
        //（宏里 `$kind` 的第二处展开）。
        assert_eq!(
            manager.set_default_identifier("missing").unwrap_err(),
            Error::UnknownIdentifier {
                kind: "signer",
                identifier: "missing".to_string(),
            }
        );

        // 门面的 Debug 由 derive 给出，注册表只打印能力名与标识列表：私钥不出现。
        let text = format!("{manager:?}");
        assert!(text.contains("Registry"), "{text}");
        assert!(!text.contains(&pair.private_key_hex), "{text}");
    }

    /// 协商门面同样是纯转发：两端各用自己的私钥与对方公钥，导出同一个共享秘密。
    #[test]
    fn key_agreement_manager_agrees_on_the_same_secret() {
        let mut registry: Registry<Box<dyn KeyAgreement>> = Registry::new("key agreement");
        registry.register(Box::new(X25519Agreement::new()));
        let manager = KeyAgreementManager::new(registry, X25519Agreement::IDENTIFIER).unwrap();

        let alice = X25519Agreement::generate_key_pair_hex().unwrap();
        let bob = X25519Agreement::generate_key_pair_hex().unwrap();

        let from_alice = manager
            .agree(&alice.private_key_hex, &bob.public_key_hex)
            .unwrap();
        let from_bob = manager
            .agree(&bob.private_key_hex, &alice.public_key_hex)
            .unwrap();
        assert_eq!(from_alice, from_bob);
    }
}
