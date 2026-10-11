// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! CBC / SM4 / ZUC / Salsa20 共用的 encrypt-then-MAC 打包与校验
//! （对应 PHP 版的 `Internal\EncryptThenMacBlob`）。
//!
//! 载荷：`v1 | IV | MAC(32) | 密文`；`MAC = HMAC-SHA256(mac_key, IV ‖ 密文)`；
//! `mac_key = HMAC-SHA256(key = 密文密钥, msg = b"dgn:enc:hmac")`。
//!
//! MAC 密钥只由密文密钥决定，而密文密钥在加密器构造后不再变——所以派生一次、
//! 随 [`EtmKeys`] 存活，加密与解密路径都不再重复派生（原先每次调用白做一次
//! 完整 HMAC-SHA256）。

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::key::Key;

/// 载荷前缀（密文格式版本，与密钥派生方案无关）。
pub(crate) const PREFIX: &[u8] = b"v1";

/// HMAC-SHA256 输出长度。
pub(crate) const MAC_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// 一套 EtM 密钥：密文密钥 + 由它派生的 MAC 密钥。
///
/// `N` 为密文密钥长度（16 / 32 / 64，随算法）。两把密钥都在 Drop 时清零
/// （`Key<N>` 自带）。
pub(crate) struct EtmKeys<const N: usize> {
    cipher: Key<N>,
    mac: Key<MAC_LEN>,
}

impl<const N: usize> EtmKeys<N> {
    pub(crate) fn new(cipher_key: [u8; N]) -> Self {
        let mac = derive_mac_key(&cipher_key);
        Self {
            cipher: Key::new(cipher_key),
            mac: Key::new(mac),
        }
    }

    pub(crate) fn from_slice(key: &[u8], label: &'static str) -> Result<Self> {
        let cipher = Key::<N>::from_slice(key, label)?;
        Ok(Self {
            mac: Key::new(derive_mac_key(cipher.as_bytes())),
            cipher,
        })
    }

    pub(crate) fn cipher(&self) -> &[u8; N] {
        self.cipher.as_bytes()
    }

    pub(crate) fn mac(&self) -> &[u8; MAC_LEN] {
        self.mac.as_bytes()
    }
}

impl<const N: usize> std::fmt::Debug for EtmKeys<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EtmKeys").finish_non_exhaustive()
    }
}

/// MAC 密钥：以密文密钥为 HMAC key、固定标签为 message（修正后的参数顺序）。
fn derive_mac_key(key: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(b"dgn:enc:hmac");
    mac.finalize().into_bytes().into()
}

/// 打包为 `v1 | IV | MAC | 密文`。`mac_key` 由 [`EtmKeys::mac`] 提供。
pub(crate) fn pack(iv: &[u8], ciphertext: &[u8], mac_key: &[u8; MAC_LEN]) -> Vec<u8> {
    let mac = {
        let mut mac = HmacSha256::new_from_slice(mac_key).expect("MAC key length is fixed");
        mac.update(iv);
        mac.update(ciphertext);
        mac.finalize().into_bytes()
    };

    let mut blob = Vec::with_capacity(PREFIX.len() + iv.len() + MAC_LEN + ciphertext.len());
    blob.extend_from_slice(PREFIX);
    blob.extend_from_slice(iv);
    blob.extend_from_slice(&mac);
    blob.extend_from_slice(ciphertext);
    blob
}

/// 校验前缀与 MAC（常量时间比较），返回 `(IV, 密文)`。
///
/// `mac_key` 由 [`EtmKeys::mac`] 提供。校验先于任何解密，且失败原因不外传。
pub(crate) fn unpack_and_verify<'a>(
    blob: &'a [u8],
    iv_len: usize,
    mac_key: &[u8; MAC_LEN],
    label: &'static str,
) -> Result<(&'a [u8], &'a [u8])> {
    let body = blob
        .strip_prefix(PREFIX)
        .ok_or(Error::InvalidPrefix { label })?;
    if body.len() < iv_len + MAC_LEN {
        return Err(Error::TooShort { label });
    }

    let (iv, rest) = body.split_at(iv_len);
    let (mac, ciphertext) = rest.split_at(MAC_LEN);

    let mut verifier = HmacSha256::new_from_slice(mac_key).expect("MAC key length is fixed");
    verifier.update(iv);
    verifier.update(ciphertext);
    verifier
        .verify_slice(mac)
        .map_err(|_| Error::MacVerificationFailed { label })?;

    Ok((iv, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> EtmKeys<16> {
        EtmKeys::new([1u8; 16])
    }

    #[test]
    fn pack_then_verify_roundtrip() {
        let keys = keys();
        let blob = pack(&[2u8; 16], &[3u8; 8], keys.mac());
        let (iv, ct) = unpack_and_verify(&blob, 16, keys.mac(), "TEST").unwrap();
        assert_eq!(iv, &[2u8; 16]);
        assert_eq!(ct, &[3u8; 8]);
    }

    #[test]
    fn tampered_blob_fails_mac() {
        let keys = keys();
        let mut blob = pack(&[2u8; 16], &[3u8; 8], keys.mac());
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert_eq!(
            unpack_and_verify(&blob, 16, keys.mac(), "TEST").unwrap_err(),
            Error::MacVerificationFailed { label: "TEST" }
        );
    }

    #[test]
    fn wrong_prefix_and_short_blob() {
        let keys = keys();
        assert_eq!(
            unpack_and_verify(b"v9short", 16, keys.mac(), "TEST").unwrap_err(),
            Error::InvalidPrefix { label: "TEST" }
        );
        assert_eq!(
            unpack_and_verify(b"v1tooshort", 16, keys.mac(), "TEST").unwrap_err(),
            Error::TooShort { label: "TEST" }
        );
    }

    /// MAC 密钥只由密文密钥决定：同一密钥两次构造必须派生出一致的 MAC 密钥，
    /// 不同密钥必须派生不同 MAC 密钥（否则 EtM 的密钥分离就名存实亡）。
    #[test]
    fn mac_key_is_deterministic_and_key_separated() {
        assert_eq!(EtmKeys::<16>::new([1u8; 16]).mac(), keys().mac());
        assert_ne!(EtmKeys::<16>::new([2u8; 16]).mac(), keys().mac());
        // MAC 密钥与密文密钥必须是两把不同的密钥。
        assert_ne!(keys().mac().as_slice(), keys().cipher().as_slice());
    }

    /// 派生出的 MAC 密钥必须等于「密文密钥为 HMAC key、固定标签为消息」的定值，
    /// 冻住这个派生关系——标签或参数顺序被改动时这里立刻失败，而自洽的
    /// 往返测试抓不出来。
    ///
    /// 期望值由独立实现复算：`HMAC-SHA256(key = 0x01×16, msg = "dgn:enc:hmac")`。
    #[test]
    fn mac_key_matches_frozen_derivation() {
        assert_eq!(
            crate::internal::hex_encode(keys().mac()),
            "0ced01b3fcdaa8c6239f535b1cf09bd1a193dd842c827d16652ba8276b1e3ff6"
        );
    }

    #[test]
    fn keys_are_length_checked_from_slice() {
        assert!(EtmKeys::<16>::from_slice(&[0u8; 16], "T").is_ok());
        assert_eq!(
            EtmKeys::<16>::from_slice(&[0u8; 32], "T").unwrap_err(),
            Error::InvalidKeyLength {
                label: "T",
                expected: 16,
                got: 32
            }
        );
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let text = format!("{:?}", keys());
        assert!(
            !text.contains("01"),
            "raw key bytes must not appear: {text}"
        );
        assert!(text.contains("EtmKeys"));
    }
}
