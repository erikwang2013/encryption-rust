// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! CBC / SM4 / ZUC 共用的 encrypt-then-MAC 打包与校验
//! （对应 PHP 版的 `Internal\EncryptThenMacBlob`）。
//!
//! 载荷：`v1 | IV | MAC(32) | 密文`；`MAC = HMAC-SHA256(mac_key, IV ‖ 密文)`；
//! `mac_key = HMAC-SHA256(key = 密文密钥, msg = b"dgn:enc:hmac")`。

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{Error, Result};

/// 载荷前缀（密文格式版本，与密钥派生方案无关）。
pub(crate) const PREFIX: &[u8] = b"v1";

/// HMAC-SHA256 输出长度。
pub(crate) const MAC_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// MAC 密钥：以密文密钥为 HMAC key、固定标签为 message（修正后的参数顺序）。
fn mac_key(key: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(b"dgn:enc:hmac");
    mac.finalize().into_bytes().into()
}

/// 打包为 `v1 | IV | MAC | 密文`。
pub(crate) fn pack(iv: &[u8], ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let mac = {
        let mut mac = HmacSha256::new_from_slice(&mac_key(key)).expect("HMAC accepts any key size");
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
pub(crate) fn unpack_and_verify<'a>(
    blob: &'a [u8],
    iv_len: usize,
    key: &[u8],
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

    let mut verifier =
        HmacSha256::new_from_slice(&mac_key(key)).expect("HMAC accepts any key size");
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

    #[test]
    fn pack_then_verify_roundtrip() {
        let key = [1u8; 16];
        let blob = pack(&[2u8; 16], &[3u8; 8], &key);
        let (iv, ct) = unpack_and_verify(&blob, 16, &key, "TEST").unwrap();
        assert_eq!(iv, &[2u8; 16]);
        assert_eq!(ct, &[3u8; 8]);
    }

    #[test]
    fn tampered_blob_fails_mac() {
        let key = [1u8; 16];
        let mut blob = pack(&[2u8; 16], &[3u8; 8], &key);
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert_eq!(
            unpack_and_verify(&blob, 16, &key, "TEST").unwrap_err(),
            Error::MacVerificationFailed { label: "TEST" }
        );
    }

    #[test]
    fn wrong_prefix_and_short_blob() {
        let key = [1u8; 16];
        assert_eq!(
            unpack_and_verify(b"v9short", 16, &key, "TEST").unwrap_err(),
            Error::InvalidPrefix { label: "TEST" }
        );
        assert_eq!(
            unpack_and_verify(b"v1tooshort", 16, &key, "TEST").unwrap_err(),
            Error::TooShort { label: "TEST" }
        );
    }
}
