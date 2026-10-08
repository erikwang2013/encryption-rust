// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 国密 SM4-GCM（认证加密）；载荷：`v1 | nonce(12) | tag(16) | 密文`
//! （与 aes-256-gcm 完全一致）。密钥 16 字节（SM4 的密钥长度），AAD 固定为空。
//!
//! 不依赖现成的 SM4-GCM crate，按 GB/T 38636-2020 附录 A 的 GCM-AEK 组装：
//!
//! - `H = E_K(0^128)`；
//! - `J0 = nonce‖0^31‖1`（96 位 nonce 的特例）；
//! - 密文 `C = GCTR_K(inc32(J0), P)`，计数器块自 `inc32(J0)` 起；
//! - `S = GHASH_H(A‖0^v‖C‖0^u‖[len(A)]64‖[len(C)]64)`，本库 `A` 为空；
//! - `T = E_K(J0) ⊕ S`（128 位 tag）；验签恒时比较、先验后解。
//!
//! 定值测试（KAT）用 RFC 8998 附录 A.1 的 SM4-GCM 向量逐字节对齐——
//! GB/T 38636-2020 附录 A 只有模式定义（算法 4 / 5），未附数值向量。

use ctr::Ctr32BE;
use ctr::cipher::{Block, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use ghash::GHash;
use ghash::universal_hash::UniversalHash;
use rand_core::{OsRng, RngCore};
use sm4::Sm4;

use crate::contract::{Identified, SymmetricCipher};
use crate::error::{Error, Result};
use crate::key::Key;

const LABEL: &str = "SM4-GCM";
const PREFIX: &[u8] = b"v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// SM4-GCM 加密器。
#[derive(Debug)]
pub struct Sm4GcmEncryptor {
    key: Key<16>,
}

impl Sm4GcmEncryptor {
    pub const IDENTIFIER: &'static str = "sm4-gcm";

    pub fn new(key: [u8; 16]) -> Self {
        Self { key: Key::new(key) }
    }

    pub fn from_slice(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Key::from_slice(key, LABEL)?,
        })
    }

    /// 固定 nonce 加密（仅测试用），返回与 [`SymmetricCipher::encrypt`] 相同的整帧。
    #[cfg(test)]
    pub(crate) fn encrypt_with_nonce(&self, nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
        let (ciphertext, tag) = seal(self.key.as_bytes(), nonce, b"", plaintext);
        pack(nonce, &tag, &ciphertext)
    }
}

impl Identified for Sm4GcmEncryptor {
    fn identifier(&self) -> &str {
        Self::IDENTIFIER
    }
}

impl SymmetricCipher for Sm4GcmEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let (ciphertext, tag) = seal(self.key.as_bytes(), &nonce, b"", plaintext);
        Ok(pack(&nonce, &tag, &ciphertext))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let body = ciphertext
            .strip_prefix(PREFIX)
            .ok_or(Error::InvalidPrefix { label: LABEL })?;
        if body.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::TooShort { label: LABEL });
        }

        let (nonce, rest) = body.split_at(NONCE_LEN);
        let (tag, ct) = rest.split_at(TAG_LEN);
        let nonce: &[u8; NONCE_LEN] = nonce.try_into().expect("length was verified");
        let tag: &[u8; TAG_LEN] = tag.try_into().expect("length was verified");

        open(self.key.as_bytes(), nonce, b"", ct, tag)
            .ok_or(Error::DecryptionFailed { label: LABEL })
    }
}

/// 整帧组装：`v1 | nonce(12) | tag(16) | 密文`。
fn pack(nonce: &[u8; NONCE_LEN], tag: &[u8; TAG_LEN], ciphertext: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(PREFIX.len() + NONCE_LEN + TAG_LEN + ciphertext.len());
    blob.extend_from_slice(PREFIX);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(tag);
    blob.extend_from_slice(ciphertext);
    blob
}

/// SM4 实例；密钥长度在构造侧已保证为 16 字节。
fn sm4_cipher(key: &[u8; 16]) -> Sm4 {
    Sm4::new_from_slice(key).expect("SM4 key length is fixed at 16")
}

/// `E_K(J0)`：tag 的掩码（`T = E_K(J0) ⊕ S`）。J0 = nonce‖0^31‖1。
fn j0_mask(cipher: &Sm4, nonce: &[u8; NONCE_LEN]) -> [u8; 16] {
    let mut j0 = [0u8; 16];
    j0[..NONCE_LEN].copy_from_slice(nonce);
    j0[15] = 1;
    cipher.encrypt_block(Block::<Sm4>::from_mut_slice(&mut j0));
    j0
}

/// CTR 起始计数器块 `inc32(J0)`：J0 的 32 位计数字为 1，GCTR 自其 +1 起。
fn ctr_start_block(nonce: &[u8; NONCE_LEN]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..NONCE_LEN].copy_from_slice(nonce);
    block[15] = 2; // inc32(J0)
    block
}

/// GHASH 状态：喂入 A（零填充）、C（零填充）与 128 位长度块
/// （`[len(A)]64‖[len(C)]64`，比特数，大端）。
fn ghash_state(cipher: &Sm4, aad: &[u8], ciphertext: &[u8]) -> GHash {
    let mut h = ghash::Key::default();
    cipher.encrypt_block(&mut h);

    let mut state = GHash::new(&h);
    state.update_padded(aad);
    state.update_padded(ciphertext);

    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(8 * aad.len() as u64).to_be_bytes());
    lengths[8..].copy_from_slice(&(8 * ciphertext.len() as u64).to_be_bytes());
    state.update(&[lengths.into()]);
    state
}

/// GCM-AEK（GB/T 38636-2020 附录 A 算法 4）：返回（密文, tag）。
fn seal(
    key: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let cipher = sm4_cipher(key);

    // ponytail: apply_keystream 在密钥流耗尽（约 2^36 字节）时 panic；能驻留
    // 内存的单次载荷远达不到该上限，真要分片加密时改走 try_apply_keystream。
    let mut ciphertext = plaintext.to_vec();
    Ctr32BE::<Sm4>::new_from_slices(key, &ctr_start_block(nonce))
        .expect("key and counter lengths are fixed")
        .apply_keystream(&mut ciphertext);

    let mask = j0_mask(&cipher, nonce);
    let s = ghash_state(&cipher, aad, &ciphertext).finalize();
    let mut tag = [0u8; TAG_LEN];
    for ((byte, m), s) in tag.iter_mut().zip(mask.iter()).zip(s.iter()) {
        *byte = m ^ s;
    }
    (ciphertext, tag)
}

/// GCM-ADK（GB/T 38636-2020 附录 A 算法 5）：tag 不符返回 `None`
/// （恒时比较，不向前端泄露「哪一步错了」）。先验 tag，通过后才解密。
fn open(
    key: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Option<Vec<u8>> {
    let cipher = sm4_cipher(key);

    // 期望的 GHASH 输出 S = T ⊕ E_K(J0)（由 T = E_K(J0) ⊕ S 移项）。
    let mask = j0_mask(&cipher, nonce);
    let mut expected = [0u8; TAG_LEN];
    for ((byte, t), m) in expected.iter_mut().zip(tag.iter()).zip(mask.iter()) {
        *byte = t ^ m;
    }
    ghash_state(&cipher, aad, ciphertext)
        .verify(Block::<GHash>::from_slice(&expected))
        .ok()?;

    let mut plaintext = ciphertext.to_vec();
    Ctr32BE::<Sm4>::new_from_slices(key, &ctr_start_block(nonce))
        .expect("key and counter lengths are fixed")
        .apply_keystream(&mut plaintext);
    Some(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 十六进制常量 → 定长数组（逐字节对齐 KAT 用）。
    fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
        crate::internal::hex_decode(hex)
            .unwrap()
            .try_into()
            .unwrap()
    }

    /// RFC 8998 附录 A.1 的 SM4-GCM 向量（IETF，权威）：
    /// <https://www.rfc-editor.org/rfc/rfc8998.txt>。GB/T 38636-2020 附录 A
    /// 给出同一组装（A.1.3.5 GCTR、A.1.4.1 GCM-AEK），但不含数值向量。
    const KAT_KEY: &str = "0123456789abcdeffedcba9876543210";
    const KAT_NONCE: &str = "00001234567800000000abcd";
    const KAT_PLAINTEXT: &str = concat!(
        "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB",
        "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD",
        "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF",
        "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA"
    );
    const KAT_AAD: &str = "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2";
    const KAT_CIPHERTEXT: &str = concat!(
        "17F399F08C67D5EE19D0DC9969C4BB7D",
        "5FD46FD3756489069157B282BB200735",
        "D82710CA5C22F0CCFA7CBF93D496AC15",
        "A56834CBCF98C397B4024A2691233B8D"
    );
    const KAT_TAG: &str = "83DE3541E4C2B58177E065A9BF7B62EC";

    #[test]
    fn rfc8998_kat_with_aad_is_byte_exact() {
        // 完整向量（含 20 字节 AAD）：密文与 tag 都要逐字节一致。
        let key: [u8; 16] = hex_array(KAT_KEY);
        let nonce: [u8; 12] = hex_array(KAT_NONCE);
        let plaintext: [u8; 64] = hex_array(KAT_PLAINTEXT);
        let aad: [u8; 20] = hex_array(KAT_AAD);
        let expected_ciphertext: [u8; 64] = hex_array(KAT_CIPHERTEXT);
        let expected_tag: [u8; 16] = hex_array(KAT_TAG);

        let (ciphertext, tag) = seal(&key, &nonce, &aad, &plaintext);
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        // 解密侧同样对齐：正确 tag 通过、改一位即拒绝。
        let plaintext_back = open(&key, &nonce, &aad, &ciphertext, &tag).unwrap();
        assert_eq!(plaintext_back, plaintext);

        let mut tampered = expected_tag;
        tampered[0] ^= 0x01;
        assert_eq!(open(&key, &nonce, &aad, &ciphertext, &tampered), None);
    }

    #[test]
    fn rfc8998_ciphertext_matches_with_empty_aad() {
        // AAD 不参与 GCTR：本库公开 API 约定（空 AAD）产出的密文应与
        // RFC 8998 向量逐字节一致；tag 因 AAD 不同而不同，不做数值断言，
        // 改用「同帧能自洽解密」验证。
        let encryptor = Sm4GcmEncryptor::new(hex_array(KAT_KEY));
        let nonce: [u8; 12] = hex_array(KAT_NONCE);
        let plaintext: [u8; 64] = hex_array(KAT_PLAINTEXT);
        let expected_ciphertext: [u8; 64] = hex_array(KAT_CIPHERTEXT);

        let frame = encryptor.encrypt_with_nonce(&nonce, &plaintext);
        assert_eq!(&frame[..2], PREFIX);
        assert_eq!(&frame[2..14], &nonce);
        assert_eq!(&frame[30..], &expected_ciphertext[..]);
        assert_eq!(encryptor.decrypt(&frame).unwrap(), plaintext);
    }

    #[test]
    fn roundtrip_and_tamper_detection() {
        let encryptor = Sm4GcmEncryptor::new([7u8; 16]);
        for plaintext in [
            b"".as_slice(),
            b"plain",
            b"0123456789abcdef",
            &[0u8; 64][..],
        ] {
            let blob = encryptor.encrypt(plaintext).unwrap();
            assert_eq!(blob.len(), 2 + NONCE_LEN + TAG_LEN + plaintext.len());
            assert_eq!(encryptor.decrypt(&blob).unwrap(), plaintext);
        }

        // 密文被改。
        let mut blob = encryptor.encrypt(b"data").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert_eq!(
            encryptor.decrypt(&blob).unwrap_err(),
            Error::DecryptionFailed { label: LABEL }
        );

        // tag 被改。
        let mut blob = encryptor.encrypt(b"data").unwrap();
        blob[2 + NONCE_LEN] ^= 0x01;
        assert_eq!(
            encryptor.decrypt(&blob).unwrap_err(),
            Error::DecryptionFailed { label: LABEL }
        );
    }

    #[test]
    fn every_encrypt_uses_a_fresh_nonce() {
        let encryptor = Sm4GcmEncryptor::new([7u8; 16]);
        let first = encryptor.encrypt(b"same").unwrap();
        let second = encryptor.encrypt(b"same").unwrap();
        assert_ne!(first, second);
        assert_ne!(first[2..14], second[2..14]);
    }

    #[test]
    fn wrong_key_and_bad_frame_fail() {
        let blob = Sm4GcmEncryptor::new([7u8; 16]).encrypt(b"x").unwrap();
        let other = Sm4GcmEncryptor::new([8u8; 16]);
        assert_eq!(
            other.decrypt(&blob).unwrap_err(),
            Error::DecryptionFailed { label: LABEL }
        );
        assert_eq!(
            other.decrypt(b"v9....").unwrap_err(),
            Error::InvalidPrefix { label: LABEL }
        );
        assert_eq!(
            other.decrypt(b"v1short").unwrap_err(),
            Error::TooShort { label: LABEL }
        );
    }

    #[test]
    fn key_length_is_checked() {
        assert_eq!(
            Sm4GcmEncryptor::from_slice(&[0u8; 32]).unwrap_err(),
            Error::InvalidKeyLength {
                label: LABEL,
                expected: 16,
                got: 32
            }
        );
    }

    #[test]
    fn identifier_matches_registered_name() {
        assert_eq!(Sm4GcmEncryptor::new([0u8; 16]).identifier(), "sm4-gcm");
    }
}
