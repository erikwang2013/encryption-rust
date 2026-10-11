// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 已知答案向量（KAT）：用**独立参考实现**生成的密文反证本库的解密路径。
//!
//! 对称族向量的密文由 PHP 8.5.6（本机，openssl + sodium 扩展）生成后硬编码为十六进制；
//! SM2 向量取自 OpenSSL 官方测试文件中的 GM/T 0003.5-2012 附录 C 示例（见文末）；
//! Rust 侧只做解密断言 —— 加密用随机 IV / Nonce，方向无法逐字节比对。
//!
//! 生成脚本（一次性执行，载荷 29 字节，密钥为可读序列 `00 01 … 1f` / `00 … 0f`）：
//!
//! ```php
//! $pt = "KAT vector 已知答案向量";
//! $k32 = pack('C*', ...range(0x00, 0x1f));
//! $k16 = pack('C*', ...range(0x00, 0x0f));
//!
//! // 1. AES-256-GCM：blob = v1 | iv(12) | tag(16) | ct
//! $iv12 = pack('C*', ...range(0xa0, 0xab));
//! $tag = '';
//! $ct = openssl_encrypt($pt, 'aes-256-gcm', $k32, OPENSSL_RAW_DATA, $iv12, $tag, '', 16);
//! echo bin2hex('v1' . $iv12 . $tag . $ct), PHP_EOL;
//!
//! // 2. XChaCha20-Poly1305：blob = v1 | nonce(24) | ct||tag(16)
//! $n24 = pack('C*', ...range(0xc0, 0xd7));
//! $cttag = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($pt, '', $n24, $k32);
//! echo bin2hex('v1' . $n24 . $cttag), PHP_EOL;
//!
//! // 3. AES-256-CBC + HMAC-SHA256：blob = v1 | iv(16) | mac(32) | ct
//! $iv16 = pack('C*', ...range(0xb0, 0xbf));
//! $ct  = openssl_encrypt($pt, 'aes-256-cbc', $k32, OPENSSL_RAW_DATA, $iv16);
//! $mk  = hash_hmac('sha256', 'dgn:enc:hmac', $k32, true);   // mac_key
//! $mac = hash_hmac('sha256', $iv16 . $ct, $mk, true);
//! echo bin2hex('v1' . $iv16 . $mac . $ct), PHP_EOL;
//!
//! // 4. SM4-CBC + HMAC-SHA256（密钥 16 字节；本机 PHP 的 openssl_get_cipher_methods()
//! //    含 'sm4-cbc'，支持）：布局同 3，key 换 $k16。
//! ```
//!
//! **范围说明**：这些向量钉住的是「本库的载荷格式与密码学原语与参考实现一致」
//! （同一密钥 / IV 下能解开参考实现产出的密文），**不是**与 PHP 版 `encryption`
//! 包的字节级互通承诺 —— PHP 包的子密钥派生（主密钥 → 各用途密钥）与本库的
//! `factory` 不同，两条链路整体并不互通（见 lib.rs 与 README「与原版的差异」）。

use encryption::contract::SymmetricCipher;
use encryption::encryptor::{Aes256CbcEncryptor, Aes256GcmEncryptor, SodiumXChaCha20Encryptor};
use encryption::guomi::{Sm2Service, Sm4CbcEncryptor};

/// 每条向量共用的明文（29 字节，含中英文字节）。
const PLAINTEXT: &[u8] = "KAT vector 已知答案向量".as_bytes();

/// 32 字节密钥：`00 01 02 … 1f`。
fn key32() -> [u8; 32] {
    std::array::from_fn(|i| i as u8)
}

/// 16 字节密钥：`00 01 02 … 0f`。
fn key16() -> [u8; 16] {
    std::array::from_fn(|i| i as u8)
}

/// 解析十六进制字面量（奇数位或非 hex 字符即 panic，用于钉住字面量本身）。
fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex 字面量长度必须为偶数");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("非 hex 字符"))
        .collect()
}

/// AES-256-GCM：`v1 | IV(a0..ab) | Tag | 密文`，PHP `openssl_encrypt(..., 'aes-256-gcm', ...)` 产出。
const GCM_BLOB: &str = concat!(
    "7631a0a1a2a3a4a5a6a7a8a9aaabf3cc402e603216440b88169c67215267ad59",
    "280d33ae61cb0d17a736b0c82741d54bf4847416ca890c9fcf01f0",
);

#[test]
fn aes256gcm_decrypts_php_openssl_vector() {
    let plaintext = Aes256GcmEncryptor::new(key32())
        .decrypt(&hex(GCM_BLOB))
        .expect("参考实现密文应能解开");
    assert_eq!(plaintext, PLAINTEXT);
}

#[test]
fn aes256gcm_rejects_tampered_reference_vector() {
    // 反向断言（只挑一个算法做）：翻转密文最后一字节，认证必然失败。
    let mut blob = hex(GCM_BLOB);
    *blob.last_mut().unwrap() ^= 0x01;
    assert!(Aes256GcmEncryptor::new(key32()).decrypt(&blob).is_err());
}

/// XChaCha20-Poly1305：`v1 | Nonce(c0..d7) | 密文‖Tag`，PHP sodium 扩展产出。
const XCHACHA_BLOB: &str = concat!(
    "7631c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7bbdfdef3ea73",
    "f6e78ab1fa12e3daca2f07eae6c76a193286c881702be11e65dc1e574eb2e087",
    "a5ae5b0adb57b2",
);

#[test]
fn xchacha20_decrypts_php_sodium_vector() {
    let plaintext = SodiumXChaCha20Encryptor::new(key32())
        .decrypt(&hex(XCHACHA_BLOB))
        .expect("参考实现密文应能解开");
    assert_eq!(plaintext, PLAINTEXT);
}

/// AES-256-CBC + HMAC-SHA256：`v1 | IV(b0..bf) | MAC | 密文`。
const CBC_BLOB: &str = concat!(
    "7631b0b1b2b3b4b5b6b7b8b9babbbcbdbebf1c25467a7b8847b6fa1614b62962",
    "5f5f00d63a92a853b3a4716d9f3eda2669ecd3cb1667b54049dbb6248771dfaf",
    "0acfdb6696cb161e360d7a69fd8a63c4f469",
);

#[test]
fn aes256cbc_hmac_decrypts_php_openssl_vector() {
    let plaintext = Aes256CbcEncryptor::new(key32())
        .decrypt(&hex(CBC_BLOB))
        .expect("参考实现密文应能解开");
    assert_eq!(plaintext, PLAINTEXT);
}

/// SM4-CBC + HMAC-SHA256：`v1 | IV(b0..bf) | MAC | 密文`，密钥 16 字节。
const SM4_BLOB: &str = concat!(
    "7631b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc4ad1603f3268200e5ed6c2a6d1d",
    "5289c92714cb7692d682ca598b799ac6d395d8cdf2fd7df48ec92704a8e3ae9f",
    "682f823842b0e5937b8506a917b329e34dfa",
);

#[test]
fn sm4cbc_decrypts_php_openssl_vector() {
    // 本机 PHP 8.5.6 的 openssl_get_cipher_methods() 含 'sm4-cbc'，向量已生成；
    // 若换到不含 sm4 的 PHP 环境，请用生成脚本重现该十六进制后再断言。
    let plaintext = Sm4CbcEncryptor::new(key16())
        .decrypt(&hex(SM4_BLOB))
        .expect("参考实现密文应能解开");
    assert_eq!(plaintext, PLAINTEXT);
}

/// SM2 公钥加解密互通向量：**GM/T 0003.5-2012 附录 C**（同 GB/T 32918.5-2016）
/// 公钥加密示例（明文 `"encryption standard"`），取自 OpenSSL 官方测试文件
/// [`test/sm2_internal_test.c`](https://github.com/openssl/openssl/blob/master/test/sm2_internal_test.c)
/// 的 `sm2_crypt_test`，其注释标注 "From Annex C in both GM/T0003.5-2012 and
/// GB/T 32918.5-2016"。
///
/// **序列化转换**：OpenSSL 给出的密文是 GM/T 0009-2012 第 7.2 节的 ASN.1 形式
/// （`SEQUENCE { INTEGER x, INTEGER y, OCTET STRING C3, OCTET STRING C2 }`），
/// 与本库消费的原始布局 `C1‖C3‖C2` 不同，此处按下述方式转换后写入：
///
/// - 去掉 `SEQUENCE` / `INTEGER` / `OCTET STRING` 的 DER 头；
/// - `y` 在原 DER 中带一个前导 `00`（正整数的 DER 填充位），转换时去掉；
/// - `C1 = 04 ‖ x ‖ y`（非压缩点，65 字节），其后依次拼接 `C3`（32 字节）
///   与 `C2`（19 字节）。
///
/// 私钥 `d`、明文与临时密钥 `k` 均取自同一出处（`d` 为
/// `3945208F…C5B8`，`k` 为 `59276E27…BC21`）。转换结果已逐个复算比对后才写入：
/// `C1 = k·G`，且 `C3 = SM3(x2‖M‖y2)`、`C2 = M ⊕ KDF(x2‖y2)`（`(x2,y2) = k·P_B`）
/// 经独立 Python 实现复现，与 OpenSSL 字节一致。
const SM2_ANNEX_C_CIPHERTEXT: &str = concat!(
    "04",                                                               // C1：非压缩点标记
    "04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73", // X
    "E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0", // Y
    "59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766", // C3 = SM3(x2‖M‖y2)
    "21886CA989CA9C7D58087307CA93092D651EFA",                           // C2
);

#[test]
fn sm2_decrypts_gmt0003_annex_c_openssl_vector() {
    const PRIVATE_KEY: &str = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";

    // 116 字节 = C1(65) + C3(32) + C2(19)，钉住字面量本身的布局。
    assert_eq!(SM2_ANNEX_C_CIPHERTEXT.len(), 2 * 116);

    let plaintext = Sm2Service::decrypt(SM2_ANNEX_C_CIPHERTEXT, PRIVATE_KEY)
        .expect("GM/T 0003.5 附录 C 密文应能解开");
    assert_eq!(plaintext, b"encryption standard");
}
