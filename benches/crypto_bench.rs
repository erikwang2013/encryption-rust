// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! criterion 基准：对比**本库封装**与**裸 crate** 的开销。
//!
//! 三个基准组分别回答三个不同的问题：
//!
//! - `wrapper-vs-raw/*`：封装成本是多少。两组基线都**在计时闭包内**构造 cipher，
//!   否则「循环外预建 vs 循环内重建」的密钥扩展开销会被误记成封装开销——
//!   早先的版本正是如此（裸 crate 建在 `b.iter()` 外、封装每次调用内部重建），
//!   于是 190–230 ns/次 的密钥扩展被当成「封装差价」藏了起来。
//! - `short-payload/*`：库的实际用例是**短载荷**（手机号一类 11 字节）。1 KiB 上
//!   固定成本会被摊薄到看不见，短载荷才暴露每调用的常数项（随机 IV、密钥扩展、
//!   帧拼装）。11 字节与 1 KiB 并列。
//! - `etm/*` 与 `hex/*`：encrypt-then-MAC 那一族与十六进制边界各自的成本。
//!
//! 明文 / 密钥为定值；封装一律走公开 API（内部每次生成新 IV），与使用者路径一致。

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use encryption::contract::SymmetricCipher;
use encryption::encryptor::{Aes256CbcEncryptor, Aes256GcmEncryptor, SodiumXChaCha20Encryptor};

const KEY: [u8; 32] = [0x11; 32];
const IV: [u8; 12] = [0x22; 12];
/// 短载荷：本库的主用例（手机号 / 身份证号 / 银行卡号）。
const SHORT_LEN: usize = 11;
/// 长载荷：摊薄固定成本后的吞吐。
const LONG_LEN: usize = 1024;

fn payload(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i % 251) as u8).collect()
}

/// 封装 vs 裸 crate：两组基线都必须在计时闭包内建 cipher 才是同类比较。
fn bench_wrapper_vs_raw(c: &mut Criterion) {
    let mut group = c.benchmark_group("wrapper-vs-raw/aes-256-gcm/11B");

    let wrapper = Aes256GcmEncryptor::new(KEY);
    let short = payload(SHORT_LEN);
    let nonce = Nonce::from_slice(&IV);

    group.bench_function("wrapper (fresh IV per call)", |b| {
        b.iter(|| wrapper.encrypt(black_box(&short)).unwrap())
    });
    // 基线：cipher 与 nonce 都固定，隔离出纯粹「帧拼装 + 错误映射」的成本。
    group.bench_function("raw aes-gcm (fixed nonce)", |b| {
        b.iter(|| {
            let cipher = Aes256Gcm::new_from_slice(&KEY).expect("32 字节密钥");
            cipher
                .encrypt(nonce, black_box(short.as_slice()))
                .expect("11 字节明文")
        })
    });

    let blob = wrapper.encrypt(&short).unwrap();
    let raw_blob = Aes256Gcm::new_from_slice(&KEY)
        .expect("32 字节密钥")
        .encrypt(nonce, short.as_slice())
        .expect("11 字节明文");

    group.bench_function("wrapper decrypt", |b| {
        b.iter(|| wrapper.decrypt(black_box(&blob)).unwrap())
    });
    group.bench_function("raw aes-gcm decrypt", |b| {
        b.iter(|| {
            let cipher = Aes256Gcm::new_from_slice(&KEY).expect("32 字节密钥");
            cipher
                .decrypt(nonce, black_box(raw_blob.as_slice()))
                .expect("tag 正确")
        })
    });

    group.finish();
}

/// 短载荷 vs 长载荷：暴露每调用的固定开销。
fn bench_payload_length(c: &mut Criterion) {
    let mut group = c.benchmark_group("short-payload/aes-256-gcm");
    let wrapper = Aes256GcmEncryptor::new(KEY);

    for length in [SHORT_LEN, 64, LONG_LEN] {
        let plaintext = payload(length);
        group.bench_with_input(
            BenchmarkId::new("encrypt", format!("{length}B")),
            &plaintext,
            |b, plaintext| b.iter(|| wrapper.encrypt(black_box(plaintext.as_slice())).unwrap()),
        );
    }
    group.finish();

    let mut group = c.benchmark_group("short-payload/sodium-xchacha20");
    let xchacha = SodiumXChaCha20Encryptor::new(KEY);
    for length in [SHORT_LEN, LONG_LEN] {
        let plaintext = payload(length);
        group.bench_with_input(
            BenchmarkId::new("encrypt", format!("{length}B")),
            &plaintext,
            |b, plaintext| b.iter(|| xchacha.encrypt(black_box(plaintext.as_slice())).unwrap()),
        );
    }
    group.finish();
}

/// encrypt-then-MAC 一族：CBC + HMAC 的每调用成本（含 MAC 派生与校验）。
fn bench_etm(c: &mut Criterion) {
    let mut group = c.benchmark_group("etm/aes-256-cbc-hmac/1KiB");
    let cipher = Aes256CbcEncryptor::new(KEY);
    let plaintext = payload(LONG_LEN);
    let blob = cipher.encrypt(&plaintext).unwrap();

    group.bench_function("encrypt", |b| {
        b.iter(|| cipher.encrypt(black_box(plaintext.as_slice())).unwrap())
    });
    group.bench_function("decrypt", |b| {
        b.iter(|| cipher.decrypt(black_box(blob.as_slice())).unwrap())
    });
    group.finish();
}

/// 十六进制边界。库内部用不用 `hex` crate 是内部决定，这里只从公开 API 计时：
///
/// - **编码**：`digest_hex` 与 `digest` 的差额就是这一次十六进制编码的成本；
/// - **解码**：`hex_decode` 是 `pub(crate)`，公开路径上最大的解码面是密钥协商 /
///   签名验签——它们每次调用都把十六进制私钥与公钥解析成字节点。用
///   `x25519.agree` 端到端计时，解析成本包含在内。
fn bench_hex(c: &mut Criterion) {
    use encryption::asymmetric::x25519::X25519Agreement;
    use encryption::contract::{Hasher, KeyAgreement};
    use encryption::hash::Sha256Hasher;

    let mut group = c.benchmark_group("hex");
    let hasher = Sha256Hasher::new();
    let data = payload(LONG_LEN);

    group.bench_function("sha256/digest/1KiB", |b| {
        b.iter(|| hasher.digest(black_box(data.as_slice())).unwrap())
    });
    group.bench_function(
        "sha256/digest_hex/1KiB (=digest+hex_encode 64 chars)",
        |b| b.iter(|| hasher.digest_hex(black_box(data.as_slice())).unwrap()),
    );

    // 解码路径：每次调用解析两段 32 字节十六进制（64 字符）。
    let agreement = X25519Agreement::new();
    let alice = X25519Agreement::generate_key_pair_hex().unwrap();
    let bob = X25519Agreement::generate_key_pair_hex().unwrap();
    group.bench_function("x25519/agree (2x hex_decode 32B + DH)", |b| {
        b.iter(|| {
            agreement
                .agree(
                    black_box(&alice.private_key_hex),
                    black_box(&bob.public_key_hex),
                )
                .unwrap()
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_wrapper_vs_raw,
    bench_payload_length,
    bench_etm,
    bench_hex
);
criterion_main!(benches);
