// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! criterion 基准：对比**本库封装**与**裸 crate** 的开销（各 1 KiB 明文）。
//!
//! - `aes256gcm/*`：`encryption::encryptor::Aes256GcmEncryptor` 对比裸 `aes-gcm`
//!   的 `Aead::encrypt` —— 差值即封装成本（前缀 / 随机 IV / 载荷拼装 / 错误映射）。
//! - `sodium-xchacha20/*`：本库封装（纯 Rust 实现）的加密吞吐。
//!
//! 明文 1 KiB、密钥 / IV 固定值；封装走公开 API（内部随机 IV），与使用者路径一致。

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use encryption::contract::SymmetricCipher;
use encryption::encryptor::{Aes256GcmEncryptor, SodiumXChaCha20Encryptor};

const KEY: [u8; 32] = [0x11; 32];
const IV: [u8; 12] = [0x22; 12];
const PLAINTEXT_LEN: usize = 1024;

fn plaintext() -> Vec<u8> {
    (0..PLAINTEXT_LEN).map(|i| (i % 251) as u8).collect()
}

fn bench_encrypt(c: &mut Criterion) {
    let plaintext = plaintext();
    let wrapper = Aes256GcmEncryptor::new(KEY);
    let xchacha = SodiumXChaCha20Encryptor::new(KEY);
    let raw = Aes256Gcm::new_from_slice(&KEY).expect("32 字节密钥");
    let nonce = Nonce::from_slice(&IV);

    c.bench_function("aes256gcm/encrypt/1KiB (wrapper)", |b| {
        b.iter(|| wrapper.encrypt(black_box(&plaintext)).unwrap())
    });
    c.bench_function("aes256gcm/encrypt/1KiB (raw aes-gcm)", |b| {
        b.iter(|| raw.encrypt(nonce, black_box(plaintext.as_slice())).unwrap())
    });
    c.bench_function("sodium-xchacha20/encrypt/1KiB (wrapper)", |b| {
        b.iter(|| xchacha.encrypt(black_box(&plaintext)).unwrap())
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let plaintext = plaintext();
    let wrapper = Aes256GcmEncryptor::new(KEY);
    let blob = wrapper.encrypt(&plaintext).unwrap();
    let raw = Aes256Gcm::new_from_slice(&KEY).expect("32 字节密钥");
    let raw_blob = raw
        .encrypt(Nonce::from_slice(&IV), plaintext.as_slice())
        .unwrap();

    c.bench_function("aes256gcm/decrypt/1KiB (wrapper)", |b| {
        b.iter(|| wrapper.decrypt(black_box(&blob)).unwrap())
    });
    c.bench_function("aes256gcm/decrypt/1KiB (raw aes-gcm)", |b| {
        b.iter(|| {
            raw.decrypt(Nonce::from_slice(&IV), black_box(raw_blob.as_slice()))
                .unwrap()
        })
    });
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
