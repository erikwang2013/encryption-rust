<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# encryption-rust

**Languages:** [简体中文](../../../README.md) | **English**

<p align="center">
  <img src="../../pet.svg" alt="Project pet Locky: a little padlock holding a golden key" width="150" height="150">
</p>

A pluggable cryptography component library: under a unified set of contracts it provides **symmetric encryption**, **asymmetric encryption**, **hashing**, and **key derivation** (HKDF / PBKDF2), with implementations covering AES/Sodium and the Chinese national standards SM2/SM3/SM4/ZUC — installed through Cargo.

**Locky** is the little padlock above, and this project's pet: every algorithm holds its own subkey, every encryption uses a fresh IV, and the keyhole never gives away a secret. Host projects can show it too: `pet::SVG` returns the SVG markup (ready to inline into HTML), `pet::ASCII` returns a terminal banner, and `pet::NAME` is `Locky`.

A Rust port of the PHP package [`erikwang2013/encryption`](https://github.com/erikwang2013/encryption).

---

## Project pet: Locky

<img src="../../pet.svg" alt="Locky — the encryption-rust project pet" width="340">

A little padlock holding a golden key. The persona is not decoration — it draws this library's design:

| Trait | Design it reflects |
|------|---------|
| The keyhole (a smile) | Key / IV discipline: the keyhole never reveals what it has seen — keys and plaintext never leak |
| The golden key in the other hand | Master key: `EncryptionManagerFactory::from_master_key` derives each algorithm's subkey from it |
| A lock opens only for its own key | Authenticated encryption: if GCM / encrypt-then-MAC fails to decrypt, the key is wrong or the ciphertext was tampered with — there is no third explanation |
| One subkey per algorithm | Under one master key, AES and SM4/ZUC share no key material, avoiding key reuse |

Motto: **the keyhole never gives away a secret.**

The artwork is compiled into the library with `include_str!` ([`src/pet.rs`](../../../src/pet.rs) — zero runtime cost, not linked unless used), and `pet::ASCII` can go straight into a terminal or a log:

```rust
use encryption::pet;

println!("{}", pet::ASCII);

//      .-------.
//      /       \
//   .-------------.
//   |  o       o  |
//   |             |
//   |     ,-.     |
//   |    (   )    |
//   |     '-'     |
//   |      |      |
//   '-------------'
```

Four constants are public — `pet::NAME` / `pet::TAGLINE` / `pet::ASCII` / `pet::SVG` — shared by the README, CLI banners, and downstream admin UIs.

`docs/pet.svg` **must not** go into Cargo's `exclude` — `include_str!` reads it at compile time, so excluding it fails the build on the spot (`cargo package` errors out rather than silently shipping without it).

---

## About the project

### What it is

`encryption-rust` is a pure-Rust cryptography component library that gives Rust applications **type-safe, extensible** encryption, decryption, hashing, and key derivation. It is coupled to no framework: use it inside web frameworks such as axum or actix-web, or standalone in a plain library or CLI project.

### What it solves

Cryptographic building blocks in the Rust ecosystem have long been scattered: AES via `aes-gcm`, stream ciphers via `chacha20poly1305`, the Chinese national standards spread across separate crates (sm2 / sm3 / sm4 / zuc), and no unified interface for HKDF / PBKDF2. This library gathers the mainstream symmetric / asymmetric / hash / KDF algorithms under a **single contract system**, so that:

- **business code only ever faces interfaces** — switching algorithms does not change business code
- **the Chinese national standards get equal treatment with AES/Sodium** — once registered, they are called through the same Manager
- **key management is normalized**: one call derives each algorithm's subkey from the master key, avoiding key reuse
- **secure defaults**: authenticated encryption (GCM / encrypt-then-MAC), random IVs, constant-time comparison, and more — out of the box

### Use cases

- Field-level encryption (encrypt phone numbers, ID numbers, and other sensitive fields before they hit the database)
- Running several algorithms side by side and migrating smoothly (e.g. from AES-256-CBC to AES-256-GCM)
- Back-office systems that require Chinese national standard (Guomi) compliance (SM2 asymmetric, SM3 hash, SM4 symmetric, ZUC stream cipher)
- API signing and verification (HMAC / SHA-256 / SM3)
- Subkey derivation from a password or master key (PBKDF2 / HKDF)

---

## Features

- **Five capability families, one shape**: symmetric encryption / asymmetric encryption / hashing / key derivation / password-based derivation — each family follows the same contract (trait) → registry (Registry) → facade (Manager) pattern, so learning one family means learning them all.
- **Ten identifiers out of the box**: `aes-256-gcm`, `sodium-xchacha20`, `aes-256-cbc-hmac`, `sm4-cbc`, `zuc-128`, `sm2`, `sha256`, `sm3`, `hkdf-sha256`, `pbkdf2-sha256` (identical to the PHP version's identifiers — migrating costs zero renames).
- **Master key factory**: `EncryptionManagerFactory::from_master_key` — one 32-byte master key derives an independent subkey per algorithm from purpose labels, assembling every algorithm in one go and ruling out key reuse.
- **Request guard + framework adapters**: native Rust plus 8 opt-in features for axum / actix-web / rocket / poem / salvo / warp / bee-rust / e-cat; declare `Guard` as a handler parameter and encrypt/decrypt right there.
- **Chinese national standards as first-class citizens**: SM2 / SM3 / SM4 / ZUC go through the same register-and-facade path as AES / SHA; SM1 / SM7 / SM9 return an explicit error rather than staying silent.
- **Secure defaults**: random IV / nonce, AEAD or encrypt-then-MAC, constant-time comparison, key material zeroized on Drop, Debug redaction, and no reason disclosed on decryption failure.
- **Pure Rust, zero extension dependencies**: no `ext-sodium` / `ext-gmp`-style prerequisites; ZUC is validated against the GB/T 33133.1 standard test vectors.
- **Docs as design diagrams**: three SVGs — architecture design / functional design / request lifecycle (one set in Chinese, one in English) — plus the pet Locky.
- **Zero framework coupling**: the core library depends on no web framework; every framework integration is optional and none is pulled in by default.

> For the full capability map see [Functional design](#functional-design) below; for the layered structure see [Architecture overview](#architecture-overview).

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Architecture overview](#architecture-overview)
- [Functional design](#functional-design)
- [Request lifecycle](#request-lifecycle)
- [Built-in algorithms and identifiers](#built-in-algorithms-and-identifiers)
- [Usage](#usage)
- [Framework integration (optional features)](#framework-integration-optional-features)
- [Differences from the PHP original](#differences-from-the-php-original)
- [Project layout](#project-layout)
- [FAQ](#faq)
- [Security recommendations](#security-recommendations)
- [Running tests](#running-tests)
- [Reference original project](#reference-original-project)
- [License](#license)

---

## Installation

```bash
cargo add encryption-rust
```

```toml
[dependencies]
encryption-rust = "1.0"
```

## Quick start

```rust
use encryption::factory::EncryptionManagerFactory;

// In production, read a random 32-byte master key from an environment variable / KMS and back it up properly.
let master_key: [u8; 32] = load_master_key();
let manager = EncryptionManagerFactory::from_master_key(&master_key, "aes-256-gcm")?;

// Field-level encryption: the ciphertext is binary; base64 / hex it yourself for TEXT columns.
let stored = manager.encrypt(phone.as_bytes())?;
let phone = manager.decrypt(&stored)?;
```

A complete runnable version lives in [`examples/quickstart.rs`](../../../examples/quickstart.rs): `cargo run --example quickstart` prints the pet ASCII art and walks the full round trip — encrypt → encode → decrypt → tamper detection.

## Architecture overview

![Architecture design: application code → facade → registry → contracts → implementations; plus the master key factory and the request guard](./architecture-design.svg)

Source file: [`architecture-design.svg`](./architecture-design.svg)

Capabilities are split into five groups of contracts, each with the same contract (trait) → registry (Registry) → facade (Manager) shape; `EncryptionManagerFactory` derives every subkey from one master key and assembles the symmetric registry.

| Capability | Contract (trait) | Registry | Facade (default algorithm) |
|------|--------------|--------|------------------|
| Symmetric encryption | `SymmetricCipher` | `Registry<Box<dyn SymmetricCipher>>` | `EncryptionManager` (`aes-256-gcm`) |
| Asymmetric encryption | `AsymmetricCipher` | `Registry<Box<dyn AsymmetricCipher>>` | `AsymmetricCryptoManager` (`sm2`) |
| Hashing | `Hasher` | `Registry<Box<dyn Hasher>>` | `HashingManager` (`sha256`) |
| Key derivation (IKM) | `KeyDerivation` | `Registry<Box<dyn KeyDerivation>>` | `KeyDerivationManager` (`hkdf-sha256`) |
| Password-based derivation | `PasswordBasedKdf` | `Registry<Box<dyn PasswordBasedKdf>>` | `PasswordBasedKdfManager` (`pbkdf2-sha256`) |

- **Symmetric**: an instance is bound to a fixed key; payloads are binary, well suited to field-level bulk encryption.
- **Asymmetric**: key material is passed in on every call (hexadecimal; the format is agreed by the implementation, e.g. SM2).
- **Hashing**: one-way digest, keyless; `digest` returns bytes, `digest_hex` returns hexadecimal.
- **Key derivation**: HKDF expands high-entropy material into subkeys; PBKDF2 stretches human passwords (random salt + a high iteration count).
- **Subkeys**: `HMAC-SHA256(key = master key, msg = purpose label)`; SM4 / ZUC take the first 16 bytes.
- **All five contracts are `Send + Sync`**: implementations can be shared across threads, which is what lets the request guard clone with zero key copies.

## Functional design

![Functional design: six capability families + design principles + secure defaults + extension path](./functional-design.svg)

Source file: [`functional-design.svg`](./functional-design.svg)

| Capability family | Facade | Identifiers shipped with the crate |
|--------|------|---------------------|
| Symmetric encryption | `EncryptionManager` | `aes-256-gcm` / `sodium-xchacha20` / `aes-256-cbc-hmac` / `sm4-cbc` / `zuc-128` |
| Asymmetric encryption | `AsymmetricCryptoManager` | `sm2` (plus the static facade `Sm2Service`) |
| Hashing | `HashingManager` | `sha256` / `sm3` (both 32 bytes) |
| Key derivation (IKM) | `KeyDerivationManager` | `hkdf-sha256` (RFC 5869) |
| Password-based derivation | `PasswordBasedKdfManager` | `pbkdf2-sha256` (310,000 iterations by default) |
| Chinese national standards | the same five facades | `sm2` / `sm3` / `sm4-cbc` / `zuc-128`; SM1 / SM7 / SM9 → explicit error |

Design principles, secure defaults, and the four-step path for "adding an algorithm" are the three blocks on the right of the diagram above; per-algorithm details (key length, payload structure) are under [Built-in algorithms and identifiers](#built-in-algorithms-and-identifiers) below.

## Request lifecycle

![Request lifecycle: configure → derive → register → encrypt → persist → parse → verify → decrypt; plus rotation and failure modes](./lifecycle.svg)

Source file: [`lifecycle.svg`](./lifecycle.svg)

Write path (bootstrapped once per process; the encrypt / decrypt calls that follow are the per-request hot path):

1. **Configure**: the 32-byte random master key comes from an environment variable / KMS and never goes into code;
2. **Derive**: the factory derives a subkey per algorithm from purpose labels; a key is never reused across algorithms;
3. **Register**: each implementation registers under its own `identifier()`, and an unknown identifier errors out explicitly;
4. **Encrypt**: every call generates a fresh random IV / nonce, and authenticated encryption or encrypt-then-MAC packs the record as `v1 | IV | Tag/MAC | ciphertext`.

Read path:

5. **Persist**: binary goes into a BLOB column; for text storage, convert to base64 first;
6. **Parse**: the identifier stored alongside the record decides which implementation to use — after switching the default algorithm, old data still decrypts as usual;
7. **Verify**: check the prefix and length first, then compare the Tag / MAC in constant time; any modified byte is caught right here;
8. **Decrypt**: the plaintext goes back to the caller; on failure no reason is distinguished and no detail leaks to the client.

Key rotation, migration, and every failure variant are in the "Maintenance & failure modes" block at the bottom of the diagram.

## Built-in algorithms and identifiers

### Symmetric encryption (`SymmetricCipher`)

| Identifier | Type | Key length | Payload |
|------|------|----------|------|
| `aes-256-gcm` | `Aes256GcmEncryptor` | 32 bytes | `v1 \| IV(12) \| Tag(16) \| ciphertext`, AES-GCM authenticated encryption, the recommended default |
| `sodium-xchacha20` | `SodiumXChaCha20Encryptor` | 32 bytes | `v1 \| Nonce(24) \| ciphertext‖Tag(16)`, XChaCha20-Poly1305, pure Rust, always available |
| `aes-256-cbc-hmac` | `Aes256CbcEncryptor` | 32 bytes | `v1 \| IV(16) \| MAC(32) \| ciphertext`, CBC + HMAC, compatible with legacy environments |
| `sm4-cbc` | `Sm4CbcEncryptor` | 16 bytes | the same CBC-HMAC structure, Chinese national standard SM4 |
| `zuc-128` | `Zuc128Encryptor` | 16 bytes | the same CBC-HMAC structure, ZUC-128 stream cipher XORed with the keystream |

### Asymmetric encryption (`AsymmetricCipher`)

| Identifier | Type | Notes |
|------|------|------|
| `sm2` | `Sm2AsymmetricCipher` / `Sm2Service` | Chinese national standard SM2; keys and ciphertext are hexadecimal, ciphertext layout C1C3C2 |

### Hashing (`Hasher`)

| Identifier | Type | Output size |
|------|------|----------|
| `sha256` | `Sha256Hasher` | 32 bytes |
| `sm3` | `Sm3Hasher` | 32 bytes |

### Key derivation

| Identifier | Type | Contract | Notes |
|------|------|------|------|
| `hkdf-sha256` | `HkdfSha256` | `KeyDerivation` | RFC 5869, based on IKM + salt + info |
| `pbkdf2-sha256` | `Pbkdf2Sha256` | `PasswordBasedKdf` | password + salt + iteration count (310,000 by default, adjustable through the constructor) |

SM1, SM7, and SM9 have no implementation: calling `guomi::unavailable::sm1()` and friends returns an explicit `UnsupportedNationalAlgorithm` error, so business code can catch it uniformly or wire in a vendor SDK / HSM.

## Usage

### 1. Symmetric encryption: a single algorithm and the registry

```rust
use encryption::encryptor::Aes256GcmEncryptor;
use encryption::manager::EncryptionManager;
use encryption::registry::Registry;
use encryption::contract::SymmetricCipher;

// single algorithm
let key = [7u8; 32];
let encryptor = Aes256GcmEncryptor::new(key);
let blob = encryptor.encrypt(b"\xe6\x98\x8e\xe6\x96\x87")?;
let plaintext = encryptor.decrypt(&blob)?;

// registry + facade
let mut registry = Registry::new("symmetric cipher");
registry.register(Box::new(encryptor));
let manager = EncryptionManager::new(registry, "aes-256-gcm")?;
let blob = manager.encrypt(b"\xe6\x95\xb0\xe6\x8d\xae")?;
```

Master key factory: `EncryptionManagerFactory::from_master_key(&master_key32, "aes-256-gcm")` registers all five algorithms — **aes-256-gcm**, **aes-256-cbc-hmac**, **sodium-xchacha20**, **sm4-cbc**, **zuc-128** — each of them using an independent subkey derived from a purpose label.

### 2. Asymmetric encryption (SM2)

```rust
use encryption::guomi::{Sm2AsymmetricCipher, Sm2Service};
use encryption::manager::AsymmetricCryptoManager;
use encryption::registry::Registry;

let pair = Sm2Service::generate_key_pair_hex()?;   // private key: 64 hex chars; public key: 130 hex chars (04‖X‖Y)

let cipher = Sm2AsymmetricCipher::new();
let ciphertext_hex = cipher.encrypt(b"\xe6\x98\x8e\xe6\x96\x87", &pair.public_key_hex)?;
let plaintext = cipher.decrypt(&ciphertext_hex, &pair.private_key_hex)?;

let mut registry = Registry::new("asymmetric cipher");
registry.register(Box::new(cipher));
let manager = AsymmetricCryptoManager::new(registry, "sm2")?;
let ciphertext_hex = manager.encrypt(b"\xe6\x98\x8e\xe6\x96\x87", &pair.public_key_hex)?;
```

Public keys are accepted in three hexadecimal forms: 130 digits (`04‖X‖Y`), 128 digits (`X‖Y`, with `04` prepended automatically), and 66 digits (compressed point).

### 3. Hashing

```rust
use encryption::guomi::Sm3Hasher;
use encryption::hash::Sha256Hasher;
use encryption::manager::HashingManager;
use encryption::registry::Registry;

let mut registry = Registry::new("hasher");
registry.register(Box::new(Sha256Hasher::new()));
registry.register(Box::new(Sm3Hasher::new()));

let hashing = HashingManager::new(registry, "sha256")?;
let digest = hashing.digest(b"\xe6\x95\xb0\xe6\x8d\xae")?;         // 32 bytes
let hex = hashing.digest_hex_with("sm3", b"\xe6\x95\xb0\xe6\x8d\xae")?; // hexadecimal
```

### 4. Key derivation (HKDF / PBKDF2)

```rust
use encryption::kdf::{HkdfSha256, Pbkdf2Sha256};
use encryption::manager::{KeyDerivationManager, PasswordBasedKdfManager};
use encryption::registry::Registry;

// Derive a subkey from high-entropy material (e.g. a subkey for envelope encryption)
let hkdf = HkdfSha256::new();
let sub_key = hkdf.derive(&ikm32, &salt, 32, b"app:v1")?;

let mut registry = Registry::new("key derivation");
registry.register(Box::new(hkdf));
let kdf = KeyDerivationManager::new(registry, "hkdf-sha256")?;

// Derive a key from a user password (use a dedicated API such as Argon2 for storing password hashes)
let pbkdf2 = Pbkdf2Sha256::with_default_iterations();   // 310,000 iterations, adjustable via new(n)
let derived = pbkdf2.derive_from_password(b"\xe5\x8f\xa3\xe4\xbb\xa4", &salt16, 32)?;

let mut registry = Registry::new("password-based kdf");
registry.register(Box::new(pbkdf2));
let pwd = PasswordBasedKdfManager::new(registry, "pbkdf2-sha256")?;
```

### 5. Chinese national standards (SM3 / SM4 / ZUC / SM2)

```rust
use encryption::guomi::{Sm2Service, Sm3Hasher, Sm4CbcEncryptor, Zuc128Encryptor};
use encryption::contract::{Hasher, SymmetricCipher};

let digest = Sm3Hasher::new().digest(b"\xe6\x95\xb0\xe6\x8d\xae")?;

let sm4 = Sm4CbcEncryptor::new([1u8; 16]);
let blob = sm4.encrypt(b"\xe6\x98\x8e\xe6\x96\x87")?;

let zuc = Zuc128Encryptor::new([2u8; 16]);
let blob = zuc.encrypt(b"\xe6\x98\x8e\xe6\x96\x87")?;

// For SM2 see the asymmetric example above.
```

### 6. Custom plugins

Implement the matching contract and register it — everything else (facade, default-algorithm switching, error semantics) is reused as is:

- Symmetric: implement `SymmetricCipher` and register it in the symmetric registry;
- Asymmetric: implement `AsymmetricCipher` and register it in the asymmetric registry;
- Hashing: implement `Hasher` (only `digest` is required; `digest_hex` has a default implementation);
- KDF: implement `KeyDerivation` or `PasswordBasedKdf` and register it in the matching registry.

```rust
use encryption::contract::{Identified, SymmetricCipher};
use encryption::error::Result;

struct MyCipher { /* ... */ }

impl Identified for MyCipher {
    fn identifier(&self) -> &str { "my-cipher" }
}

impl SymmetricCipher for MyCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> { /* ... */ Ok(plaintext.to_vec()) }
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> { Ok(ciphertext.to_vec()) }
}

manager.registry_mut().register(Box::new(MyCipher { /* ... */ }));
```

### 7. Error handling

On failure the library returns `encryption::error::Error`, with the same stance as the PHP version: a decryption failure is always "wrong key or tampered ciphertext", and no reason is distinguished. Catch and log it in business code, and **do not** pass error details through to the frontend.

```rust
match manager.decrypt(&stored) {
    Ok(plaintext) => { /* ... */ }
    Err(error) => log::warn!("decryption failed: {error}"),
}
```

## Framework integration (optional features)

[`Guard`](../../../src/guard.rs) is a framework-agnostic request guard: internally it is an `Arc<EncryptionManager>`, so cloning it just bumps a reference count and **copies no key material**. One opt-in feature per framework; a default build pulls in none of them.

| feature | Integration |
|---------|---------|
| (native Rust) | `Guard::from_master_key(&key, "aes-256-gcm")`; put it into whatever state container you like |
| `axum` | implements `FromRequestParts`: declare `Guard` as a handler parameter |
| `actix-web` | implements `FromRequest`: register `web::Data::new(guard)` and declare `Guard` as a handler parameter |
| `rocket` | implements `FromRequest` (request guard): `manage(guard)` and declare `Guard` as a handler parameter |
| `poem` | implements `FromRequest`: `.data(guard)` and declare `Guard` as a handler parameter |
| `salvo` | implements `Extractible`: `affix_state::inject(guard)` and declare `Guard` as a handler parameter |
| `warp` | the `with_guard(guard)` combinator plugs into the filter chain |
| `bee-rust` | bee-rust's `Router` takes axum handlers directly, reusing the axum adapter (module: `integrations::bee_rust`) |
| `ecat` | `GuardLayer` (a tower Layer/Service) injects the Guard into request extensions |

A real application's state struct holds more than one encryptor. Make the state implement `Guarded` (just point at the field holding the guard) and every framework's extraction logic can be reused:

```rust
use std::sync::Arc;
use encryption::guard::Guard;
use encryption::integrations::Guarded;

#[derive(Clone)]
struct AppState {
    pool: Arc<()>,          // your connection pool, config, …
    encryption: Guard,      // the encryption guard
}

impl Guarded for AppState {
    fn guard(&self) -> &Guard { &self.encryption }
}

// axum example: declare the guard right in the handler signature
async fn store_phone(guard: Guard) -> String {
    guard.encrypt("13800138000".as_bytes()).unwrap_or_default().len().to_string()
}
```

Forgetting to wire it up (a missing `manage` / `app_data` / `with_state` / `.data(...)`) yields an explicit **500** (a server-side wiring error) — not a panic, and not a 4xx. How to respond to an encryption failure is the handler's call — this library does not decide for your app whether a failed decryption should return 500 or 422.

```bash
cargo add encryption-rust --features axum   # or actix-web / rocket / poem / salvo / warp / bee-rust / ecat
```

## Differences from the PHP original

This library follows the architecture and identifier design of the PHP version [`erikwang2013/encryption`](https://github.com/erikwang2013/encryption), but uses a **Rust-specific format**:

1. Ciphertext is **not interoperable** with the PHP version: the structure keeps the `v1 | IV | Tag/MAC | ciphertext` shape, but there is no byte-level cross-decryption guarantee, and no cross-decryption tests have been run.
2. Only the corrected subkey derivation is used (the HMAC key is the master key and the message is the purpose label); the original's legacy reversed-order v1 scheme is not reproduced.
3. No extension dependencies: Sodium XChaCha20 is a pure-Rust implementation, always available (the original needs `ext-sodium`); SM2 has no `ext-gmp` prerequisite.
4. SM2 ciphertext / key encoding follows the RustCrypto `sm2` standard (C1C3C2, uncompressed C1) and is not aligned with the original's pohoc/crypto-sm layout.
5. Framework adapters are rewritten for the Rust ecosystem: native Rust (the `Guard` request guard) plus axum / actix-web / rocket / poem / salvo / warp / bee-rust / e-cat, corresponding to the original's Laravel / ThinkPHP / Hyperf / webman integrations.

## Project layout

```text
encryption-rust/
├── src/
│   ├── lib.rs                 crate docs and module exports
│   ├── contract.rs            the five capability contracts (traits) and Identified
│   ├── registry.rs            the generic registry Registry<T>
│   ├── manager.rs             the five facades: Encryption / Asymmetric / Hashing / KeyDerivation / PasswordBasedKdf
│   ├── factory.rs             master key factory: subkey derivation and registry assembly
│   ├── guard.rs               request guard Guard (Arc<EncryptionManager>, framework-agnostic)
│   ├── integrations/          8 framework adapters (each behind its own feature)
│   │                          axum / actix / rocket / poem / salvo / warp / bee_rust / ecat
│   ├── key.rs                 fixed-length key material Key<N> (zeroized on Drop, redacted Debug)
│   ├── error.rs               Error / Result
│   ├── encryptor/             aes256gcm / aes256cbc / sodium_xchacha20
│   ├── hash/                  sha256
│   ├── kdf/                   hkdf_sha256 / pbkdf2_sha256
│   ├── guomi/                 sm2 / sm3 / sm4 / zuc / unavailable (SM1/SM7/SM9 placeholders)
│   ├── internal/              hex helpers and etm.rs (the encrypt-then-MAC shared by CBC/SM4/ZUC)
│   └── pet.rs                 project pet Locky (NAME / TAGLINE / ASCII / SVG)
├── tests/
│   ├── crypto_roundtrip.rs    end-to-end round trips for every algorithm and the five facades
│   ├── invariants.rs          cross-algorithm non-interoperability, tampering always fails, IV freshness, plugin extension
│   └── sm2.rs                 SM2 key pairs, the facade, and error paths
├── examples/quickstart.rs     zero-config quick start (encrypt → store → read → decrypt → tamper detection)
├── docs/
│   ├── pet.svg                the project pet artwork (inlined by src/pet.rs with include_str!)
│   ├── architecture-design.svg  architecture design (referenced by this README)
│   ├── functional-design.svg    functional design (referenced by this README)
│   ├── lifecycle.svg            request lifecycle (referenced by this README)
│   └── i18n/en/               English README and the three English design diagrams
├── Cargo.toml
├── SECURITY.md
└── LICENSE
```

## FAQ

**Do I need to install system extensions?**
No. The whole implementation consists of pure-Rust crates: no `ext-sodium` / `ext-gmp`-style prerequisites, just `cargo build`.

**Why is the ciphertext binary?**
Consistent with the original: the library produces and accepts bytes. To store it in JSON / a TEXT column, base64- or hex-encode it yourself (see `examples/quickstart.rs`).

**Where does the master key come from?**
A 32-byte random value read from an environment variable / KMS / key service; never write it into code, never commit it to version control; **you must back it up — losing the master key means losing the data**.

**Why does the error message not distinguish the cause when decryption fails?**
A wrong key, a tampered ciphertext, and a wrong algorithm are all the same failure. Distinguishing the cause would hand attackers an oracle and leak internal details to the frontend.

**What is the SM2 ciphertext layout?**
C1C3C2 (the default layout of the current standard), with C1 an uncompressed point `04‖X‖Y`. It is not necessarily byte-for-byte identical to the original pohoc/crypto-sm hex convention (see "Differences from the PHP original").

**Are there English versions of the design diagrams?**
Yes. This English README uses the three English design diagrams under `docs/i18n/en/`; the source files use the same layouts that the Chinese README references.

## Security recommendations

- **Master key**: 32 bytes from a CSPRNG; keep it in an environment variable / KMS, never in the codebase, never in logs; back it up offline and restrict access.
- **Passwords**: use a dedicated API such as Argon2 / bcrypt to store user passwords; use PBKDF2 only to "derive an encryption key from a passphrase", and raise the iteration count for your environment.
- **Errors**: catch and log them; never pass error details through to the frontend.
- **Algorithm choice**: `aes-256-gcm` by default for new systems; the library guarantees encrypt-then-MAC for CBC / SM4-CBC — don't assemble it yourself.
- **Randomness**: the IV / nonce is generated by the library on every encryption (system CSPRNG); never reuse one, and never bring your own.

## Running tests

```bash
cargo test                       # core library (pulls in no framework by default)
cargo test --all-features        # together with the tests for the 8 framework adapters
cargo run --example quickstart
```

Coverage: per-algorithm round trips and tamper-always-fails, cross-algorithm non-interoperability, factory subkey independence and validation, registry / facade behavior, SM2 key paths, the pet constants, and guard extraction for every framework (including the "forgot to wire it → 500" path).

## Reference original project

- The PHP original: [github.com/erikwang2013/encryption](https://github.com/erikwang2013/encryption)

## License

[MIT](../../../LICENSE) © 2026 erik — [https://erik.xyz](https://erik.xyz)
