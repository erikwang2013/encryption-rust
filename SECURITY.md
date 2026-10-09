<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Security policy

`erikwang2013/encryption-rust` is a cryptography component library: a flaw here can silently weaken every application that depends on it. Reports are welcome and will be taken seriously.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

- Email **erik@erik.xyz** with the subject line `SECURITY: erikwang2013/encryption-rust`.
- Or use GitHub's [private vulnerability reporting](https://github.com/erikwang2013/encryption-rust/security/advisories/new).

Please include: affected version(s), what you observed, a minimal reproduction if you have one, and your assessment of impact. If you need an encrypted channel, say so in a first plain message.

You will get an acknowledgement, an assessment, and — if the report is confirmed — credit in the release notes unless you prefer otherwise.

## Supported versions

Fixes are released on the latest 0.x / 1.x line. Older tags are not maintained; upgrade to the newest release.

## Scope

In scope:

- Cryptographic weaknesses in the library's own code: subkey derivation (`HMAC-SHA256(key = master, msg = label)`), payload framing (`v1 | IV | tag/MAC | ciphertext`), padding handling, MAC/tag verification, key-length validation, hex parsing
- Flaws in how this crate wires the RustCrypto primitives: IV/nonce handling, unauthenticated decryption paths, padding-oracle exposure, constant-time verification
- Flaws in `EncryptionManagerFactory` key management (subkey truncation for SM4/ZUC, default-algorithm validation)
- Timing side channels in verification paths, and any way to make a failed decryption look successful

Out of scope:

- Weak keys, hard-coded secrets, or compromised environments in *your* application
- Choosing an unsuitable algorithm for your threat model (see the "安全建议" section of the README)
- Defects in the underlying RustCrypto crates (`aes-gcm`, `chacha20poly1305`, `sm2`, `sm3`, `sm4`, `hmac`, `sha2`, `hkdf`, `pbkdf2`, `zuc`) — report those upstream; if it affects this library, tell us too and we will track it here
- Missing features (e.g. no sign/verify API) — that is a feature request, use the issue tracker

## Known advisories in dependencies

- **RUSTSEC-2023-0071 — "Marvin" timing side channel in the `rsa` crate.** No upstream patch exists (`patched = []`; both `rsa` 0.9.x and 0.10.0-rc are affected; tracked in RustCrypto/RSA#626, #680, #702), so it is whitelisted in CI with an explicit exit condition. This library's `rsa-oaep-sha256` decrypts through `decrypt_blinded` (the mitigation direction acknowledged by the advisory), but **prefer ECDH / X25519 / Ed25519 / ML-KEM for network-exposed settings** — treat RSA-OAEP as an interop / local-use tool. This whitelist entry will be removed when the upstream fix lands or when this library drops the algorithm.

## What this library does not protect against

Transport security (use TLS), application-level authorisation, and key storage are outside its remit. Losing the master key means losing the data — there is no recovery path, by design.
