<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与[语义化版本](https://semver.org/lang/zh-CN/)。

## [1.2.0] - 2026-10-09

### Added
- 对称加密扩展 9 个标识：`chacha20-poly1305-ietf`（RFC 8439）、`aes-256-gcm-siv`（RFC 8452 误用稳健 AEAD）、`camellia-256-cbc-hmac`、`aria-256-cbc-hmac`、`threefish-512-cbc-hmac`、`kuznyechik-256-cbc-hmac`、`salsa20`、`sm4-gcm`（sm4 + ctr + ghash 组装，RFC 8998 向量逐字节锚定）、`zuc-256`（32 字节密钥 / 23 字节 IV，规范 v1.1 双向量锚定）
- 哈希扩展 8 个标识：`sha3-256` / `sha3-512`（FIPS 202）、`blake2b-512` / `blake2s-256`（RFC 7693）、`blake3`、`streebog-256` / `streebog-512`（GOST R 34.11-2012）、`belt-hash`（STB 34.101.31）
- 口令派生扩展：`argon2`（Argon2id v19，RFC 9106；默认约 19 MiB/次）、`scrypt`（RFC 7914；默认约 128 MiB/次，文档标注 Web DoS 面）
- 非对称加密扩展：`rsa-oaep-sha256`（PKCS#8 / SPKI DER 十六进制密钥；解密盲化防时序侧信道；Project Wycheproof 定值向量）
- 三个新契约与门面：`Signer`（`SignatureManager`）、`KeyAgreement`（`KeyAgreementManager`）、`KeyEncapsulation`（`KeyEncapsulationManager`）
- 签名 5 个标识：`sm2`（新增签名能力，GM/T 0003.2 默认用户 ID 已固化并文档化）、`ed25519`（RFC 8032）、`ecdsa-p256-sha256` / `ecdsa-p384-sha384` / `ecdsa-secp256k1-sha256`（RFC 6979 确定性签名）
- 密钥协商 4 个标识：`x25519`（RFC 7748，拒绝小阶点）、`ecdh-p256` / `ecdh-p384` / `ecdh-secp256k1`
- 后量子密钥封装 3 个标识：`ml-kem-512` / `ml-kem-768` / `ml-kem-1024`（FIPS 203；NIST ACVP 定值向量；隐式拒绝语义实现、文档与测试三处一致）
- 新错误变体：`SignFailed` / `VerificationFailed`（验签失败不区分原因）与 `InvalidKdfParams`
- 扩展面算法一律不进主密钥工厂默认集，工厂注册集与 PHP 对齐面保持不变；已知缺口已如实文档化：secp256k1 的 ECDSA / ECDH 无权威定值向量（RFC 6979 / 5903 未收录），以行为测试覆盖

### Changed
- `sm2` 启用 `dsa` feature（SM2 签名）；`KeyPairHex` 统一为 `encryption::asymmetric::KeyPairHex`（RSA 与签名 / 协商共用）
- 新增钉版依赖：`ghash` / `ctr`（SM4-GCM 组装）、`p256` / `p384` / `k256` / `ed25519-dalek` / `x25519-dalek`、`ml-kem` 0.2.3（features `deterministic` + `zeroize`）、`rsa` 0.9、`sha3` / `blake2` / `blake3` / `streebog` / `belt-hash`、`argon2` / `scrypt`、`camellia` / `aria` / `threefish` / `kuznyechik` / `salsa20` / `aes-gcm-siv` —— 全部落在既有 cipher 0.4 / digest 0.10 / aead 0.5 / elliptic-curve 0.13 / signature 2 代际
- README（中英）与项目目录说明同步扩展面；两张功能/架构设计图（中英）同步到八族
- `RUSTSEC-2023-0071`（rsa 0.9.10「Marvin」时序侧信道，上游无补丁）加入 audit 白名单，附理由与退出条件；SECURITY.md / README / 模块文档同步披露缓解（`decrypt_blinded`）与替代建议（网络暴露场景优先 ECDH / X25519 / Ed25519 / ML-KEM）
- 发布包排除 `.claude` / `.agents`（此前 agent 配置随包发布；1.2.0 起包内文件从 335 个缩减为 87 个）

## [1.1.1] - 2026-10-07

### Fixed
- CI audit job 补 `checks: write` 权限（rustsec/audit-check 落检查结果所需；首跑报 `Resource not accessible by integration`）

### Changed
- dependabot 策略：cargo 依赖忽略 semver-major（密码学依赖按「cipher 0.4 / digest 0.10」代际刻意钉版，防止静默换栈），`dtolnay/rust-toolchain` 的 MSRV 引用不再被当作版本升级；首批 6 个代际大版本 PR 已附理由关闭
- `RUSTSEC-2026-0258`（h2 0.3.27，经 actix-web / rocket 传递引入，低危、0.3 线无补丁）加入 audit 白名单，附退出条件
- Cargo.lock 按 MSRV（1.88）感知重解析：`windows-sys` / `socket2` 等相关传递依赖回退到兼容 1.88 的最高版本

## [1.1.0] - 2026-10-07

### Added
- `Guard::from_env()` / `Guard::from_env_with()`：从环境变量构造请求守卫——`ENCRYPTION_MASTER_KEY`（支持 `hex:` / `base64:` 前缀或无前缀自动判定）与可选的 `ENCRYPTION_ALGORITHM`（默认 `aes-256-gcm`）
- 跨实现已知答案向量（[`tests/known_answer.rs`](./tests/known_answer.rs)）：AES-256-GCM / XChaCha20-Poly1305 / AES-256-CBC-HMAC / SM4-CBC 的参考密文由本机 OpenSSL / libsodium（经 PHP）生成并逐字节钉死
- criterion 基准（[`benches/crypto_bench.rs`](./benches/crypto_bench.rs)）：对比本库封装与裸 `aes-gcm` 的开销
- GitHub Actions CI：fmt / clippy `-D warnings` / `test --all-features` / MSRV 1.88 / `cargo audit`，另附 dependabot（cargo + github-actions）
- README 徽章（crates.io / docs.rs / CI / License）；docs.rs 改为全 feature 构建（`[package.metadata.docs.rs] all-features = true`），8 个框架适配在文档中可见

### Changed
- `aes-gcm` / `aes` / `sm4` / `chacha20` / `poly1305` 启用 `zeroize` feature：底层轮密钥与内部状态随释放清零，与 `Key<N>` 的 Drop 清零闭环
- `[profile.release]` 启用 `lto = true`、`codegen-units = 1`（仅对本仓库 bench / examples 生效，不影响库使用者）

## [1.0.1] - 2026-10-07

### Changed
- 宠物 Locky 整合：中英 6 张设计图右上角内嵌小图标、新增 `docs/social-preview.svg/.png`（GitHub 社交预览）、两版 README 同步（纯文档 / 资源变更，代码不变）

## [1.0.0] - 2026-10-07

### Added
- 首个版本：五族契约（trait）→ 注册表 → 门面 → 主密钥工厂的完整实现；十个算法标识
  `aes-256-gcm` / `sodium-xchacha20` / `aes-256-cbc-hmac` / `sm4-cbc` / `zuc-128` /
  `sm2` / `sha256` / `sm3` / `hkdf-sha256` / `pbkdf2-sha256`
- 请求守卫 `Guard` + 8 个框架适配（axum / actix-web / rocket / poem / salvo / warp / bee-rust / e-cat，全部 opt-in feature）
- 宠物 Locky（`docs/pet.svg`，`include_str!` 内联）；中英文 README 与中英双份设计图；SECURITY.md
