<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与[语义化版本](https://semver.org/lang/zh-CN/)。

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
