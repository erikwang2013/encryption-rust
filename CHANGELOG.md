<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与[语义化版本](https://semver.org/lang/zh-CN/)。

## [1.3.0] - 2026-10-11

> 新增公开 API（`from_master_key_all` / `register_extensions`）属向后兼容的功能新增；其余为内部重构与缺陷修复，公开类型名与方法签名均未变。按 semver 为 minor。

### Added
- `EncryptionManagerFactory::from_master_key_all` 与 `register_extensions`：**九个扩展对称算法（`chacha20-poly1305-ietf`、`aes-256-gcm-siv`、`camellia-256-cbc-hmac`、`aria-256-cbc-hmac`、`threefish-512-cbc-hmac`、`kuznyechik-256-cbc-hmac`、`salsa20`、`sm4-gcm`、`zuc-256`）自此进工厂并各带独立派生子密钥**。此前它们不在工厂、也没有派生路径，按 README 手工装配的使用者只能自造密钥或复用别的算法的子密钥——后者直接违反本库「密钥永不跨算法复用」的不变量
- 扩展子密钥派生用 HKDF-Expand（RFC 5869），域与默认标签隔离：`PRK = HMAC-SHA256(主密钥, "dgn:derive-ext")`，`子密钥 = HKDF-Expand(PRK, info = "dgn:derive-ext:<标识>")`。默认五个算法的派生方案**逐字节冻结不变**，存量密文照旧解开（Threefish-512 需要 64 字节密钥，单次 HMAC-SHA256 给不出来，HKDF-Expand 是标准构造，好过自造串联规则）
- SM2 互通定值向量：`GM/T 0003.5-2012 附录 C` 加密示例（明文 `"encryption standard"`）与附录 A 签名示例，取自 OpenSSL 官方测试文件 `test/sm2_internal_test.c`；DER 形式到本库原始 `C1‖C3‖C2` 布局的转换逐项写明并独立复算。SM2 此前是**唯一没有外部锚点**的算法族（13 个测试全是自洽往返，布局写错也照样全绿）
- 工厂派生定值向量：五个默认标签 + 九个扩展标签的派生结果全部冻结为常量（此前改标签或改参数顺序会让存量数据全解不开，而所有测试仍绿）
- `SignatureManager` / `KeyAgreementManager` 的往返测试（这两个门面此前全仓库零引用）；八个门面的 `kind` 错误字符串全部钉死
- 基准组重做：`wrapper-vs-raw`（两组基线都在计时闭包内建 cipher，此前裸 crate 建在循环外、封装每次重建，190–230 ns 的密钥扩展被误记成「封装差价」）、`short-payload`（11 字节——本库真实用例）、`etm/aes-256-cbc-hmac`、`hex`

### Fixed
- **`KeyPairHex` 的 `Debug` 会打印私钥明文**（`src/asymmetric/mod.rs` 与 `src/guomi/sm2.rs` 各有一份逐字节相同的定义，都 derive 了 `Debug`）：`print!("{pair:?}")` / `tracing::debug!(?pair)` 即可把 RSA / SM2 / Ed25519 / ECDSA / X25519 的私钥打进日志，而 README 把「Debug 遮蔽」列为安全默认值、`Key<N>` 也确实做到了——唯独所有 `generate_key_pair_hex()` 的返回值没做到。现改为手写遮蔽 `Debug`（打印 `***`），并删掉重复定义（`guomi::KeyPairHex` 改为再导出，导入路径不变）
- ZUC-128 / ZUC-256 的 `buffer.len() * 8` 在 **32 位目标**（wasm32 / i686 / armv7）上 512 MiB 载荷即回绕，底层实现拿到回绕后的 `bit_len` 会把超出部分的密文**静默清零**（数据毁坏）。改用 `checked_mul(8)` 并在回绕时返回错误
- PBKDF2 / scrypt 的输出长度上限原为 `usize::MAX`（只挡 `length == 0`），`derive_from_password(pw, salt, usize::MAX/2)` 会尝试分配 2^63 字节而 abort。改为 `u32::MAX`，与 Argon2 已有取值一致
- 主密钥临时副本不再裸 drop：`factory.rs` 的栈拷贝与 `guard.rs` 的 `decode_master_key` 中间 `Vec` 改用 `Zeroizing` / 显式 `zeroize()`（此前核心转储或交换分区可捞出主密钥，而派生子密钥本是清零的）
- `hex_decode` 改用 256 项全表。**紧凑算术写法是错的**：`(c & 0x0f) | (c >> 6) * 9` 这类会把 `':'`（0x3a→10）与 `'Z'`（0x5a→11）误判成合法十六进制字符；新增遍历全部 256 个字节取值的接受集测试把它钉住

### Changed
- **性能：EtM 的 MAC 密钥不再每次调用重算。** `mac_key` 只由密文密钥决定，此前每个 `pack` / `unpack_and_verify` 都重做一次完整 HMAC-SHA256（即每次操作两次 HMAC）。现随加密器构造派生一次、存进 `EtmKeys`（密文密钥与 MAC 密钥都 Drop 清零）。影响共享该层的九个算法（aes-256-cbc / camellia / aria / kuznyechik / threefish / sm4 / zuc-128 / zuc-256 / salsa20），实测**每次调用省 15–18%**
- **性能：块密码实例改为构造时建立。** AES-GCM / AES-GCM-SIV / ChaCha20-Poly1305-IETF / XChaCha20 / SM4-GCM 此前每次加解密都重跑一遍密钥编排；实测 **190–230 ns/次**，短载荷下占计算量的 62%（解密方向没有随机数开销挡着，占比更高）。轮密钥仍随结构体 Drop 清零（`zeroize` feature 已开）
- **性能：`hex_encode` 改查表**，不再每字节走一次 `core::fmt`：实测 32 B 1836→210 ns、1 KiB 62→4.2 µs、1 MiB 42.7→3.6 ms
- **结构：六个 CBC-HMAC 加密器合并为一个泛型实现** `CbcHmacEncryptor<C, KEY_LEN>`。`aes256cbc` / `aria256cbc` / `camellia256cbc` / `kuznyechikcbc` / `threefish512cbc` / `guomi/sm4` 此前是六份逐字节相同的代码（非测试正文各 47 行，逐行比对 94–98% 相同），任何边界修正都要改六遍；现泛型参数只区分块密码与密钥长度，IV 长度取自块长（Threefish-512 为 64），六个公开类型名以 `type` 别名保持原样，各标准的裸块密码定值向量（SM4 GB/T 32907 / Camellia RFC 3713 / ARIA RFC 5794 / Kuznyechik RFC 7801 / Threefish 官方 KAT）合并进一处测试
- **结构：八个门面合并为一个 `manager_facade!` 宏**，607 行 → 345 行。此前每个门面都是同构的 `struct` + `new` + 四个访问器 + `x` / `x_with` 转发对，`manager/asymmetric.rs` 存在的理由竟是「让 `manager.rs` 保持在 500 行以内」——行数是被样板撑起来的
- **结构：七个哈希器的样板合并为 `hasher!` 宏 + `NamedDigest` blanket impl**。SM3（`sm3` crate 属 digest 0.11 代际）与 BLAKE3（独立实现，不走 digest trait）各自实现 `Hasher`，其余五个摘要共用一个 blanket
- `ml-kem` 的 `deterministic` feature 从 `[dependencies]` 移到 `[dev-dependencies]`：它只服务 NIST ACVP 定值向量测试，不该进使用者的生产依赖图
- 新增 `#![forbid(unsafe_code)]`——全库本就不含 `unsafe`，改由编译器强制
- 跨算法不变量测试（互不通用 / 篡改必败 / IV 每次新）改用 `from_master_key_all`，覆盖面从 5 个算法扩到 **14 个**；新增「扩展子密钥彼此独立」「换主密钥后扩展密文解不开」「默认五算法子密钥未被扰动」三条不变量
- README（中英）同步：扩展算法不再描述为「手动注册、不进工厂」，补 `from_master_key_all` / `register_extensions` 的装配方式与两套派生方案的说明
- `SECURITY.md` 新增「Known limitations in this library」：如实说明工厂派生过程中**清不掉**的那部分状态——`hkdf` 0.12 与 `hmac` 0.12 都不提供 `zeroize` feature，故 `Hkdf` 内部的 PRK 副本与 HMAC 的 ipad/opad 填充永不擦除，主密钥栈拷贝被移出后也无法保证清零。加密器**持有**的东西（`Key<N>` / `EtmKeys` / 缓存 cipher）照旧全部 Drop 清零。影响边界与规避建议（主密钥放 KMS/HSM 按需派生）一并写明
- `.gitignore` 补 `.claude/worktrees/`（agent 工具的本机 git worktree，此前一直挂在 `git status` 的未跟踪列表里）

## [1.2.1] - 2026-10-10

### Changed
- 文档与披露同步（**无代码变更**，API 与行为与 1.2.0 完全一致）：
- `SECURITY.md` 新增「Known advisories in dependencies」小节：披露 `RUSTSEC-2023-0071`（rsa「Marvin」时序侧信道，上游无补丁）的缓解（`decrypt_blinded`）与替代建议（网络暴露场景优先 ECDH / X25519 / Ed25519 / ML-KEM）
- README（中英）安全建议补 RSA-OAEP 边界条目；架构 / 功能设计图（中英）同步八族（功能图新增「1.2.0 扩展三族」横幅带）；`rsa` 模块文档标注同一公告
- CI：audit 白名单加入 `RUSTSEC-2023-0071`（附理由与退出条件，与 h2 条目同格式）

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
