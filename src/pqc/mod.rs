// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 后量子实现（对应 PHP 版 `Pqc/`）：FIPS 203 ML-KEM 密钥封装。

mod ml_kem;

pub use ml_kem::{MlKem512Kem, MlKem768Kem, MlKem1024Kem};
