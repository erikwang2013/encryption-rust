// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! SM1 / SM7 / SM9 在公开生态中无标准实现：调用下列函数将返回明确的
//! [`Error::UnsupportedNationalAlgorithm`]，便于在业务层统一捕获或接入
//! 厂商 SDK / 加密机。
//!
//! - SM1：未公开的商用分组密码；
//! - SM7：面向 RFID 等领域；
//! - SM9：基于身份的密码体系（IBC），需完整协议与密钥管理。

use crate::error::{Error, Result};

/// SM1：不公开的商用分组密码。
pub fn sm1() -> Result<()> {
    Err(Error::UnsupportedNationalAlgorithm {
        name: "SM1",
        hint: "it is a non-public commercial block cipher; use a national-crypto HSM or the SDK from the chip vendor",
    })
}

/// SM7：主要用于 RFID 等领域。
pub fn sm7() -> Result<()> {
    Err(Error::UnsupportedNationalAlgorithm {
        name: "SM7",
        hint: "it targets RFID and similar fields; use the matching dedicated device or vendor interface",
    })
}

/// SM9：基于身份的密码体系。
pub fn sm9() -> Result<()> {
    Err(Error::UnsupportedNationalAlgorithm {
        name: "SM9",
        hint: "it is a full identity-based cryptosystem requiring complete IBC protocols and key management; integrate a national-crypto middleware",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_report_unsupported() {
        for result in [sm1(), sm7(), sm9()] {
            assert!(matches!(
                result.unwrap_err(),
                Error::UnsupportedNationalAlgorithm { .. }
            ));
        }
    }
}
