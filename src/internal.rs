// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! crate 内部工具，不对外暴露。

pub(crate) mod etm;

use std::fmt::Write;

use crate::error::{Error, Result};

/// 小写十六进制编码。
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// 十六进制解码；奇数长度或含非十六进制字符返回 [`Error::InvalidHex`]。
pub(crate) fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::InvalidHex);
    }

    let (pairs, _) = bytes.as_chunks::<2>();
    let mut output = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let high = (pair[0] as char).to_digit(16).ok_or(Error::InvalidHex)?;
        let low = (pair[1] as char).to_digit(16).ok_or(Error::InvalidHex)?;
        output.push(((high << 4) | low) as u8);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_and_errors() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_decode("000fff").unwrap(), vec![0x00, 0x0f, 0xff]);
        assert_eq!(hex_decode("0fF").unwrap_err(), Error::InvalidHex);
        assert_eq!(hex_decode("zz").unwrap_err(), Error::InvalidHex);
    }
}
