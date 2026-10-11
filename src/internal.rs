// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! crate 内部工具，不对外暴露。

pub(crate) mod etm;

use crate::error::{Error, Result};

/// 小写十六进制数字表（编码查表：每字节两次查表，不走 `core::fmt`）。
pub(crate) const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// 小写十六进制编码。
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut output = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX_LOWER[(byte >> 4) as usize]);
        output.push(HEX_LOWER[(byte & 0x0f) as usize]);
    }
    // 上面写入的全部是 ASCII 十六进制数字，UTF-8 合法性由构造保证。
    String::from_utf8(output).expect("hex digits are ASCII")
}

/// 半字节解码表：`0-9` / `A-F` / `a-f` → 0-15，其余 256 个取值一律 `0xff`（非法）。
///
/// 用全表而不是算术映射：`(c & 0x0f) | (c >> 6) * 9` 这类紧凑写法会把 `':'`
/// （0x3a → 10）与 `'Z'`（0x5a → 11）误判成合法十六进制字符。
const HEX_DECODE: [u8; 256] = {
    let mut table = [0xffu8; 256];
    let mut digit = 0;
    while digit < 10 {
        table[b'0' as usize + digit] = digit as u8;
        digit += 1;
    }
    let mut letter = 0;
    while letter < 6 {
        table[b'a' as usize + letter] = (10 + letter) as u8;
        table[b'A' as usize + letter] = (10 + letter) as u8;
        letter += 1;
    }
    table
};

/// 十六进制解码；奇数长度或含非十六进制字符返回 [`Error::InvalidHex`]。
///
/// 接受大小写混合（`0-9` / `a-f` / `A-F`），与 [`hex_encode`] 的输出互逆。
pub(crate) fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::InvalidHex);
    }

    let (pairs, _) = bytes.as_chunks::<2>();
    let mut output = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let high = HEX_DECODE[pair[0] as usize];
        let low = HEX_DECODE[pair[1] as usize];
        if high == 0xff || low == 0xff {
            return Err(Error::InvalidHex);
        }
        output.push((high << 4) | low);
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

    /// 查表解码必须原样保住旧实现的接受集：大小写混合可解，非十六进制字符全拒。
    #[test]
    fn hex_decode_accepts_both_cases_and_rejects_everything_else() {
        assert_eq!(hex_decode("aBcDeF").unwrap(), vec![0xab, 0xcd, 0xef]);
        assert_eq!(hex_decode("ABCDEF").unwrap(), vec![0xab, 0xcd, 0xef]);
        assert_eq!(hex_decode("abcdef").unwrap(), vec![0xab, 0xcd, 0xef]);

        // 每个字节的完整接受集：0-9 A-F a-f 之外的字符必须一律拒绝。
        for byte in 0u8..=0xff {
            let text = [byte as char; 2].iter().collect::<String>();
            let accepted =
                byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte.to_ascii_uppercase());
            assert_eq!(
                hex_decode(&text).is_ok(),
                accepted,
                "byte {byte:#04x} ({:?})",
                byte as char
            );
        }
    }

    #[test]
    fn hex_encode_matches_encode_for_all_bytes() {
        let all: Vec<u8> = (0u8..=0xff).collect();
        let encoded = hex_encode(&all);

        // 每字节两个字符：256 字节 → 512 字符。
        assert_eq!(encoded.len(), 512);
        // 首尾各取两个字节（4 个字符），钉住大小写与高低半字节的顺序。
        assert_eq!(&encoded[..4], "0001");
        assert_eq!(&encoded[..8], "00010203");
        assert_eq!(&encoded[504..], "fcfdfeff");
        assert_eq!(hex_decode(&encoded).unwrap(), all);
    }
}
