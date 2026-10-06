// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 项目宠物「Locky」（小锁）。
//!
//! 图形本体见 `docs/pet.svg`（`SVG` 常量以 `include_str!` 内联，零运行时开销，
//! 不用就不链接）；终端里没有 SVG，因此保留一份等价的 ASCII 版本
//! （与 PHP 版 `Erikwang2013\Encryption\Mascot::ascii()` 逐字符一致）。

/// 宠物名。
pub const NAME: &str = "Locky";

/// 一句话标语。
pub const TAGLINE: &str = "每个算法各持一把子密钥，每次加密都用新的 IV，钥匙孔从不泄露秘密";

/// 终端横幅用的 ASCII 版本：纯 ASCII、等宽 17 列，不依赖字体或颜色（无尾随换行）。
pub const ASCII: &str = concat!(
    "     .-------.\n",
    "     /       \\\n",
    "  .-------------.\n",
    "  |  o       o  |\n",
    "  |             |\n",
    "  |     ,-.     |\n",
    "  |    (   )    |\n",
    "  |     '-'     |\n",
    "  |      |      |\n",
    "  '-------------'",
);

/// 项目宠物 SVG（`docs/pet.svg` 原文；可内联进 HTML，或自行转成 data URI 使用）。
pub const SVG: &str = include_str!("../docs/pet.svg");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_matches_php_mascot_line_for_line() {
        let lines: Vec<&str> = ASCII.lines().collect();
        assert_eq!(lines.len(), 10);
        assert_eq!(lines[0].trim_start(), ".-------.");
        assert_eq!(lines[2].trim_start(), ".-------------.");
        assert_eq!(lines[9].trim_start(), "'-------------'");
        assert!(!ASCII.ends_with('\n'));
    }

    #[test]
    fn svg_is_inlined_from_docs() {
        assert!(SVG.trim_start().starts_with("<svg"));
        assert!(SVG.contains("Locky"));
    }

    #[test]
    fn name_and_tagline_are_public() {
        assert_eq!(NAME, "Locky");
        assert!(!TAGLINE.is_empty());
    }
}
