// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 零配置快速开始：主密钥 → 工厂 → 加密 → 存（base64）→ 读 → 解密 → 篡改检测。
//! 对应 PHP 版 `examples/plain-php/demo.php` 的完整往返。
//!
//! 运行：`cargo run --example quickstart`

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use encryption::{factory::EncryptionManagerFactory, pet};

fn main() -> Result<(), encryption::error::Error> {
    println!("{}", pet::ASCII);
    println!("{} · {}\n", pet::NAME, pet::TAGLINE);

    // 生产环境请从环境变量 / KMS 读取随机 32 字节主密钥，并妥善备份——
    // 丢了主密钥就等于丢了数据。这里用固定值只为演示。
    let master_key: [u8; 32] = *b"encryption-rust-demo-master-key!";

    // 工厂从主密钥派生各算法子密钥，一次性注册全部算法。
    let manager = EncryptionManagerFactory::from_master_key(&master_key, "aes-256-gcm")?;
    println!("已注册算法: {:?}", manager.registry().identifiers());

    // 1. 加密并转成文本，像写入 TEXT 列那样存起来。
    let phone = "13800138000";
    let stored = BASE64.encode(manager.encrypt(phone.as_bytes())?);
    println!("\n入库值: {stored}");

    // 2. 读出来解密。
    let read_back = BASE64.decode(&stored).unwrap();
    let decrypted = manager.decrypt(&read_back)?;
    println!("解出原文: {}", String::from_utf8_lossy(&decrypted));

    // 3. 换一个算法（显式指定标识）。
    let blob = manager.encrypt_with("sm4-cbc", phone.as_bytes())?;
    println!("SM4 密文长度: {} 字节", blob.len());

    // 4. 篡改检测：翻转密文最后一字节，解密必须失败。
    let mut tampered = manager.encrypt(phone.as_bytes())?;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    match manager.decrypt(&tampered) {
        Ok(_) => println!("篡改未被发现——不该发生！"),
        Err(error) => println!("篡改被拒绝: {error}"),
    }

    Ok(())
}
