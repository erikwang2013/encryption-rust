// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! CBC + HMAC-SHA256（encrypt-then-MAC，PKCS#7 填充）的**唯一实现**。
//!
//! `aes-256-cbc-hmac` / `camellia-256-cbc-hmac` / `aria-256-cbc-hmac` /
//! `kuznyechik-256-cbc-hmac` / `threefish-512-cbc-hmac` / `sm4-cbc` 六个标识
//! 共用这一个泛型：它们此前是六份逐字节相同的实现（只有块密码类型、标识符
//! 与密钥长度不同），任何一处边界修正都要改六遍。现在泛型参数 `C` 是块密码、
//! `KEY_LEN` 是密钥长度，载荷统一为 `v1 | IV | MAC(32) | 密文`，
//! IV 长度取自 `C` 的块长（16 字节，Threefish-512 为 64 字节）。
//!
//! 泛型对使用者的可见面为零：各算法的公开类型名由下面的 `type` 别名保持原样，
//! `new([u8; N])` / `from_slice(&[u8])` 签名不变。

use cbc::cipher::{
    Block, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit, Unsigned,
    block_padding::Pkcs7,
};
use cbc::{Decryptor, Encryptor};
use rand_core::{OsRng, RngCore};

use crate::contract::{Identified, SymmetricCipher};
use crate::error::{Error, Result};
use crate::internal::etm::{self, EtmKeys};

/// CBC-HMAC 加密器：`C` 为块密码，`KEY_LEN` 为其密钥长度（字节）。
///
/// 直接在结构体里持有派生好的 EtM 密钥对（密文密钥 + MAC 密钥，均 Drop 清零），
/// 因此每次调用不再重复派生 MAC 密钥。
pub struct CbcHmacEncryptor<
    C: BlockCipher + BlockEncryptMut + BlockDecryptMut + cbc::cipher::KeyInit,
    const KEY_LEN: usize,
> {
    keys: EtmKeys<KEY_LEN>,
    identifier: &'static str,
    label: &'static str,
    // `PhantomData<fn() -> C>` 而不是 `PhantomData<C>`：后者会把 `C` 的
    // Send/Sync 约束传染给加密器，导致 `SymmetricCipher`（要求 Send + Sync）
    // 实现不出来；`fn() -> C` 是函数指针，永远 Send + Sync，且对 C 协变。
    _cipher: std::marker::PhantomData<fn() -> C>,
}

impl<C, const KEY_LEN: usize> CbcHmacEncryptor<C, KEY_LEN>
where
    C: BlockCipher + BlockEncryptMut + BlockDecryptMut + cbc::cipher::KeyInit,
{
    /// 具名构造：`identifier` 为注册表标识，`label` 为错误消息里的算法名。
    pub fn with_names(key: [u8; KEY_LEN], identifier: &'static str, label: &'static str) -> Self {
        Self {
            keys: EtmKeys::new(key),
            identifier,
            label,
            _cipher: std::marker::PhantomData,
        }
    }

    /// 从切片构造；长度不符返回 [`Error::InvalidKeyLength`]。
    pub fn with_names_from_slice(
        key: &[u8],
        identifier: &'static str,
        label: &'static str,
    ) -> Result<Self> {
        Ok(Self {
            keys: EtmKeys::from_slice(key, label)?,
            identifier,
            label,
            _cipher: std::marker::PhantomData,
        })
    }

    /// CBC 的 IV 长度即块密码的块长（AES/Camellia/ARIA/Kuznyechik/SM4 为 16，
    /// Threefish-512 为 64）。
    pub const fn iv_len() -> usize {
        <C as BlockSizeUser>::BlockSize::USIZE
    }
}

impl<C, const KEY_LEN: usize> SymmetricCipher for CbcHmacEncryptor<C, KEY_LEN>
where
    C: BlockCipher + BlockEncryptMut + BlockDecryptMut + cbc::cipher::KeyInit,
{
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut iv = Block::<C>::default();
        OsRng.fill_bytes(&mut iv);

        let ciphertext = Encryptor::<C>::new_from_slices(self.keys.cipher(), &iv)
            .expect("key and iv lengths are fixed")
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        Ok(etm::pack(&iv, &ciphertext, self.keys.mac()))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (iv, body) =
            etm::unpack_and_verify(ciphertext, Self::iv_len(), self.keys.mac(), self.label)?;

        Decryptor::<C>::new_from_slices(self.keys.cipher(), iv)
            .expect("key and iv lengths were verified")
            .decrypt_padded_vec_mut::<Pkcs7>(body)
            .map_err(|_| Error::DecryptionFailed { label: self.label })
    }
}

impl<C, const KEY_LEN: usize> Identified for CbcHmacEncryptor<C, KEY_LEN>
where
    C: BlockCipher + BlockEncryptMut + BlockDecryptMut + cbc::cipher::KeyInit,
{
    fn identifier(&self) -> &str {
        self.identifier
    }
}

/// 只打印标识符——密钥材质不出现在 `Debug` 里。
impl<C, const KEY_LEN: usize> std::fmt::Debug for CbcHmacEncryptor<C, KEY_LEN>
where
    C: BlockCipher + BlockEncryptMut + BlockDecryptMut + cbc::cipher::KeyInit,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CbcHmacEncryptor")
            .field("identifier", &self.identifier)
            .finish_non_exhaustive()
    }
}

/// 为每个块密码生成公开类型别名与单独的 `new` / `IDENTIFIER`。
///
/// 别名保持原类型名与构造签名，因此工厂、测试与使用者的既有代码无需改动。
macro_rules! cbc_hmac_aliases {
    ($( $(#[$doc:meta])* $name:ident = $cipher:ty, $key_len:literal, $label:literal, $identifier:literal; )*) => {
        $(
            $(#[$doc])*
            pub type $name = CbcHmacEncryptor<$cipher, $key_len>;

            impl CbcHmacEncryptor<$cipher, $key_len> {
                /// 注册表标识。
                pub const IDENTIFIER: &'static str = $identifier;

                /// 以定长密钥构造（长度由类型保证，不会失败）。
                pub fn new(key: [u8; $key_len]) -> Self {
                    Self::with_names(key, $identifier, $label)
                }

                /// 从切片构造；长度不符返回 [`Error::InvalidKeyLength`]。
                pub fn from_slice(key: &[u8]) -> Result<Self> {
                    Self::with_names_from_slice(key, $identifier, $label)
                }
            }
        )*
    };
}

cbc_hmac_aliases! {
    /// AES-256-CBC + HMAC-SHA256（兼容旧环境）。
    Aes256CbcEncryptor = aes::Aes256, 32, "AES-256-CBC", "aes-256-cbc-hmac";

    /// Camellia-256-CBC + HMAC-SHA256（ISO/IEC 18033-3）。
    Camellia256CbcEncryptor = camellia::Camellia256, 32, "Camellia-256-CBC", "camellia-256-cbc-hmac";

    /// ARIA-256-CBC + HMAC-SHA256（RFC 5794）。
    Aria256CbcEncryptor = aria::Aria256, 32, "ARIA-256-CBC", "aria-256-cbc-hmac";

    /// Kuznyechik-256-CBC + HMAC-SHA256（GOST R 34.12-2015）。
    Kuznyechik256CbcEncryptor = kuznyechik::Kuznyechik, 32, "Kuznyechik-256-CBC", "kuznyechik-256-cbc-hmac";

    /// Threefish-512-CBC + HMAC-SHA256（块与 IV 均 64 字节）。
    Threefish512CbcEncryptor = threefish::Threefish512, 64, "Threefish-512-CBC", "threefish-512-cbc-hmac";

    /// SM4-CBC + HMAC-SHA256（国密，GB/T 32907）。
    Sm4CbcEncryptor = sm4::Sm4, 16, "SM4", "sm4-cbc";
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 六个别名共享同一实现：逐个往返 + 篡改必败。
    ///
    /// 边界载荷按**块长**取，不能写死 16：PKCS#7 在「明文恰为块长整数倍」时会
    /// 补出整整一个填充块，Threefish-512 的块是 64 字节——只喂 16/17 字节的话，
    /// 它的填充分支根本没被走到。
    #[test]
    fn every_cbc_hmac_alias_roundtrips_and_detects_tampering() {
        fn check<E: SymmetricCipher>(cipher: &E, label: &str, block_len: usize) {
            let exact = vec![b'0'; block_len];
            let one_over = vec![b'1'; block_len + 1];
            let multi = vec![0xa5u8; block_len * 3 + 7];

            for plaintext in [
                b"".as_slice(),
                b"x",
                exact.as_slice(),
                one_over.as_slice(),
                multi.as_slice(),
            ] {
                let blob = cipher.encrypt(plaintext).unwrap();
                assert_eq!(cipher.decrypt(&blob).unwrap(), plaintext, "{label}");

                let mut tampered = blob.clone();
                let last = tampered.len() - 1;
                tampered[last] ^= 0x01;
                assert!(cipher.decrypt(&tampered).is_err(), "{label} 篡改未被发现");
            }
        }

        check(&Sm4CbcEncryptor::new([5u8; 16]), "sm4-cbc", 16);
        check(&Aes256CbcEncryptor::new([5u8; 32]), "aes-256-cbc-hmac", 16);
        check(&Camellia256CbcEncryptor::new([5u8; 32]), "camellia", 16);
        check(&Aria256CbcEncryptor::new([5u8; 32]), "aria", 16);
        check(&Kuznyechik256CbcEncryptor::new([5u8; 32]), "kuznyechik", 16);
        check(
            &Threefish512CbcEncryptor::new([5u8; 64]),
            "threefish-512",
            64,
        );
    }

    /// IV 长度必须等于块密码块长——Threefish-512 是 64，其余是 16。
    #[test]
    fn iv_length_follows_the_block_cipher_block_size() {
        assert_eq!(Aes256CbcEncryptor::iv_len(), 16);
        assert_eq!(Camellia256CbcEncryptor::iv_len(), 16);
        assert_eq!(Aria256CbcEncryptor::iv_len(), 16);
        assert_eq!(Kuznyechik256CbcEncryptor::iv_len(), 16);
        assert_eq!(Sm4CbcEncryptor::iv_len(), 16);
        assert_eq!(Threefish512CbcEncryptor::iv_len(), 64);
    }

    /// 标识符保持历史取值（注册表键不能变）。
    #[test]
    fn identifiers_are_stable() {
        assert_eq!(
            Aes256CbcEncryptor::new([0u8; 32]).identifier(),
            "aes-256-cbc-hmac"
        );
        assert_eq!(
            Camellia256CbcEncryptor::new([0u8; 32]).identifier(),
            "camellia-256-cbc-hmac"
        );
        assert_eq!(
            Aria256CbcEncryptor::new([0u8; 32]).identifier(),
            "aria-256-cbc-hmac"
        );
        assert_eq!(
            Kuznyechik256CbcEncryptor::new([0u8; 32]).identifier(),
            "kuznyechik-256-cbc-hmac"
        );
        assert_eq!(
            Threefish512CbcEncryptor::new([0u8; 64]).identifier(),
            "threefish-512-cbc-hmac"
        );
        assert_eq!(Sm4CbcEncryptor::new([0u8; 16]).identifier(), "sm4-cbc");
    }

    /// IV 每次加密都必须是新的随机值。
    #[test]
    fn iv_is_fresh_per_encryption() {
        let cipher = Aes256CbcEncryptor::new([5u8; 32]);
        let first = cipher.encrypt(b"same").unwrap();
        let second = cipher.encrypt(b"same").unwrap();
        assert_ne!(first, second);
        assert_ne!(first[2..18], second[2..18]);
    }

    /// 换密钥必须 MAC 失败（不是填充错），前缀/长度错误各自报对应错误。
    #[test]
    fn wrong_key_and_bad_frames_are_rejected() {
        let blob = Aes256CbcEncryptor::new([5u8; 32])
            .encrypt(b"secret")
            .unwrap();
        let other = Aes256CbcEncryptor::new([6u8; 32]);
        assert_eq!(
            other.decrypt(&blob).unwrap_err(),
            Error::MacVerificationFailed {
                label: "AES-256-CBC"
            }
        );
        assert_eq!(
            other.decrypt(b"v9 nope").unwrap_err(),
            Error::InvalidPrefix {
                label: "AES-256-CBC"
            }
        );
        assert_eq!(
            other.decrypt(b"v1 short").unwrap_err(),
            Error::TooShort {
                label: "AES-256-CBC"
            }
        );
    }

    #[test]
    fn key_length_is_checked_from_slice() {
        assert_eq!(
            Aes256CbcEncryptor::from_slice(&[0u8; 16]).unwrap_err(),
            Error::InvalidKeyLength {
                label: "AES-256-CBC",
                expected: 32,
                got: 16
            }
        );
        assert_eq!(
            Sm4CbcEncryptor::from_slice(&[0u8; 32]).unwrap_err(),
            Error::InvalidKeyLength {
                label: "SM4",
                expected: 16,
                got: 32
            }
        );
        assert_eq!(
            Threefish512CbcEncryptor::from_slice(&[0u8; 32]).unwrap_err(),
            Error::InvalidKeyLength {
                label: "Threefish-512-CBC",
                expected: 64,
                got: 32
            }
        );
    }

    /// 裸块密码必须与各自标准的示例向量一致——往返测试抓不出「轮函数整体错位」。
    #[test]
    fn bare_block_ciphers_match_their_standard_vectors() {
        use cbc::cipher::{BlockEncrypt, KeyInit};

        fn unhex(text: &str) -> Vec<u8> {
            crate::internal::hex_decode(text).unwrap()
        }
        fn block_encrypt<C: BlockEncrypt + KeyInit>(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
            let cipher = C::new_from_slice(key).unwrap();
            let mut block = Block::<C>::clone_from_slice(plaintext);
            cipher.encrypt_block(&mut block);
            block.to_vec()
        }

        // SM4：GB/T 32907-2016 附录 A.1。
        assert_eq!(
            block_encrypt::<sm4::Sm4>(
                &unhex("0123456789abcdeffedcba9876543210"),
                &unhex("0123456789abcdeffedcba9876543210")
            ),
            unhex("681edf34d206965e86b3e94f536e4246")
        );

        // Camellia-256：RFC 3713「128-bit key の test data」之外的 256 位示例
        // （RFC 3713 §2.3 的 256-bit key 向量）。
        assert_eq!(
            block_encrypt::<camellia::Camellia256>(
                &unhex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff"),
                &unhex("0123456789abcdeffedcba9876543210")
            ),
            unhex("9acc237dff16d76c20ef7c919e3a7509")
        );

        // ARIA-256：RFC 5794 附录 A.3。
        assert_eq!(
            block_encrypt::<aria::Aria256>(
                &unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                &unhex("00112233445566778899aabbccddeeff")
            ),
            unhex("f92bd7c79fb72e2f2b8f80c1972d24fc")
        );

        // Kuznyechik：RFC 7801 附录 A.1（256 位密钥）。
        assert_eq!(
            block_encrypt::<kuznyechik::Kuznyechik>(
                &unhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
                &unhex("1122334455667700ffeeddccbbaa9988")
            ),
            unhex("7f679d90bebc24305a468d42b9d4edcd")
        );

        // Threefish-512：Skein/Threefish 官方 KAT 的前两条**链式**向量
        // （第二条以第一条的密文为密钥）。两条都要在：
        // threefish 0.5.2 自带的 tests/mod.rs 首行是 `#![cfg(featue = "cipher")]`
        // （feature 拼写错误），整个测试目标被 cfg 掉、从未跑过——这两条向量
        // 是该实现唯一的事实锚点。
        let threefish_vectors = [
            (
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                concat!(
                    "b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b",
                    "7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"
                ),
            ),
            (
                concat!(
                    "b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b",
                    "7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"
                ),
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                concat!(
                    "f13ca06760dd9bbeab87b6c56f3bbbdb",
                    "e9d08a77978b942ac02d471dc10268f2",
                    "261c3d4330d6ca341f4bd4115dee16a2",
                    "1dcda2a34a0a76fba976174e4cf1e306"
                ),
            ),
        ];
        for (key, plaintext, expected) in threefish_vectors {
            assert_eq!(
                block_encrypt::<threefish::Threefish512>(&unhex(key), &unhex(plaintext)),
                unhex(expected),
                "Threefish-512 official KAT"
            );
        }
    }
}
