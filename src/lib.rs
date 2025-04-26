// src/lib.rs
pub mod crc32;
pub mod md4;
pub mod md5;
pub mod sha1;
pub mod sha256;
pub mod sha512;
pub mod sm3;

// 定义Hash特征
pub trait Hasher {
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;
    fn reset(&mut self);
}
