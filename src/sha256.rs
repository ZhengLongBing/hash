//! SHA-256 (Secure Hash Algorithm 256) 哈希算法实现
//!
//! # 算法概述
//! SHA-256是SHA-2家族中的一员，可以生成一个256位(32字节)的消息摘要。
//! 它被广泛应用于数字签名、区块链等安全场景。
//!
//! # 处理步骤
//!
//! 1. 消息填充
//!    - 在消息末尾添加一个1位
//!    - 添加0位直到长度满足 448 mod 512
//!    - 添加64位的原始消息长度
//!
//! 2. 初始化哈希值
//!    - 使用8个32位寄存器 (A-H)
//!    - 初始值来自前8个质数的平方根小数部分
//!
//! 3. 消息处理
//!    - 将输入分成512位的块
//!    - 每个块:
//!      * 创建64个32位字的消息调度表
//!      * 进行64轮压缩函数运算
//!      * 使用Ch(x,y,z)和Maj(x,y,z)等逻辑函数
//!      * 应用轮常量和消息调度
//!
//! 4. 最终处理
//!    - 将8个寄存器的值连接
//!    - 输出256位的最终哈希值
//!
//! # 安全性
//!
//! SHA-256目前被认为是安全的，没有发现实际可行的攻击方法。
//! 它是比特币等区块链技术的核心算法之一。

use crate::Hasher;

// 初始哈希值（前8个质数的平方根的小数部分前32位）
const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// 轮常量（前64个质数的立方根的小数部分前32位）
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct SHA256 {
    state: [u32; 8],   // 哈希状态 (A, B, C, D, E, F, G, H)
    total_len: u64,    // 已处理的字节数
    buffer: [u8; 64],  // 数据缓冲区
    buffer_len: usize, // 缓冲区中有效数据长度
}

impl SHA256 {
    pub fn new() -> SHA256 {
        SHA256 {
            state: H,
            total_len: 0,
            buffer: [0; 64],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        let mut input_idx = 0;

        // 处理之前的剩余数据
        if self.buffer_len > 0 {
            while self.buffer_len < 64 && input_idx < input.len() {
                self.buffer[self.buffer_len] = input[input_idx];
                self.buffer_len += 1;
                input_idx += 1;
            }

            if self.buffer_len == 64 {
                let temp = self.buffer;
                self.transform(&temp);
                self.buffer_len = 0;
                self.total_len += 64;
            }
        }

        // 处理完整的64字节块
        while input_idx + 64 <= input.len() {
            self.transform(&input[input_idx..input_idx + 64]);
            input_idx += 64;
            self.total_len += 64;
        }

        // 保存剩余数据
        while input_idx < input.len() {
            self.buffer[self.buffer_len] = input[input_idx];
            self.buffer_len += 1;
            input_idx += 1;
        }
    }

    fn transform(&mut self, block: &[u8]) {
        let mut w = [0u32; 64];

        // 将输入数据转换为32位字数组 (大端序)
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        // 扩展消息调度表
        for i in 16..64 {
            let s0 = Self::sigma0(w[i - 15]);
            let s1 = Self::sigma1(w[i - 2]);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // 初始化工作变量
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // 主循环
        for i in 0..64 {
            let s1 = Self::sigma1_upper(e);
            let ch = Self::ch(e, f, g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);

            let s0 = Self::sigma0_upper(a);
            let maj = Self::maj(a, b, c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // 更新状态
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    pub fn finalize(&mut self) -> [u8; 32] {
        let total_len = self.total_len + self.buffer_len as u64;

        // 添加填充位
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // 计算需要的填充长度
        if self.buffer_len > 56 {
            // 如果剩余空间不足56字节，填充0至64字节并处理
            while self.buffer_len < 64 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            let temp = self.buffer;
            self.transform(&temp);
            self.buffer_len = 0;
        }

        // 填充0直到56字节
        while self.buffer_len < 56 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }

        // 添加消息长度（以位为单位，大端序）
        let bits_len = total_len * 8;
        self.buffer[56..64].copy_from_slice(&bits_len.to_be_bytes());
        let temp = self.buffer;
        self.transform(&temp);

        // 输出结果（大端序）
        let mut result = [0u8; 32];
        for (i, &state) in self.state.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&state.to_be_bytes());
        }
        self.reset();
        result
    }

    pub fn reset(&mut self) {
        self.state = H;
        self.total_len = 0;
        self.buffer = [0; 64];
        self.buffer_len = 0;
    }

    // SHA256辅助函数
    #[inline]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline]
    fn sigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline]
    fn sigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    #[inline]
    fn sigma0_upper(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline]
    fn sigma1_upper(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }
}

impl Hasher for SHA256 {
    fn block_size(&self) -> usize {
        64
    }
    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn finalize(&mut self) -> Vec<u8> {
        self.finalize().to_vec()
    }

    fn reset(&mut self) {
        self.reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string() {
        let mut sha256 = SHA256::new();
        let result = sha256.finalize();
        assert_eq!(
            hex::encode(result),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hello_world() {
        let mut sha256 = SHA256::new();
        sha256.update(b"Hello, World!");
        let result = sha256.finalize();
        assert_eq!(
            hex::encode(result),
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
    }

    #[test]
    fn test_long_input() {
        let mut sha256 = SHA256::new();
        sha256.update(b"The quick brown fox jumps over the lazy dog");
        let result = sha256.finalize();
        assert_eq!(
            hex::encode(result),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }

    #[test]
    fn test_multiple_updates() {
        let mut sha256 = SHA256::new();
        sha256.update(b"Hello, ");
        sha256.update(b"World!");
        let result = sha256.finalize();
        assert_eq!(
            hex::encode(result),
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
    }
}
