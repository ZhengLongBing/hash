//! SHA-1 (Secure Hash Algorithm 1) 哈希算法实现
//!
//! # 算法概述
//! SHA-1是一种密码散列函数，可以生成一个160位(20字节)的消息摘要。
//! 虽然现在已不再推荐用于安全场景，但仍在许多系统中使用。
//!
//! # 处理步骤
//!
//! 1. 消息填充
//!    - 在消息末尾添加一个1位
//!    - 添加0位直到长度满足 448 mod 512
//!    - 添加64位的原始消息长度
//!
//! 2. 初始化哈希值
//!    - 使用5个32位寄存器 (A,B,C,D,E)
//!    - 用预定义的常量初始化
//!
//! 3. 消息块处理(对每个512位块)
//!    - 将块扩展为80个32位字
//!    - 进行4轮处理，每轮20步:
//!      * 0-19步: F(b,c,d) = (b AND c) OR ((NOT b) AND d)
//!      * 20-39步: F(b,c,d) = b XOR c XOR d
//!      * 40-59步: F(b,c,d) = (b AND c) OR (b AND d) OR (c AND d)
//!      * 60-79步: F(b,c,d) = b XOR c XOR d
//!
//! 4. 最终处理
//!    - 将5个寄存器的值连接
//!    - 输出160位的哈希值
//!
//! # 安全性
//!
//! SHA-1已被证明存在碰撞攻击风险，不建议用于安全关键场景。
//! 建议使用SHA-256或更新的哈希算法。
//!

use crate::Hasher;

// 初始哈希值
const H: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

// 常量表
const K: [u32; 4] = [
    0x5A827999, // 0 <= t <= 19
    0x6ED9EBA1, // 20 <= t <= 39
    0x8F1BBCDC, // 40 <= t <= 59
    0xCA62C1D6, // 60 <= t <= 79
];

pub struct SHA1 {
    state: [u32; 5],   // 哈希状态 (A, B, C, D, E)
    total_len: u64,    // 已处理的字节数
    buffer: [u8; 64],  // 数据缓冲区
    buffer_len: usize, // 缓冲区中有效数据长度
}

impl SHA1 {
    pub fn new() -> SHA1 {
        SHA1 {
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
        let mut w = [0u32; 80];

        // 将输入数据转换为32位字数组 (大端序)
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        // 扩展消息块
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        // 初始化工作变量
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        // 主循环
        for t in 0..80 {
            let (f, k) = match t {
                0..=19 => (Self::f(b, c, d), K[0]),
                20..=39 => (Self::h(b, c, d), K[1]),
                40..=59 => (Self::g(b, c, d), K[2]),
                60..=79 => (Self::h(b, c, d), K[3]),
                _ => unreachable!(),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[t]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // 更新状态
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }

    pub fn finalize(&mut self) -> [u8; 20] {
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
        let mut result = [0u8; 20];
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

    // SHA1辅助函数
    #[inline]
    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }

    #[inline]
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }

    #[inline]
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }
}

impl Hasher for SHA1 {
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
        let mut sha1 = SHA1::new();
        let result = sha1.finalize();
        assert_eq!(
            hex::encode(result),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_hello_world() {
        let mut sha1 = SHA1::new();
        sha1.update(b"Hello, World!");
        let result = sha1.finalize();
        assert_eq!(
            hex::encode(result),
            "0a0a9f2a6772942557ab5355d76af442f8f65e01"
        );
    }

    #[test]
    fn test_long_input() {
        let mut sha1 = SHA1::new();
        sha1.update(b"The quick brown fox jumps over the lazy dog");
        let result = sha1.finalize();
        assert_eq!(
            hex::encode(result),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn test_multiple_updates() {
        let mut sha1 = SHA1::new();
        sha1.update(b"Hello, ");
        sha1.update(b"World!");
        let result = sha1.finalize();
        assert_eq!(
            hex::encode(result),
            "0a0a9f2a6772942557ab5355d76af442f8f65e01"
        );
    }
}
