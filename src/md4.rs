//! MD4 哈希算法实现
//!
//! MD4 (Message Digest Algorithm 4) 是一种密码散列函数，由 Ron Rivest 在1990年设计。
//! 它产生一个128位(16字节)的哈希值。
//!
//! # 算法步骤
//!
//! 1. 填充消息
//!    - 在消息末尾添加一个1位，然后添加0位直到长度满足 448 mod 512
//!    - 添加64位的原始消息长度
//!
//! 2. 初始化缓冲区
//!    - 设置四个32位寄存器 (A,B,C,D)
//!    - 使用预定义的初始值
//!
//! 3. 处理消息块
//!    - 将输入分成512位的块
//!    - 每个块分三轮处理:
//!      - 第一轮: 使用函数 F(x,y,z) = (x & y) | (~x & z)
//!      - 第二轮: 使用函数 G(x,y,z) = (x & y) | (x & z) | (y & z)
//!      - 第三轮: 使用函数 H(x,y,z) = x ^ y ^ z
//!
//! 4. 输出
//!    - 最终的哈希值是四个寄存器的级联
//!
//! # 安全性
//!
//! 注意：MD4已被证明不够安全，不建议用于安全关键型应用。
//! 建议使用更安全的算法如SHA-256或SHA-3。
//!

use crate::Hasher;

// 初始状态 (A, B, C, D)
const INIT_STATE: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

pub struct MD4 {
    state: [u32; 4],   // 哈希状态 (A, B, C, D)
    total_len: u64,    // 已处理的字节数
    buffer: [u8; 64],  // 数据缓冲区
    buffer_len: usize, // 缓冲区中有效数据长度
}

impl MD4 {
    pub fn new() -> MD4 {
        MD4 {
            state: INIT_STATE,
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
        // 将输入数据转换为32位字数组 (小端序)
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        // 保存原始状态
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        // 第一轮 (16次操作)
        for i in 0..4 {
            a = Self::round1_op(a, b, c, d, x[i * 4], 3);
            d = Self::round1_op(d, a, b, c, x[i * 4 + 1], 7);
            c = Self::round1_op(c, d, a, b, x[i * 4 + 2], 11);
            b = Self::round1_op(b, c, d, a, x[i * 4 + 3], 19);
        }

        // 第二轮 (16次操作)
        for i in 0..4 {
            a = Self::round2_op(a, b, c, d, x[i], 3);
            d = Self::round2_op(d, a, b, c, x[i + 4], 5);
            c = Self::round2_op(c, d, a, b, x[i + 8], 9);
            b = Self::round2_op(b, c, d, a, x[i + 12], 13);
        }

        // 第三轮 (16次操作)
        for i in [0, 2, 1, 3] {
            a = Self::round3_op(a, b, c, d, x[i], 3);
            d = Self::round3_op(d, a, b, c, x[i + 8], 9);
            c = Self::round3_op(c, d, a, b, x[i + 4], 11);
            b = Self::round3_op(b, c, d, a, x[i + 12], 15);
        }

        // 更新状态
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }

    fn round1_op(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
        a.wrapping_add(Self::f(b, c, d))
            .wrapping_add(x)
            .rotate_left(s)
    }

    fn round2_op(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
        a.wrapping_add(Self::g(b, c, d))
            .wrapping_add(x)
            .wrapping_add(0x5A827999)
            .rotate_left(s)
    }

    fn round3_op(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
        a.wrapping_add(Self::h(b, c, d))
            .wrapping_add(x)
            .wrapping_add(0x6ED9EBA1)
            .rotate_left(s)
    }

    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }

    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }

    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    pub fn finalize(&mut self) -> [u8; 16] {
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

        // 添加消息长度（以位为单位，小端序）
        let bits_len = total_len * 8;
        self.buffer[56..64].copy_from_slice(&bits_len.to_le_bytes());
        let temp = self.buffer;
        self.transform(&temp);

        // 输出结果（小端序）
        let mut result = [0u8; 16];
        for (i, &state) in self.state.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&state.to_le_bytes());
        }
        self.reset();
        result
    }

    pub fn reset(&mut self) {
        self.state = INIT_STATE;
        self.total_len = 0;
        self.buffer = [0; 64];
        self.buffer_len = 0;
    }
}

impl Hasher for MD4 {
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
        let mut md4 = MD4::new();
        let result = md4.finalize();
        assert_eq!(hex::encode(result), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_abc() {
        let mut md4 = MD4::new();
        md4.update(b"abc");
        let result = md4.finalize();
        assert_eq!(hex::encode(result), "a448017aaf21d8525fc10ae87aa6729d");
    }

    #[test]
    fn test_message_digest() {
        let mut md4 = MD4::new();
        md4.update(b"message digest");
        let result = md4.finalize();
        assert_eq!(hex::encode(result), "d9130a8164549fe818874806e1c7014b");
    }

    #[test]
    fn test_multiple_updates() {
        let mut md4 = MD4::new();
        md4.update(b"message ");
        md4.update(b"digest");
        let result = md4.finalize();
        assert_eq!(hex::encode(result), "d9130a8164549fe818874806e1c7014b");
    }
}
