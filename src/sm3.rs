//! SM3 (国密3) 哈希算法实现
//!
//! # 算法概述
//! SM3是中国国家密码管理局发布的密码杂凑算法标准，可以生成256位(32字节)的消息摘要。
//! 它在安全性上类似于SHA-256，主要用于数字签名和验证。
//!
//! # 处理步骤
//!
//! 1. 消息填充
//!    - 在消息末尾添加一个1位
//!    - 添加0位直到长度满足 448 mod 512
//!    - 添加64位的原始消息长度
//!
//! 2. 初始化哈希值
//!    - 使用8个32位寄存器 (V0-V7)
//!    - 用预定义的初始值IV进行初始化
//!
//! 3. 消息分组处理
//!    - 将输入分成512位的块
//!    - 每个块:
//!      * 消息扩展：生成132个32位字
//!      * 压缩函数：进行64轮迭代压缩
//!      * 使用布尔函数FF和GG
//!      * 应用常量T和移位操作
//!
//! 4. 最终处理
//!    - 将8个寄存器的值连接
//!    - 输出256位的最终哈希值
//!
//! # 特点
//!
//! - 国产密码算法，适合国内应用场景
//! - 安全性与SHA-256相当
//! - 针对32位处理器优化
//! - 支持商用密码应用安全性要求
//!
//! # 应用场景
//!
//! - 数字签名
//! - 消息认证
//! - 随机数生成
//! - 完整性验证

use crate::Hasher;

// 初始值
const IV: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

pub struct SM3 {
    state: [u32; 8],   // 哈希状态 (V0-V7)
    total_len: u64,    // 已处理的字节数
    buffer: [u8; 64],  // 数据缓冲区
    buffer_len: usize, // 缓冲区中有效数据长度
}

impl SM3 {
    pub fn new() -> SM3 {
        SM3 {
            state: IV,
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
        // 1. 消息扩展
        let mut w = [0u32; 68];
        let mut w1 = [0u32; 64];

        // 将输入数据转换为32位字数组 (大端序)
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        // 消息扩展
        for j in 16..68 {
            w[j] = Self::p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
                ^ w[j - 13].rotate_left(7)
                ^ w[j - 6];
        }

        for j in 0..64 {
            w1[j] = w[j] ^ w[j + 4];
        }

        // 2. 压缩函数
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for j in 0..64 {
            let ss1 = a
                .rotate_left(12)
                .wrapping_add(e)
                .wrapping_add(Self::t(j).rotate_left(j))
                .rotate_left(7);
            let ss2 = ss1 ^ a.rotate_left(12);
            let tt1 = Self::ff(a, b, c, j)
                .wrapping_add(d)
                .wrapping_add(ss2)
                .wrapping_add(w1[j as usize]);
            let tt2 = Self::gg(e, f, g, j)
                .wrapping_add(h)
                .wrapping_add(ss1)
                .wrapping_add(w[j as usize]);

            d = c;
            c = b.rotate_left(9);
            b = a;
            a = tt1;
            h = g;
            g = f.rotate_left(19);
            f = e;
            e = Self::p0(tt2);
        }

        // 3. 更新状态
        self.state[0] ^= a;
        self.state[1] ^= b;
        self.state[2] ^= c;
        self.state[3] ^= d;
        self.state[4] ^= e;
        self.state[5] ^= f;
        self.state[6] ^= g;
        self.state[7] ^= h;
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
        self.state = IV;
        self.total_len = 0;
        self.buffer = [0; 64];
        self.buffer_len = 0;
    }

    // SM3辅助函数
    #[inline]
    fn t(j: u32) -> u32 {
        if j <= 15 { 0x79cc4519 } else { 0x7a879d8a }
    }

    #[inline]
    fn ff(x: u32, y: u32, z: u32, j: u32) -> u32 {
        if j <= 15 {
            x ^ y ^ z
        } else {
            (x & y) | (x & z) | (y & z)
        }
    }

    #[inline]
    fn gg(x: u32, y: u32, z: u32, j: u32) -> u32 {
        if j <= 15 {
            x ^ y ^ z
        } else {
            (x & y) | (!x & z)
        }
    }

    #[inline]
    fn p0(x: u32) -> u32 {
        x ^ x.rotate_left(9) ^ x.rotate_left(17)
    }

    #[inline]
    fn p1(x: u32) -> u32 {
        x ^ x.rotate_left(15) ^ x.rotate_left(23)
    }
}

impl Hasher for SM3 {
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
        let mut sm3 = SM3::new();
        let result = sm3.finalize();
        assert_eq!(
            hex::encode(result),
            "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
        );
    }

    #[test]
    fn test_abc() {
        let mut sm3 = SM3::new();
        sm3.update(b"abc");
        let result = sm3.finalize();
        assert_eq!(
            hex::encode(result),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
    }

    #[test]
    fn test_long_input() {
        let mut sm3 = SM3::new();
        sm3.update(b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        let result = sm3.finalize();
        assert_eq!(
            hex::encode(result),
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
        );
    }

    #[test]
    fn test_multiple_updates() {
        let mut sm3 = SM3::new();
        sm3.update(b"ab");
        sm3.update(b"c");
        let result = sm3.finalize();
        assert_eq!(
            hex::encode(result),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
    }
}
