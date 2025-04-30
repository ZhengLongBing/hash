//! SHA-512 (Secure Hash Algorithm 512) 哈希算法实现
//!
//! # 算法概述
//! SHA-512是SHA-2家族中最强大的哈希算法之一，可以生成512位(64字节)的消息摘要。
//! 它广泛用于数字签名、密码存储等安全场景。
//!
//! # 处理步骤
//!
//! 1. 消息填充
//!    - 在消息末尾添加一个1位
//!    - 添加0位直到长度满足 896 mod 1024
//!    - 添加128位的原始消息长度
//!
//! 2. 初始化哈希值
//!    - 使用8个64位寄存器 (A,B,C,D,E,F,G,H)
//!    - 用前8个质数的平方根小数部分的前64位初始化
//!
//! 3. 消息块处理(对每个1024位块)
//!    - 将块扩展为80个64位字
//!    - 使用以下函数:
//!      * Ch(x,y,z) = (x AND y) XOR ((NOT x) AND z)
//!      * Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)
//!      * Σ0(x) = ROTR(28,x) XOR ROTR(34,x) XOR ROTR(39,x)
//!      * Σ1(x) = ROTR(14,x) XOR ROTR(18,x) XOR ROTR(41,x)
//!
//! 4. 压缩函数
//!    - 进行80轮更新
//!    - 每轮使用不同的常量K[i]
//!    - 更新8个工作变量
//!
//! 5. 最终处理
//!    - 将8个寄存器的值连接
//!    - 输出512位的哈希值
//!
//! # 安全性
//! - 目前没有发现任何有效的攻击方法
//! - 被广泛认为是最安全的哈希算法之一
//! - 适用于高安全性要求的场景

use crate::Hasher;

// 初始哈希值（前8个质数的平方根小数部分前64位）
const H: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

// 轮常量（前80个质数的立方根小数部分前64位）
const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

pub struct SHA512 {
    state: [u64; 8],   // 哈希状态 (A, B, C, D, E, F, G, H)
    total_len: u128,   // 已处理的字节数（使用u128避免溢出）
    buffer: [u8; 128], // 数据缓冲区
    buffer_len: usize, // 缓冲区中有效数据长度
}

impl SHA512 {
    pub fn new() -> SHA512 {
        SHA512 {
            state: H,
            total_len: 0,
            buffer: [0; 128],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        let mut input_idx = 0;

        // 处理之前的剩余数据
        if self.buffer_len > 0 {
            while self.buffer_len < 128 && input_idx < input.len() {
                self.buffer[self.buffer_len] = input[input_idx];
                self.buffer_len += 1;
                input_idx += 1;
            }

            if self.buffer_len == 128 {
                let temp = self.buffer;
                self.transform(&temp);
                self.buffer_len = 0;
                self.total_len += 128;
            }
        }

        // 处理完整的128字节块
        while input_idx + 128 <= input.len() {
            self.transform(&input[input_idx..input_idx + 128]);
            input_idx += 128;
            self.total_len += 128;
        }

        // 保存剩余数据
        while input_idx < input.len() {
            self.buffer[self.buffer_len] = input[input_idx];
            self.buffer_len += 1;
            input_idx += 1;
        }
    }

    fn transform(&mut self, block: &[u8]) {
        let mut w = [0u64; 80];

        // 将输入数据转换为64位字数组 (大端序)
        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                block[i * 8],
                block[i * 8 + 1],
                block[i * 8 + 2],
                block[i * 8 + 3],
                block[i * 8 + 4],
                block[i * 8 + 5],
                block[i * 8 + 6],
                block[i * 8 + 7],
            ]);
        }

        // 扩展消息调度表
        for i in 16..80 {
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
        for i in 0..80 {
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

    pub fn finalize(&mut self) -> [u8; 64] {
        let total_len = self.total_len + self.buffer_len as u128;

        // 添加填充位
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // 计算需要的填充长度
        if self.buffer_len > 112 {
            // 如果剩余空间不足112字节，填充0至128字节并处理
            while self.buffer_len < 128 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            let temp = self.buffer;
            self.transform(&temp);
            self.buffer_len = 0;
        }

        // 填充0直到112字节
        while self.buffer_len < 112 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }

        // 添加消息长度（以位为单位，大端序）
        let bits_len = total_len * 8;
        self.buffer[112..128].copy_from_slice(&bits_len.to_be_bytes());
        let temp = self.buffer;
        self.transform(&temp);

        // 输出结果（大端序）
        let mut result = [0u8; 64];
        for (i, &state) in self.state.iter().enumerate() {
            result[i * 8..(i + 1) * 8].copy_from_slice(&state.to_be_bytes());
        }
        self.reset();
        result
    }

    pub fn reset(&mut self) {
        self.state = H;
        self.total_len = 0;
        self.buffer = [0; 128];
        self.buffer_len = 0;
    }

    // SHA512辅助函数
    #[inline]
    fn ch(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (!x & z)
    }

    #[inline]
    fn maj(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline]
    fn sigma0(x: u64) -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
    }

    #[inline]
    fn sigma1(x: u64) -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
    }

    #[inline]
    fn sigma0_upper(x: u64) -> u64 {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    #[inline]
    fn sigma1_upper(x: u64) -> u64 {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }
}

impl Hasher for SHA512 {
    fn block_size(&self) -> usize {
        128
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
        let mut sha512 = SHA512::new();
        let result = sha512.finalize();
        assert_eq!(
            hex::encode(result),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn test_hello_world() {
        let mut sha512 = SHA512::new();
        sha512.update(b"Hello, World!");
        let result = sha512.finalize();
        assert_eq!(
            hex::encode(result),
            "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387"
        );
    }

    #[test]
    fn test_long_input() {
        let mut sha512 = SHA512::new();
        sha512.update(b"The quick brown fox jumps over the lazy dog");
        let result = sha512.finalize();
        assert_eq!(
            hex::encode(result),
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
        );
    }

    #[test]
    fn test_multiple_updates() {
        let mut sha512 = SHA512::new();
        sha512.update(b"Hello, ");
        sha512.update(b"World!");
        let result = sha512.finalize();
        assert_eq!(
            hex::encode(result),
            "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387"
        );
    }
}
