//! MD5 (Message Digest Algorithm 5) 哈希算法实现
//!
//! MD5是一种广泛使用的密码散列函数，由Ron Rivest在1991年设计，用于生成128位(16字节)的哈希值。
//!
//! # 算法步骤
//!
//! 1. 消息填充
//!    - 在消息末尾添加一个1位
//!    - 添加0位直到消息长度满足 448 mod 512
//!    - 添加64位的原始消息长度
//!
//! 2. 初始化MD缓冲区
//!    - 设置四个32位寄存器 (A,B,C,D)
//!    - 使用预定义的初始值
//!
//! 3. 处理消息块(每块512位)
//!    - 将每个块分为16个32位字
//!    - 执行4轮操作,每轮16步
//!    - 每步使用不同的非线性函数F,G,H,I
//!    - 使用预计算的正弦函数值作为常量
//!    - 进行位移和模加运算
//!
//! 4. 输出
//!    - 连接A,B,C,D寄存器的值
//!    - 产生128位的最终哈希值
//!
//! # 特点
//! - 快速:设计优化用于32位处理器
//! - 简单:仅使用基本的位运算
//! - 雪崩效应:输入的微小变化会导致输出的显著不同
//! - 注意:不再建议用于安全用途,因为已被证明存在碰撞攻击

use crate::Hasher;

pub struct MD5 {
    state: [u32; 4],  // A B C D 四个寄存器
    total_len: u64,   // 已处理的字节数
    buffer: [u8; 64], // 数据缓冲区
    buffer_len: usize,
}

const H: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
// 常量表
const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

impl MD5 {
    pub fn new() -> MD5 {
        MD5 {
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
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        // 将输入数据转换为32位字数组
        let mut x = [0u32; 16];

        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        // 主循环
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => (Self::f(b, c, d), i),
                16..=31 => (Self::g(b, c, d), (5 * i + 1) % 16),
                32..=47 => (Self::h(b, c, d), (3 * i + 5) % 16),
                48..=63 => (Self::i(b, c, d), (7 * i) % 16),
                _ => unreachable!(),
            };

            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(x[g])
                    .rotate_left(S[i]),
            );
            a = temp;
        }

        // 更新状态
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
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

        // 添加消息长度（以位为单位）
        let bits_len = total_len * 8;
        self.buffer[56..64].copy_from_slice(&bits_len.to_le_bytes());

        let temp = self.buffer;
        self.transform(&temp);

        // 输出结果
        let mut result = [0u8; 16];
        for (i, &state) in self.state.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&state.to_le_bytes());
        }
        self.reset();
        result
    }

    pub fn reset(&mut self) {
        self.state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
        self.total_len = 0;
        self.buffer = [0; 64];
        self.buffer_len = 0;
    }

    #[inline]
    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }

    #[inline]
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & z) | (y & !z)
    }

    #[inline]
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    #[inline]
    fn i(x: u32, y: u32, z: u32) -> u32 {
        y ^ (x | !z)
    }
}

impl Hasher for MD5 {
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
    fn test_new_md5() {
        let md5 = MD5::new();
        assert_eq!(md5.state, [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);
        assert_eq!(md5.total_len, 0);
        assert_eq!(md5.buffer_len, 0);
    }

    #[test]
    fn test_empty_string() {
        let mut md5 = MD5::new();
        let hash = md5.finalize();
        assert_eq!(hex::encode(hash), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_simple_string() {
        let mut md5 = MD5::new();
        md5.update(b"hello");
        let hash = md5.finalize();
        assert_eq!(hex::encode(hash), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_long_string() {
        let mut md5 = MD5::new();
        let input = "abcdefghijklmnopqrstuvwxyz".repeat(10);
        md5.update(input.as_bytes());
        let hash = md5.finalize();
        assert_eq!(hex::encode(hash), "4e6405697346169610a3a39991c48321");
    }

    #[test]
    fn test_multiple_updates() {
        let mut md5 = MD5::new();
        md5.update(b"hello ");
        md5.update(b"world");
        let hash = md5.finalize();
        assert_eq!(hex::encode(hash), "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn test_reset() {
        let mut md5 = MD5::new();
        md5.update(b"hello");
        md5.reset();
        md5.update(b"world");
        let hash = md5.finalize();
        assert_eq!(hex::encode(hash), "7d793037a0760186574b0282f2f435e7");
    }

    #[test]
    fn test_hash_trait() {
        let mut hasher: Box<dyn Hasher> = Box::new(MD5::new());
        hasher.update(b"hello");
        let result = hasher.finalize();
        assert_eq!(hex::encode(result), "5d41402abc4b2a76b9719d911017c592");
    }
}
