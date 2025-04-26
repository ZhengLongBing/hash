//! CRC32 (Cyclic Redundancy Check) 哈希算法实现
//!
//! # 算法概述
//! CRC32是一种循环冗余校验算法,主要用于数据完整性校验。它将任意长度的输入数据
//! 映射为32位的校验值。
//!
//! # 处理步骤
//! 1. 初始化
//!    - CRC寄存器初始化为0xFFFFFFFF
//!    - 预计算256个8位CRC查找表项
//!
//! 2. 数据处理
//!    - 将输入数据按字节处理
//!    - 对每个字节:
//!      * 取CRC寄存器低8位与输入字节异或
//!      * 查表获得对应的CRC值
//!      * CRC寄存器右移8位与表项异或
//!
//! 3. 最终处理
//!    - 将最终的CRC值与0xFFFFFFFF异或
//!    - 输出32位校验值
//!
//! # 特点
//! - 计算速度快:使用查表法避免重复计算
//! - 检错能力强:可检测常见的突发性错误
//! - 实现简单:仅需异或和移位运算
//! - 广泛应用:在通信、存储等领域使用

use crate::Hasher;

// CRC32 多项式 (IEEE 802.3)
const CRC32_POLY: u32 = 0xEDB88320;

// 预计算的CRC32表
static CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if (crc & 1) == 1 {
                (crc >> 1) ^ CRC32_POLY
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

pub struct CRC32 {
    crc: u32,          // 当前CRC值
    total_len: u64,    // 已处理的字节数
    buffer: [u8; 64],  // 数据缓冲区
    buffer_len: usize, // 缓冲区中有效数据长度
}

impl CRC32 {
    pub fn new() -> CRC32 {
        CRC32 {
            crc: 0xFFFFFFFF, // 初始值
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
        for &byte in block {
            self.crc = (self.crc >> 8) ^ CRC32_TABLE[(self.crc ^ u32::from(byte)) as usize & 0xFF];
        }
    }

    pub fn finalize(&mut self) -> u32 {
        // 处理剩余数据
        if self.buffer_len > 0 {
            for i in 0..self.buffer_len {
                let byte = self.buffer[i];
                self.crc =
                    (self.crc >> 8) ^ CRC32_TABLE[(self.crc ^ u32::from(byte)) as usize & 0xFF];
            }
            self.total_len += self.buffer_len as u64;
            self.buffer_len = 0;
        }

        // 最终异或值
        let result = !self.crc;
        self.reset();
        result
    }

    pub fn reset(&mut self) {
        self.crc = 0xFFFFFFFF;
        self.total_len = 0;
        self.buffer = [0; 64];
        self.buffer_len = 0;
    }
}

impl Hasher for CRC32 {
    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn finalize(&mut self) -> Vec<u8> {
        self.finalize().to_be_bytes().to_vec()
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
        let mut crc32 = CRC32::new();
        let result = crc32.finalize();
        assert_eq!(result, 0x00000000);
    }

    #[test]
    fn test_simple_string() {
        let mut crc32 = CRC32::new();
        crc32.update(b"123456789");
        let result = crc32.finalize();
        assert_eq!(result, 0xCBF43926);
    }

    #[test]
    fn test_multiple_updates() {
        let mut crc32 = CRC32::new();
        crc32.update(b"1234");
        crc32.update(b"56789");
        let result = crc32.finalize();
        assert_eq!(result, 0xCBF43926);
    }
}
