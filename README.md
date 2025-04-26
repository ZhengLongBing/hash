# Rust Hash 算法库

这是一个用 Rust 实现的哈希算法集合库，提供了多种常用的哈希算法实现。

## 支持的算法

- CRC32: 循环冗余校验算法，主要用于数据完整性校验
- MD4: 消息摘要算法 4 (不推荐用于安全场景)
- MD5: 消息摘要算法 5 (不推荐用于安全场景)
- SHA-1: 安全哈希算法 1 (不推荐用于安全场景)
- SHA-256: 安全哈希算法 256
- SHA-512: 安全哈希算法 512
- SM3: 国密3算法，中国国家密码管理局发布的密码杂凑算法标准

## 安装

在你的 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
hash = { git = "https://github.com/your-username/hash" }
```

## 使用示例

所有哈希算法都实现了统一的 `Hasher` trait，使用方式一致：

```rust
use hash::{Hasher, md5::MD5, sha256::SHA256, sm3::SM3};

// MD5 示例
let mut hasher = MD5::new();
hasher.update(b"Hello, World!");
let result = hasher.finalize();
println!("MD5: {}", hex::encode(result));

// SHA-256 示例
let mut hasher = SHA256::new();
hasher.update(b"Hello, World!");
let result = hasher.finalize();
println!("SHA-256: {}", hex::encode(result));

// SM3 示例
let mut hasher = SM3::new();
hasher.update(b"Hello, World!");
let result = hasher.finalize();
println!("SM3: {}", hex::encode(result));
```

### 分块处理数据

所有哈希算法都支持分块处理数据：

```rust
let mut hasher = SHA256::new();
hasher.update(b"Hello, ");
hasher.update(b"World!");
let result = hasher.finalize();
```

### 重置哈希器

如果需要重复使用同一个哈希器实例：

```rust
let mut hasher = SHA256::new();
hasher.update(b"data1");
let result1 = hasher.finalize(); // 这会自动重置哈希器

// 或者手动重置
hasher.reset();
hasher.update(b"data2");
let result2 = hasher.finalize();
```

## 安全性建议

- 对于需要密码安全的场景，推荐使用 SHA-256、SHA-512 或 SM3
- MD4、MD5 和 SHA-1 已被证明存在安全漏洞，不建议用于安全关键场景
- CRC32 主要用于数据完整性校验，不适用于密码学场景

## 性能考虑

- 所有算法都经过优化，适合处理大量数据
- 使用内部缓冲区减少内存分配
- 支持流式处理，适合处理大文件或流数据

## 许可证

[待补充许可证信息]

## 贡献

欢迎提交 Issue 和 Pull Request！
