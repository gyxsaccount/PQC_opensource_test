# libSSH2 后量子迁移测试报告

生成时间: 2026-09-16T09:02:46.4870879Z
基线工具: OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2

## 配置模式

- **M1-soft**: 推荐: 服务端保留经典算法回退 (渐进迁移) (目标: post-quantum-target)
- **M2-strict**: 严格: 服务端仅启用 PQ 算法 (硬迁移, 用于断点检测) (目标: post-quantum-strict)

## 汇总

| 指标 | 值 |
|---|---|
| 总场景数 | 8 |
| 断点场景数 | 2 |
| 安全场景数 | 6 |

## 逐场景协商结果

| 场景 | KEX | Hostkey | Cipher | MAC | 断点 |
|---|---|---|---|---|---|
| **M1-C1: 旧客户端 → 旧服务端 (pre-PQ→pre-PQ)** | matched: diffie-hellman-group1-sha1 | matched: ssh-ed25519 | matched: aes128-ctr | matched: hmac-sha2-256 | 无 |
| **M1-C2: 旧客户端 → 新服务端 (pre-PQ→hybrid)** | matched: diffie-hellman-group14-sha256 | matched: ssh-ed25519 | matched: aes128-ctr | matched: hmac-sha2-256 | 无 |
| **M1-C3: 新客户端 → 旧服务端 (hybrid→pre-PQ)** | matched: sntrup761x25519-sha512@openssh.com | matched: ssh-ed25519 | matched: aes256-gcm@openssh.com | matched: hmac-sha2-256-etm@openssh.com | 无 |
| **M1-C4: 新客户端 → 新服务端 (hybrid→hybrid)** | matched: mlkem768x25519-sha256 | matched: ssh-ed25519+ml-dsa-44 | matched: aes256-gcm@openssh.com | matched: hmac-sha2-256-etm@openssh.com | 无 |
| **M2-C1: 旧客户端 → 旧服务端 (pre-PQ→pre-PQ)** | matched: diffie-hellman-group1-sha1 | matched: ssh-ed25519 | matched: aes128-ctr | matched: hmac-sha2-256 | 无 |
| **M2-C2: 旧客户端 → 新服务端 (pre-PQ→hybrid)** | MISMATCH | MISMATCH | matched: aes128-gcm@openssh.com | matched: hmac-sha2-256-etm@openssh.com | **kex, hostkey** |
| **M2-C3: 新客户端 → 旧服务端 (hybrid→pre-PQ)** | matched: sntrup761x25519-sha512@openssh.com | MISMATCH | matched: aes256-gcm@openssh.com | matched: hmac-sha2-256-etm@openssh.com | **hostkey** |
| **M2-C4: 新客户端 → 新服务端 (hybrid→hybrid)** | matched: mlkem768x25519-sha256 | matched: ssh-ed25519+ml-dsa-44 | matched: aes256-gcm@openssh.com | matched: hmac-sha2-256-etm@openssh.com | 无 |

## 断点详情

- **C2: 旧客户端 → 新服务端 (pre-PQ→hybrid)**: 失败类别 = kex, hostkey
- **C3: 新客户端 → 旧服务端 (hybrid→pre-PQ)**: 失败类别 = hostkey

### 断点分析

| 断点分类 | 对应案例 | 解释 |
|---|---|---|
| KEX | M2-C2 | 旧客户端不认识 mlkem768x25519-sha256, 服务端无经典回退 - 无共同 KEX |
| Hostkey | M2-C2 | 旧客户端不认识 ssh-ed25519+ml-dsa-44, 服务端无纯 ssh-ed25519 - 无共同签名 |
| Cipher/MAC | - | 若保持 `aes256-gcm` / `hmac-sha2-256`, 新旧两端通常无断点 |

> 断点消除策略: 迁移过渡期服务端必须保留经典算法双轨运行 (KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,...)。

## 自实现代码位置

| 文件 | 功能 |
|---|---|
| self_implemented/hybrid_kex.c/.h | ML-KEM-768 + X25519 混合 KEX |
| self_implemented/hybrid_signature.c/.h | ML-DSA-44 + Ed25519 混合签名 |
| self_implemented/libssh2_pq.patch | libssh2 集成补丁 |

详见 VERSION_MATRIX.md(版本清单) 和 BREAKPOINTS.md(断点分析)。
