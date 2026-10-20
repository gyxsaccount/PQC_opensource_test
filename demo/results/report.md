# libSSH2 后量子迁移测试报告

生成时间: 2026-10-20T12:45:50.2367903Z
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
| **M1-C1: 客户端[传统] → 服务端[传统]** | matched: diffie-hellman-group1-sha1 | matched: ssh-ed25519 | matched: aes128-ctr | matched: hmac-sha2-256 | 无 |
| **M1-C2: 客户端[传统] → 服务端[混合]** | matched: diffie-hellman-group14-sha256 | matched: ssh-ed25519 | matched: aes128-ctr | matched: hmac-sha2-256 | 无 |
| **M1-C3: 客户端[混合] → 服务端[传统]** | matched: curve25519-sha256 | matched: ssh-ed25519 | matched: aes256-gcm@openssh.com | matched: hmac-sha2-256-etm@openssh.com | 无 |
| **M1-C4: 客户端[混合] → 服务端[混合]** | matched: mlkem768x25519-sha256 | matched: ssh-ed25519+ml-dsa-44 | matched: aes256-gcm@openssh.com | matched: hmac-sha2-256-etm@openssh.com | 无 |
| **M2-C1: 客户端[传统] → 服务端[传统]** | matched: diffie-hellman-group1-sha1 | matched: ssh-ed25519 | matched: aes128-ctr | matched: hmac-sha2-256 | 无 |
| **M2-C2: 客户端[传统] → 服务端[纯后量子]** | MISMATCH | MISMATCH | matched: aes128-gcm@openssh.com | matched: hmac-sha2-256-etm@openssh.com | **kex, hostkey** |
| **M2-C3: 客户端[纯后量子] → 服务端[传统]** | MISMATCH | MISMATCH | matched: aes256-gcm@openssh.com | matched: hmac-sha2-256-etm@openssh.com | **kex, hostkey** |
| **M2-C4: 客户端[纯后量子] → 服务端[纯后量子]** | matched: mlkem768x25519-sha256 | matched: ssh-ed25519+ml-dsa-44 | matched: aes256-gcm@openssh.com | matched: hmac-sha2-256-etm@openssh.com | 无 |

### 如何阅读这张表 (详细说明)

#### 表头 (4 列算法 + 1 列结果)

| 列 | 含义 | 判定 |
|---|---|---|
| **KEX** | 密钥交换算法: 如何协商出加密密钥 (本表关注是否选出后量子混合 KEX) | matched: <算法> = 协商成功 |
| **Hostkey** | 主机密钥算法: 如何验证服务器身份 | MISMATCH = 无共同算法 = 断点 |
| **Cipher** | 对称加密算法: 传输数据加密 | |
| **MAC** | 完整性校验算法: 防篡改 | |
| **断点** | 4 类中协商失败的类别 | 无 = 握手成功; 列出类别 = 连接失败 |

> **核心规则**: SSH 握手必须 4 类算法每类都选出一个双方共有的算法。任一类别 MISMATCH → 连接直接失败。

#### 场景名含义: 三种部署类型 (M1/M2 × C1-C4)

**每个端点的部署类型** (由算法集自动识别, 显示在场景标签的 [ ] 里):

| 类型 | 含义 | 算法组成 |
|---|---|---|
| **传统** | 只用经典算法, 无任何后量子 | 纯 ECDH/DH + RSA/ECDSA/Ed25519 |
| **混合** | 经典 + 后量子**同时部署** (渐进迁移) | mlkem768x25519 + curve25519 等并存 |
| **纯后量子** | **只**用后量子算法, 删光经典 (硬迁移) | 仅 mlkem768x25519 + ml-dsa-44 |

**M1 / M2 = 迁移模式**:

- **M1 (软迁移)**: 新服务端 = **混合** (经典 + 后量子同时保留, 不伤旧客户端)
- **M2 (硬迁移)**: 新服务端 = **纯后量子** (删光经典算法, 会切断旧客户端)

**C1-C4 = 客户端 × 服务端的 4 种组合** (场景标签直接写明双方类型):

| 代号 | 实际标签 | 一句话 |
|---|---|---|
| C1 | 客户端[传统] → 服务端[传统] | 迁移前环境, 双方纯经典 |
| C2 | 客户端[传统] → 服务端[混合/纯后量子] | 老客户端连新服务端 |
| C3 | 客户端[混合/纯后量子] → 服务端[传统] | 新客户端连老服务端 |
| C4 | 客户端[混合/纯后量子] → 服务端[混合/纯后量子] | 双方都是新环境 |

> 场景标签是**自动生成**的: 按实际算法集识别 [传统]/[混合]/[纯后量子], 不再用笼统的新旧表述。

#### 单元格值怎么读

- matched: curve25519-sha256 = 双方协商成功, 选出了该算法 (客户端offer与服务端offer第一个交集)
- MISMATCH = 该类别双方**无共同算法**, 握手失败
- 带 mlkem / sntrup 的算法 = **后量子混合算法** (迁移目标)

#### 四行关键解读 (对应本报告实际输出)

| 场景 | 白话解读 | 结论 |
|---|---|---|
| **M1-C2** 客户端[传统] → 服务端[混合] | 老客户端只会经典, 混合服务端退一步用经典算法回应 | 软迁移下老客户端不受影响 = 向后兼容 ✅ |
| **M1-C4** 客户端[混合] → 服务端[混合] | 双方都带后量子, 选出 mlkem768x25519-sha256 + ssh-ed25519+ml-dsa-44 | 后量子算法真正生效 = 迁移目标达成 🎉 |
| **M2-C2** 客户端[传统] → 服务端[纯后量子] | 老客户端只会经典, 服务端只留后量子, 无交集 | **硬迁移切断所有老客户端** = 最大断点 ❌ |
| **M2-C3** 客户端[纯后量子] → 服务端[传统] | 客户端只发后量子, 老服务端全不认 | 纯后量子客户端必须保留经典兜底才能连老服务端 ❌ |

#### 核心结论

> 盯三件事: ① 有没有 MISMATCH (有=断点=连不上); ② M1 全绿 → 渐进迁移是安全路径;
> ③ M2 出现断点 → 激进迁移会伤老客户端, 必须等客户端全升级后才能用。

**推荐采用 M1 软迁移 (永远有回退、无断点); M2 硬迁移只在所有客户端升级完毕后使用。**

## 断点详情

- **C2: 客户端[传统] → 服务端[纯后量子]**: 失败类别 = kex, hostkey
- **C3: 客户端[纯后量子] → 服务端[传统]**: 失败类别 = kex, hostkey

### 断点分析

| 断点分类 | 对应案例 | 解释 |
|---|---|---|
| KEX | M2-C2 | 旧客户端不认识 mlkem768x25519-sha256, 服务端无经典回退 - 无共同 KEX |
| Hostkey | M2-C2 | 旧客户端不认识 ssh-ed25519+ml-dsa-44, 服务端无纯 ssh-ed25519 - 无共同签名 |
| Cipher/MAC | - | 若保持 `aes256-gcm` / `hmac-sha2-256`, 新旧两端通常无断点 |

> 断点消除策略: 迁移过渡期服务端必须保留经典算法双轨运行 (KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,...)。

## 官方 master 分支原生支持 ML-KEM (重要发现)

> libssh2 官方 **master 分支 (2026-04-03 起, PR #1644) 已原生支持混合 ML-KEM KEX**
> (基于 OpenSSL 3.5+)。官方最新 release 仍是 1.11.1 (不含 PQC),
> 此能力仅在 master 开发分支。详见 code_modification_points.md 第 1 节。

### 官方支持的 PQ 算法 (编译开关 LIBSSH2_MLKEM)

| KEX 算法名 | 组合 | 与 OpenSSH 9.9 对照 |
|---|---|---|
| mlkem768x25519-sha256 | ML-KEM-768 + X25519 | 同款 |
| mlkem768nistp256-sha256 | ML-KEM-768 + NIST P-256 | OpenSSH 无此款 |
| mlkem1024nistp384-sha384 | ML-KEM-1024 + NIST P-384 | OpenSSH 无此款 |

### 官方注册表 (src/kex.c L2846-2853)

```c
#if LIBSSH2_MLKEM
static const struct kex_method kex_method_ssh_mlkem768_x25519_sha256 = {
    "mlkem768x25519-sha256",                      /* L2848 */
    kex_method_mlkem768x25519_key_exchange,       /* L2849 */
    kex_method_mlkem768x25519_cleanup,            /* L2850 */
    KEX_METHOD_FLAG_REQ_SIGN_HOSTKEY,
};
#endif /* LIBSSH2_MLKEM */
```

### 官方 OpenSSL 3.5 KEM 后端 (src/openssl.c L2031-2186)

- 密钥生成 `ssh2_mlkem_new()`: `EVP_PKEY_CTX_new_from_name("ML-KEM-768")` -> `EVP_PKEY_keygen` -> `EVP_PKEY_get_raw_*`
- 解封装 `ssh2_mlkem_get_sk()`: `EVP_PKEY_decapsulate_init` -> `EVP_PKEY_decapsulate`
- 完整代码见 code_modification_points.md 第 1.3 节

### 官方 vs 自实现

| 对比项 | 官方 master | 本项目自实现 |
|---|---|---|
| ML-KEM-768 + X25519 混合 KEX | 原生 | 自实现 |
| **混合共享密钥合并方式 ⚠️** | **拼接 (concat)**: ML-KEM_ss(32) ‖ X25519_ss(32) = 64B → SHA256 (kex.c L2493/L2588) | **XOR 合并**: ML-KEM_ss ⊕ X25519_ss = 32B → SHA256 (hybrid_kex.c MOD-K1) |
| 需要打补丁 | 否 (已合入) | 是 |
| 发布状态 | 仅 master, 未进 release | 可在 1.11.x 集成 |
| 适用建议 | 能从 master 编译 -> 用官方 | 需停留 1.11.x -> 用自实现 |

> **⚠️ 关键差异点**：两共享密钥合并方式不同——官方与 OpenSSH 9.9 用**拼接 (concat)**，
> 自实现当前用 **XOR**。安全性等价，但**协议格式不兼容**：自实现客户端与官方/OpenSSH
> 服务端互通会握手失败。若以互通为目标，自实现应改用**拼接方式**（详见
> [code_modification_points.md](code_modification_points.md) 第 1.4 节）。

## 自实现代码位置

| 文件 | 功能 |
|---|---|
| self_implemented/hybrid_kex.c/.h | ML-KEM-768 + X25519 混合 KEX |
| self_implemented/hybrid_signature.c/.h | ML-DSA-44 + Ed25519 混合签名 |
| self_implemented/libssh2_pq.patch | libssh2 集成补丁 |

详见 VERSION_MATRIX.md(版本清单) 和 BREAKPOINTS.md(断点分析)。
