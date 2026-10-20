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

### 如何阅读这张表 (详细说明)

#### 表头 (4 列算法 + 1 列结果)

| 列 | 含义 | 判定 |
|---|---|---|
| **KEX** | 密钥交换算法: 如何协商出加密密钥 (本表关注是否选出后量子混合 KEX) | `matched: <算法>` = 协商成功 |
| **Hostkey** | 主机密钥算法: 如何验证服务器身份 | `MISMATCH` = 无共同算法 = 断点 |
| **Cipher** | 对称加密算法: 传输数据加密 | |
| **MAC** | 完整性校验算法: 防篡改 | |
| **断点** | 4 类中协商失败的类别 | `无` = 握手成功; 列出类别 = 连接失败 |

> **核心规则**: SSH 握手必须 4 类算法每类都选出一个双方共有的算法。任一类别 `MISMATCH` → 连接直接失败。

#### 场景名含义 (M1/M2 × C1-C4)

**M1 / M2 = 服务端迁移模式**:

- **M1 (软迁移)**: 新服务端 = 经典 + 后量子算法**同时保留** (渐进式, 不伤旧客户端)
- **M2 (硬迁移)**: 新服务端 = **只留后量子**, 删光经典算法 (激进, 会切断旧客户端)

**C1-C4 = 客户端 × 服务端的 4 种组合**:

| 代号 | 客户端 | 服务端 | 一句话 |
|---|---|---|---|
| C1 | 旧 (无PQ) | 旧 (无PQ) | 两个老版本对话 |
| C2 | 旧 (无PQ) | 新 (含PQ) | 老客户端想连新服务器 |
| C3 | 新 (含PQ) | 旧 (无PQ) | 新客户端想连老服务器 |
| C4 | 新 (含PQ) | 新 (含PQ) | 两个新版本对话 (PQ 生效) |

#### 单元格值怎么读

- `matched: curve25519-sha256` = 双方协商成功, 选出了该算法 (客户端offer与服务端offer第一个交集)
- `MISMATCH` = 该类别双方**无共同算法**, 握手失败
- 带 `mlkem` / `sntrup` 的算法 = **后量子混合算法** (迁移目标)

#### 四行关键解读

| 场景 | 白话解读 | 结论 |
|---|---|---|
| **M1-C2** 旧客户端→新服务端(软) | 老客户端不会 PQ, 服务端"退一步"用经典算法 | 软迁移下老客户端不受影响 = 向后兼容 ✅ |
| **M1-C4** 新客户端→新服务端(软) | 双方都会 PQ, 选出 `mlkem768x25519-sha256` | 后量子算法真正生效 = 迁移目标达成 🎉 |
| **M2-C2** 旧客户端→新服务端(硬) | 老客户端只会经典, 服务端只留 PQ, 无交集 | **硬迁移切断所有老客户端** = 最大断点 ❌ |
| **M2-C3** 新客户端→旧服务端(硬客户端) | KEX 碰巧成功, 但签名只发混合, 老服务端不认 | 严格客户端也必须保留经典签名兜底 ❌ |

#### 核心结论

> 盯三件事: ① 有没有 `MISMATCH` (有=断点=连不上); ② M1 全绿 → 渐进迁移是安全路径;
> ③ M2 出现断点 → 激进迁移会伤老客户端, 必须等客户端全升级后才能用。

**推荐采用 M1 软迁移 (永远有回退、无断点); M2 硬迁移只在所有客户端升级完毕后使用。**

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

## 代码修改点（具体位置 + 高亮）

> 以下为在 libssh2 **1.11.0 源码树**中定位的**具体修改点**，行号为实测行号。
> 完整含 `diff` 高亮代码见 [code_modification_points.md](code_modification_points.md)。

### 修改点总览

| # | 文件 | 行号 | 修改类型 | 用途 |
|---|---|---|---|---|
| 1 | `src/kex.c` | **L3040-3059** | 新增算法条目 | 注册 `mlkem768x25519-sha256` / `sntrup761x25519-sha512` |
| 2 | `src/kex.h` | 新增 | 新增函数声明 | 声明混合 KEX 实现函数 |
| 3 | `src/hostkey.c` | **L1275-1302** | 新增算法条目 | 注册 `ssh-ed25519+ml-dsa-44` 混合主机密钥 |
| 4 | `src/transport.c` | 协商逻辑 | 修改 | 混合算法优先匹配 + 经典回退 |
| 5 | `src/openssl.h` | **L395-397** | 新增类型映射 | 桥接 OpenSSL 3.5 EVP_PKEY |
| 6 | `CMakeLists.txt` | **L281-303** | 新增选项 | `ENABLE_POST_QUANTUM` + OpenSSL 3.5 检测 |
| 7 | `self_implemented/hybrid_kex.c` | 全文件 | 新增 | 混合 KEX 实现 |
| 8 | `self_implemented/hybrid_signature.c` | 全文件 | 新增 | 混合签名实现 |

### 关键高亮示例

**① src/kex.c:3040-3059 — KEX 算法表插入点（置顶优先）**

```diff
 static const LIBSSH2_KEX_METHOD *libssh2_kex_methods[] = {
+#if LIBSSH2_POST_QUANTUM
+    &kex_method_mlkem768x25519_sha256,   /* NEW: ML-KEM-768 + X25519 */
+    &kex_method_sntrup761x25519_sha512,  /* NEW: NTRU Prime + X25519 */
+#endif
 #if LIBSSH2_ED25519
     &kex_method_ssh_curve25519_sha256,   /* 经典算法保留尾部 = 回退 */
```

**② src/hostkey.c:1275-1302 — 主机密钥表插入点**

```diff
 static const LIBSSH2_HOSTKEY_METHOD *hostkey_methods[] = {
+#if LIBSSH2_POST_QUANTUM
+    &hostkey_method_ed25519_mldsa44,     /* NEW: Ed25519 + ML-DSA-44 */
+#endif
 #if LIBSSH2_ECDSA
     &hostkey_method_ecdsa_ssh_nistp256,
```

**③ CMakeLists.txt:281-303 — 构建开关**

```diff
+option(ENABLE_POST_QUANTUM "Enable hybrid post-quantum algorithms (OpenSSL 3.5+)" OFF)
+
 if(CRYPTO_BACKEND STREQUAL "OpenSSL" OR NOT CRYPTO_BACKEND)
-    find_package(OpenSSL ${SPECIFIC_CRYPTO_REQUIREMENT})
+    if(ENABLE_POST_QUANTUM)
+        find_package(OpenSSL 3.5 REQUIRED)   /* 需要 ML-KEM/ML-DSA 原语 */
+    else()
+        find_package(OpenSSL ${SPECIFIC_CRYPTO_REQUIREMENT})
+    endif()
```

> 其余修改点（kex.h / transport.c / openssl.h / hybrid 实现）的完整
> 高亮 diff 代码见 [code_modification_points.md](code_modification_points.md)。

详见 VERSION_MATRIX.md(版本清单) 和 BREAKPOINTS.md(断点分析)。
