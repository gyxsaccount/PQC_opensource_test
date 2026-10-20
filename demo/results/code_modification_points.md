# libSSH2 后量子迁移 — 代码修改点明细

> 基于 libssh2 **1.11.0** 源码树（`demo/libssh2_source/libssh2-libssh2-1.11.0/`）
> 实际定位的修改位置。行号为该版本源码实测行号。
> 配套补丁: `demo/self_implemented/libssh2_pq.patch`

---

## 0. 自实现声明（SELF-IMPLEMENT）

> **libssh2 官方软件本身【不具备】后量子能力**，本项目为实现 PQC 迁移
> 自实现了以下 SSH 协议层封装（算法原语来自 OpenSSL 3.5，非本项目实现）。

| 能力 | libssh2 是否原生具备 | 本项目自实现位置 |
|---|---|---|
| 后量子 KEX 算法注册 (`mlkem768x25519-sha256`) | ❌ 不具备 | `self_implemented/hybrid_kex.c` + `kex.c` 补丁 |
| 两个共享密钥的 XOR 混合合并 | ❌ 不具备 | `hybrid_kex.c` 中 `xor_shared_secret()` (MOD-K1) |
| 混合 KEX 的封装/解封装 framing | ❌ 不具备 | `hybrid_kex.c` MOD-K7/K8 |
| 后量子签名注册 (`ssh-ed25519+ml-dsa-44`) | ❌ 不具备 | `self_implemented/hybrid_signature.c` + `hostkey.c` 补丁 |
| 混合签名双算法拼接 framing | ❌ 不具备 | `hybrid_signature.c` MOD-S1/S9/S10 |
| ML-KEM-768 / ML-DSA-44 算法本体 | ❌ libssh2 无 | ✅ **OpenSSL 3.5 原生提供**（本项目不实现） |

**实际运行时需要改成的样子**：
- 自实现代码（`hybrid_kex.c` / `hybrid_signature.c`）已补全为真实 OpenSSL 3.5
  EVP API 调用（见下文明细中的 `【MOD-K#】/【MOD-S#】` 标记）。
- 真正要跑起来，还需：
  1. 把两个 .c/.h 文件加入 libssh2 的 `CMakeLists.txt` 源文件列表；
  2. 打上 `libssh2_pq.patch` 注册算法条目；
  3. 用 OpenSSL 3.5+ 编译（`-DENABLE_POST_QUANTUM=ON`）。

---

## 1. 核心修改点总览

| # | 文件 | 行号 | 修改类型 | 用途 |
|---|---|---|---|---|
| 1 | `src/kex.c` | **L3040-3059** | 新增算法条目 | 注册 `mlkem768x25519-sha256` / `sntrup761x25519-sha512` KEX |
| 2 | `src/kex.h` | 新增声明 | 新增函数声明 | 声明 `_libssh2_kex_method_mlkem768x25519` 等 |
| 3 | `src/hostkey.c` | **L1275-1302** | 新增算法条目 | 注册 `ssh-ed25519+ml-dsa-44` 混合主机密钥 |
| 4 | `src/transport.c` | 协商匹配逻辑 | 修改匹配逻辑 | 混合算法名优先匹配 + 经典回退 |
| 5 | `src/openssl.h` | **L395-397** | 新增类型映射 | 桥接 OpenSSL 3.5 EVP_PKEY 类型 |
| 6 | `CMakeLists.txt` | **L281-303** | 新增选项 | `ENABLE_POST_QUANTUM` 开关 + OpenSSL 3.5 检测 |
| 7 | `demo/self_implemented/hybrid_kex.c` | 全文件 | 新增文件(已补全) | ML-KEM-768 + X25519 混合 KEX 实现 (MOD-K1~K11) |
| 8 | `demo/self_implemented/hybrid_signature.c` | 全文件 | 新增文件(已补全) | ML-DSA-44 + Ed25519 混合签名实现 (MOD-S1~S11) |

---

## 2. 修改点 1：KEX 算法注册表（src/kex.c:3040-3059）

**现状代码**（只含经典算法）:

```c
static const LIBSSH2_KEX_METHOD *libssh2_kex_methods[] = {
#if LIBSSH2_ED25519
    &kex_method_ssh_curve25519_sha256,          // L3042
    &kex_method_ssh_curve25519_sha256_libssh,   // L3043
#endif
#if LIBSSH2_ECDSA
    &kex_method_ecdh_sha2_nistp256,             // L3046
    &kex_method_ecdh_sha2_nistp384,             // L3047
    &kex_method_ecdh_sha2_nistp521,             // L3048
#endif
    &kex_method_diffie_helman_group_exchange_sha256,   // L3050
    ...
    NULL                                          // L3058
};
```

**修改后代码**（插入 PQ 混合 KEX，置顶优先）:

```diff
 static const LIBSSH2_KEX_METHOD *libssh2_kex_methods[] = {
+#if LIBSSH2_POST_QUANTUM
+    &kex_method_mlkem768x25519_sha256,      /* NEW 混合 KEX: ML-KEM-768 + X25519 */
+    &kex_method_sntrup761x25519_sha512,     /* NEW 混合 KEX: NTRU Prime + X25519 */
+#endif
 #if LIBSSH2_ED25519
     &kex_method_ssh_curve25519_sha256,
```

> **高亮**：`+` 行为新增代码。置于数组**最前**，确保协商时 PQ 算法优先被选择；
> 经典算法保留在尾部作回退（迁移敏捷性要求）。

---

## 3. 修改点 2：KEX 函数声明（src/kex.h）

**新增声明**（在现有 `_libssh2_kex_method_*` 声明旁）:

```diff
 int _libssh2_kex_method_curve25519_sha256(struct _LIBSSH2_KEX *kex,
                                           _libssh2_key_exchange_func_t phase);
+int _libssh2_kex_method_mlkem768x25519_sha256(struct _LIBSSH2_KEX *kex,
+                                              _libssh2_key_exchange_func_t phase);
+int _libssh2_kex_method_sntrup761x25519_sha512(struct _LIBSSH2_KEX *kex,
+                                              _libssh2_key_exchange_func_t phase);
```

> **高亮**：`+` 行为新增声明，供 kex.c 算法表引用。

---

## 4. 修改点 3：主机密钥方法表（src/hostkey.c:1275-1302）

**现状代码**（只含经典主机密钥）:

```c
static const LIBSSH2_HOSTKEY_METHOD *hostkey_methods[] = {
#if LIBSSH2_ECDSA
    &hostkey_method_ecdsa_ssh_nistp256,   // L1277
    ...
#endif
#if LIBSSH2_ED25519
    &hostkey_method_ssh_ed25519,          // L1285
    &hostkey_method_ssh_ed25519_cert,     // L1286
#endif
#if LIBSSH2_RSA
    ...
#endif
    NULL                                  // L1301
};
```

**修改后代码**（插入混合主机密钥，置顶）:

```diff
 static const LIBSSH2_HOSTKEY_METHOD *hostkey_methods[] = {
+#if LIBSSH2_POST_QUANTUM
+    &hostkey_method_ed25519_mldsa44,      /* NEW 混合签名: Ed25519 + ML-DSA-44 */
+#endif
 #if LIBSSH2_ECDSA
     &hostkey_method_ecdsa_ssh_nistp256,
```

> **高亮**：`+` 行为新增条目。`hostkey_method_ed25519_mldsa44`
> 的 sign/verify 回调指向 `hybrid_signature.c` 中的 `hybrid_sign` / `hybrid_verify`。

---

## 5. 修改点 4：传输层协商匹配（src/transport.c）

**现状逻辑**：逐条 `strcmp` 精确匹配 name-list，只认两端都列出的算法名。

**修改点**：在 `_libssh2_transport_send` / KEX 选择函数中加入混合算法优先匹配与经典回退:

```diff
 static const LIBSSH2_KEX_METHOD *
 choose_kex_method(...) {
     /* 现有 name-list 匹配逻辑 */
+
+    /* NEW: 混合算法优先 (PQ 在客户端列表中靠前) */
+    if(session->post_quantum_enabled) {
+        /* 1) 先尝试匹配 mlkem768x25519-sha256 */
+        /* 2) 无匹配时回退到经典 curve25519-sha256 (M1 软迁移) */
+    }
 }
```

> **高亮**：这是"断点消除"的代码层落点——
> 若服务端只支持经典算法，客户端自动回退；若服务端只支持 PQ，旧客户端无解（M2 断点）。

---

## 6. 修改点 5：OpenSSL 后端类型映射（src/openssl.h:395-397）

**现状代码**:

```c
#define libssh2_ed25519_ctx EVP_PKEY                    // L395
#define _libssh2_ed25519_free(ctx) EVP_PKEY_free(ctx)   // L397
```

**修改点**（新增 ML-KEM / ML-DSA 类型桥接，依赖 OpenSSL 3.5）:

```diff
 #define libssh2_ed25519_ctx EVP_PKEY
 #define _libssh2_ed25519_free(ctx) EVP_PKEY_free(ctx)
+
+/* NEW: OpenSSL 3.5+ 原生 PQ 原语桥接 */
+#if LIBSSH2_POST_QUANTUM
+#define libssh2_mlkem768_ctx EVP_PKEY_CTX   /* ML-KEM 密钥封装上下文 */
+#define libssh2_mldsa44_ctx  EVP_PKEY       /* ML-DSA 签名密钥 */
+#endif
```

> **高亮**：`+` 行为新增。libssh2 的 crypto 抽象层（`crypto.c`/`openssl.h`）
> 用宏将 OpenSSL 3.5 的 EVP 对象映射为 libssh2 内部类型，供 hybrid 代码复用。

---

## 7. 修改点 6：CMake 构建选项（CMakeLists.txt:281-303）

**现状代码**:

```cmake
if(CRYPTO_BACKEND STREQUAL "OpenSSL" OR NOT CRYPTO_BACKEND)
    find_package(OpenSSL ${SPECIFIC_CRYPTO_REQUIREMENT})   # L297
    if(OPENSSL_FOUND)
        set(CRYPTO_BACKEND "OpenSSL")                       # L300
        ...
    endif()
endif()
```

**修改点**（新增 PQ 开关 + OpenSSL 3.5 版本约束）:

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
     if(OPENSSL_FOUND)
+        if(ENABLE_POST_QUANTUM)
+            add_compile_definitions(LIBSSH2_POST_QUANTUM)
+            list(APPEND LIBSSH2_SOURCES hybrid_kex.c hybrid_signature.c)
+        endif()
         ...
```

> **高亮**：`+`/`-` 行为新增/改动。`-DENABLE_POST_QUANTUM=ON` 编译时才会
> 启用混合算法，默认 OFF 保持向后兼容（迁移敏捷性：默认产物不引入断点）。

---

## 8. 新增文件：自实现代码（demo/self_implemented/）

### 8.1 hybrid_kex.c —— ML-KEM-768 + X25519 混合密钥交换

**关键新增逻辑**（XOR 合并两个共享密钥）:

```diff
+/* NEW: 客户端阶段1 - 生成 X25519 临时密钥对 + ML-KEM-768 密钥对 */
+int hybrid_kex_client_round1(hybrid_kex_client_offer *offer,
+                             uint8_t x_secret[X25519_KEYLEN],
+                             uint8_t mlkem_sk[MLKEM768_SECLEN]);
+
+/* NEW: 服务端 - X25519 派生 + ML-KEM 封装, 输出混合共享密钥 */
+int hybrid_kex_server_round(const hybrid_kex_client_offer *offer,
+                            hybrid_kex_server_reply *reply,
+                            uint8_t shared[HYBRID_SS_LEN]);
+
+/* NEW: 客户端阶段2 - 解封装后 XOR 合并 */
+static void xor_shared_secret(uint8_t out[32],
+                              const uint8_t a[32],
+                              const uint8_t b[32]) {
+    for(int i = 0; i < 32; i++) out[i] = a[i] ^ b[i];
+}
```

> **高亮**：`+` 全为新增代码。`xor_shared_secret` 是混合 KEX 的**核心组合逻辑**：
> SSH 协议没有现成的"混合共享密钥"合并标准，必须自实现（RFC 9708 思路）。

### 8.2 hybrid_signature.c —— ML-DSA-44 + Ed25519 混合签名

**关键新增逻辑**（双签名拼接 framing）:

```diff
+/* NEW: 混合签名格式 = len(ed25519_sig)||ed25519_sig||len(ml_dsa_sig)||ml_dsa_sig */
+int hybrid_sign(const uint8_t *hybrid_sec,
+                const uint8_t *msg, size_t msg_len,
+                uint8_t *hybrid_sig, size_t *hybrid_sig_len);
+
+/* NEW: AND 语义验证 - 两个子签名都通过才算合法 */
+int hybrid_verify(const uint8_t *hybrid_pub, size_t hybrid_pub_len,
+                  const uint8_t *msg, size_t msg_len,
+                  const uint8_t *hybrid_sig, size_t hybrid_sig_len);
```

> **高亮**：`+` 全为新增代码。SSH 主机密钥格式没有"混合签名"类型，
> 需要自定义 framing（参考 draft-ssh-hybrid-signatures-04）。

---

## 9. 修改点与断点对应关系

| 断点场景 | 相关修改点 | 说明 |
|---|---|---|
| M2-C2 (旧客户端→仅PQ服务端) | 修改点 1/3/4 | 服务端删除经典算法 → 旧客户端匹配失败；客户端侧修改点 4 的"经典回退"无法救回 |
| M2-C3 (仅PQ客户端→旧服务端) | 修改点 3/4 | 客户端只发混合签名 → 旧服务端不识别；需修改点 3 保留纯 `ssh-ed25519` 兜底 |
| M1 全部正常 | 修改点 1/3 尾部保留经典 | 算法表尾部经典条目实现回退，断点清零 |

---

## 10. 修改文件清单（patch 内容）

```
include/libssh2.h       + PQ 算法名宏 (LIBSSH2_KEX_MLKEM768X25519 等)
src/kex.h               + 函数声明
src/kex.c               + 算法表条目 (L3040 区域)
src/hostkey.c           + 主机密钥表条目 (L1275 区域)
src/transport.c         + 混合协商匹配逻辑
src/openssl.h           + EVP_PKEY 类型桥接
src/crypto.c            + 后端注册注释
CMakeLists.txt          + ENABLE_POST_QUANTUM 选项
```

> 完整补丁见 `demo/self_implemented/libssh2_pq.patch`。
> **状态更新**：`hybrid_kex.c` / `hybrid_signature.c` 中原本 `[SELF-IMPLEMENT]`
> 占位的 OpenSSL EVP 调用**已补全为真实 OpenSSL 3.5 API**（各函数标注 `【MOD-K#】/【MOD-S#】`）。
> 剩余需人工确认项：
> - OpenSSL 3.5.0 的 ML-KEM raw 密钥导出如改用 `OSSL_PKEY_PARAM_PUB_KEY` 参数方式，
>   需替换 `EVP_PKEY_get_raw_public_key` 的调用（见 hybrid_kex.c MOD-K4 注释）。
> - ML-DSA-44 的 digest 名若用预哈希（pre-hash）模式，`EVP_DigestSignInit_ex`
>   的 digest 参数需改为 `"SHA512"` 并接入 `EVP_DigestSignUpdate` 流程。
