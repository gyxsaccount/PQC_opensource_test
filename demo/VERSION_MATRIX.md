# 版本与组件清单 (Version & Component Matrix)

> 本文档标注所有涉及组件的最低/推荐版本, 及哪些部分需要**自实现**。

## 1. 软件与组件版本表

| 组件 | 作用 | 迁移前版本(已验证) | 迁移后推荐版本 | 是否支持 PQC | 备注 |
|---|---|---|---|---|---|
| **libssh2** | 被测 SSH 库 | 1.11.x | 1.11.x + [自实现补丁] | 否 → 打补丁 | 原生无 PQ, 需集成 hybrid KEX/签名 |
| **OpenSSL** | libssh2 密码后端 | 3.0.x / 3.2.x | **>= 3.5.0** | 部分 (ML-KEM/ML-DSA 原生) | 3.5.0 起原生支持 FIPS 203/204/205 |
| **liboqs** | PQ 算法库(备选) | — | **>= 0.12.0** | 是 | 配合 oqs-provider 使用 |
| **oqs-provider** | OpenSSL provider | — | **>= 0.8.0** | 是 | 若不用 OpenSSL 3.5 原生则必装 |
| **OpenSSH** | 参考客户端/服务端 | 9.5p2 (Win 内置) | **>= 9.9** | 是 (mlkem768x25519) | 9.9 起支持 ML-KEM 混合 KEX; 9.5 已含 sntrup761x25519 |
| **CMake** | 构建系统 | 3.15+ | >= 3.15 | — | 需 OpenSSL 3.5 find_package 支持 |
| **VS Build Tools** | 编译工具链 | — | VS2022 (MSVC v143) | — | 需 C++ 桌面工作负载 |
| **NIST 标准** | 算法标准 | — | FIPS 203/204/205 | — | ML-KEM / ML-DSA / SLH-DSA |

## 2. 算法映射与版本支持矩阵

| SSH 协商类别 | 迁移前算法 | OpenSSL 3.5 | OpenSSH 9.9 | libssh2(官方) | libssh2(打补丁) |
|---|---|---|---|---|---|
| KEX | curve25519-sha256 | ✅ | ✅ | ✅ | ✅ |
| KEX | ecdh-sha2-nistp256 | ✅ | ✅ | ✅ | ✅ |
| **KEX(PQ)** | **mlkem768x25519-sha256** | ✅ | ✅ | ❌ | **🛠 自实现** |
| **KEX(PQ)** | **sntrup761x25519-sha512** | ✅ (经 liboqs) | ✅ | ❌ | **🛠 自实现** |
| Hostkey | ssh-ed25519 | ✅ | ✅ | ✅ | ✅ |
| Hostkey | rsa-sha2-512 | ✅ | ✅ | ✅ | ✅ |
| **Hostkey(PQ)** | **ssh-ed25519+ml-dsa-44** | ✅ | 部分 | ❌ | **🛠 自实现** |
| **Hostkey(PQ)** | **ssh-slh-dsa-sha2-128s** | ✅ | 部分 | ❌ | **🛠 自实现** |
| Cipher | aes256-gcm | ✅ | ✅ | ✅ | ✅ (无需改) |
| Cipher | chacha20-poly1305 | ✅ | ✅ | ✅ | ✅ (无需改) |
| MAC | hmac-sha2-256/512 | ✅ | ✅ | ✅ | ✅ (无需改) |

图例: ✅ 原生支持 / ❌ 不支持 / 🛠 需自实现或打补丁

## 3. 必须自实现的部分 (SELF-IMPLEMENT)

| 文件 | 功能 | 依赖 | 参考标准 |
|---|---|---|---|
| `demo/self_implemented/hybrid_kex.c/.h` | ML-KEM-768+X25519 混合 KEX | OpenSSL 3.5 EVP_KEM | RFC 9708, draft-ssh-hybrid |
| `demo/self_implemented/hybrid_signature.c/.h` | ML-DSA-44+Ed25519 混合签名 | OpenSSL 3.5 EVP_SIGNATURE | draft-ssh-hybrid-signatures-04 |
| `demo/self_implemented/libssh2_pq.patch` | libssh2 集成补丁 | libssh2 1.11 源码 | — |

> **重要结论**: OpenSSL 3.5 已原生提供 ML-KEM/ML-DSA 原语, 因此**算法本身无需自实现**;
> 需要自实现的是 **SSH 协议层的混合封装 (hybrid framing + 协商)**, 即上面 3 个文件。

## 4. 下载地址

- OpenSSL 3.5: https://github.com/openssl/openssl/releases
- liboqs: https://github.com/open-quantum-safe/liboqs/releases
- oqs-provider: https://github.com/open-quantum-safe/oqs-provider/releases
- libssh2: https://github.com/libssh2/libssh2/releases
- OpenSSH (Win32, 9.9+): https://github.com/PowerShell/Win32-OpenSSH/releases
