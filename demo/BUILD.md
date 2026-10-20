# BUILD.md — 完整迁移测试环境的构建步骤

> 本指南在具备 C 工具链 (VS2022 或 MinGW-w64) + CMake 的机器上执行。
> 当前受限环境 (无编译器) 下, demo 的基线采集与断点矩阵部分可直接运行,
> 构建 libssh2 部分需按本指南在完整工具链上执行。

## 0. 环境要求 (迁移后全功能)

- Windows 10/11 x64 或 Linux x64
- CMake >= 3.15
- VS2022 Build Tools (MSVC v143) 或 gcc >= 11
- (可选) OpenSSL 3.5 预编译包或源码构建
- 网络可访问 GitHub

## 1. 安装/构建 OpenSSL 3.5 (提供 PQ 原语)

```powershell
# 方式 A: 下载预编译包 (推荐)
#   https://github.com/openssl/openssl/releases
#   解压后设置环境变量:
$env:OPENSSL_ROOT_DIR = "D:\libs\openssl-3.5.0"

# 方式 B: 源码构建 (需 Perl + NASM)
#   git clone --branch openssl-3.5 https://github.com/openssl/openssl.git
#   cd openssl
#   perl Configure VC-WIN64A --prefix=D:\libs\openssl-3.5.0
#   nmake; nmake install_sw
```

验证 PQ 原语可用:
```powershell
& "D:\libs\openssl-3.5.0\bin\openssl.exe" list -kem-algorithms   # 应含 ML-KEM-768
& "D:\libs\openssl-3.5.0\bin\openssl.exe" list -signature-algorithms  # 应含 ML-DSA-44
```

## 2. 构建 libssh2 (迁移前基线)

```powershell
git clone https://github.com/libssh2/libssh2.git
cd libssh2
git checkout libssh2-1.11.0
cmake -S . -B build `
  -DOPENSSL_ROOT_DIR="$env:OPENSSL_ROOT_DIR" `
  -DCRYPTO_BACKEND=OpenSSL `
  -DBUILD_SHARED_LIBS=OFF `
  -DBUILD_EXAMPLES=ON
cmake --build build --config Release
```

运行 libssh2 自带示例 (连接测试服务端):
```powershell
.\build\Release\ssh2.exe host:22 user password "echo ok"
```

## 3. 打上后量子补丁并重编译 (迁移后)

```powershell
cd libssh2
git apply D:\PQC-test\libSSH2\demo\self_implemented\libssh2_pq.patch
# 将 hybrid_kex.c/h 与 hybrid_signature.c/h 复制到 src/
# 将 hybrid_kex.c/h 与 hybrid_signature.c/h 加入 CMakeLists.txt 的 libssh2_sources

cmake -S . -B build_pq `
  -DOPENSSL_ROOT_DIR="$env:OPENSSL_ROOT_DIR" `
  -DCRYPTO_BACKEND=OpenSSL `
  -DENABLE_POST_QUANTUM=ON
cmake --build build_pq --config Release
```

> **自实现代码状态**：`demo/self_implemented/hybrid_kex.c` / `hybrid_signature.c`
> 中的 OpenSSL 3.5 EVP 调用**已补全为真实 API**（各函数标注 `【MOD-K#】/【MOD-S#】`）。
> 若 OpenSSL 3.5.0 的 ML-KEM raw 接口有差异，按 `hybrid_kex.c` MOD-K4 注释调整；
> ML-DSA 若用预哈希模式，按 `hybrid_signature.c` MOD-S7 注释调整 digest 参数。

## 4. 部署后量子 SSH 服务端 (OpenSSH 9.9)

```powershell
# 下载 Win32-OpenSSH 9.9+: https://github.com/PowerShell/Win32-OpenSSH/releases
# 或 Linux: sudo apt install openssh-server (>= 9.9)
# 在 sshd_config 中启用混合 KEX:
#   KexAlgorithms mlkem768x25519-sha256,curve25519-sha256
```

## 5. 运行完整迁移测试

```powershell
# 1) 基线采集
.\scripts\capture_baseline.ps1

# 2) 断点矩阵
.\scripts\compatibility_matrix.ps1

# 3) 真实互通测试 (需服务端就绪):
#    旧客户端(libssh2 1.11 未打补丁) → 新服务端(OpenSSH 9.9, 仅混合)  → 预期失败 [C2 断点]
#    新客户端(libssh2 1.11 打补丁)   → 旧服务端(OpenSSH 9.5)           → 预期成功 [C3 回退]
#    新客户端(打补丁)                → 新服务端(OpenSSH 9.9, 混合)     → 预期成功 [C4 PQ生效]
```

## 6. 常见问题

| 问题 | 原因 | 解决 |
|---|---|---|
| OpenSSL 3.5 中无 ML-KEM | 版本过旧 | 确认 >= 3.5.0, `openssl list -kem-algorithms` |
| libssh2 编译报缺 EVP_KEM | 链接了旧 OpenSSL | 检查 OPENSSL_ROOT_DIR 指向 3.5 |
| 打补丁冲突 | libssh2 版本不符 | 使用 libssh2-1.11.0 精确版本 |
| 旧客户端连不上新服务端 | 服务端删除了经典算法 | 恢复 `KexAlgorithms curve25519-sha256,...` 双轨 |
