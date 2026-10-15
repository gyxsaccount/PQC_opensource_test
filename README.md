# libSSH2 后量子迁移测试 (PQC Migration Test)

针对开源软件 **libssh2**（SSH 协议数据传输）的后量子（Post-Quantum，PQC）迁移测试项目。
通过迁移前后算法对照、SSH 协商模拟与真实互通抓包，检测迁移过程中是否存在**阻碍或断点**，
评估并保证**迁移敏捷性**（渐进迁移、随时可回退）。

```
git clone --branch libssh2_test https://github.com/gyxsaccount/PQC_opensource_test.git
```

---

## 目录结构

```
libSSH2/
├── README.md                  ← 本文件 (总览)
├── demo/
│   ├── README.md              ← demo 用法简介
│   ├── VERSION_MATRIX.md      ← 组件/版本清单 + 自实现标注
│   ├── BREAKPOINTS.md         ← 断点成因、检测与消除策略
│   ├── BUILD.md               ← 完整编译打补丁 libssh2 的步骤
│   ├── scripts/               ← 6 个测试脚本 + 2 个算法目标配置
│   ├── self_implemented/      ← [SELF-IMPLEMENT] 混合 PQ 自实现代码 + libssh2 补丁
│   ├── results/               ← 测试结果 (JSON/MD/HTML)
│   └── libssh2_source/        ← libssh2 1.11.0 源码 (被测试对象)
└── .gitignore
```

---

## 1. 运行测试的环境要求

### 1.1 最低要求（算法对照 / 断点检测 / 真实互通抓包）

无需编译任何 C 代码，**Windows 自带 OpenSSH 客户端即可**：

| 组件 | 版本要求 | 说明 |
|---|---|---|
| Windows | 10/11 x64 | 含 PowerShell 5.1+ |
| OpenSSH 客户端 | 随系统自带即可 | 已验证 9.5p2；用于 `ssh -Q` 采集与 `ssh -vvv` 抓包 |
| 网络 | 可访问 github.com:22 | 真实互通测试可选；无法访问时可用 `-SkipLive` 跳过 |

### 1.2 完整要求（编译打补丁的 libssh2 并验证 PQ 握手）

| 组件 | 版本要求 | 用途 | 是否需要自实现 |
|---|---|---|---|
| C 工具链 | MinGW-w64 / LLVM-MinGW 或 VS2022 Build Tools | 编译 | 否 |
| CMake | >= 3.15 | 构建 liboqs / libssh2 | 否 |
| liboqs | >= 0.12.0 | 提供 ML-KEM-768 等 PQ 原语 | 否 |
| OpenSSL | >= 3.5.0 | ML-KEM/ML-DSA 原生支持（后端） | 否（算法原生）；混合封装需自实现 |
| libssh2 | 1.11.0 | 被测软件 | 打补丁集成 PQ（见 `self_implemented/`） |
| OpenSSH 服务端 | >= 9.9（参考） | PQ 混合 KEX 服务端 | 否 |

> **关键结论**：OpenSSL 3.5 / liboqs 已原生提供 ML-KEM/ML-DSA **算法原语**；
> 需要**自实现**的只是 **SSH 协议层的混合封装与协商逻辑**，见 `demo/self_implemented/`。

---

## 2. 依赖安装

### 2.1 直接运行 demo（无需安装任何依赖）

```powershell
# 只需 Windows 自带 OpenSSH 客户端
# 如果执行策略限制, 用 -ExecutionPolicy Bypass
PowerShell -ExecutionPolicy Bypass -File D:\PQC-test\libSSH2\demo\scripts\run_all.ps1
```

### 2.2 编译打补丁的 libssh2（完整 PQ 验证）

详见 `demo/BUILD.md`。核心步骤：

```powershell
# 1) 工具链 (winget 安装, 免管理员)
winget install Kitware.CMake -e
winget install MartinStorsjo.LLVM-MinGW.UCRT -e

# 2) 构建 liboqs (提供 ML-KEM-768)
cmake -S <liboqs源> -B <build> -G "MinGW Makefiles" -DBUILD_SHARED_LIBS=OFF
cmake --build <build> -j4
cmake --install <build>

# 3) 构建 OpenSSL 3.5 (原生 ML-KEM/ML-DSA; 需完整 Perl, Git 自带 perl 缺模块)
#    或用 slproweb / 官方 release 预编译包
perl Configure mingw64 --prefix=D:\libs\openssl-3.5.1
mingw32-make -j4 && mingw32-make install_sw

# 4) 打补丁并编译 libssh2
git apply demo/self_implemented/libssh2_pq.patch
cmake -S . -B build_pq -DCRYPTO_BACKEND=OpenSSL -DOPENSSL_ROOT_DIR=D:\libs\openssl-3.5.1
cmake --build build_pq --config Release
```

> 网络受限提示：本机实测 `git clone` 不稳定，但 `Invoke-WebRequest` 下载
> GitHub 的 ZIP / tar.gz 可行；OpenSSL 编译需补充缺失的 Perl 模块（见 BUILD.md）。

---

## 3. 运行

### 3.1 一键运行全部测试

```powershell
PowerShell -ExecutionPolicy Bypass -File D:\PQC-test\libSSH2\demo\scripts\run_all.ps1
```

依次执行 6 个阶段：

| 阶段 | 脚本 | 输出 |
|---|---|---|
| 1. 迁移前基线采集 | `capture_baseline.ps1` | `results/baseline_pre_migration.json` |
| 2. 断点矩阵 (M1软迁移 + M2硬迁移) | `compatibility_matrix.ps1` | `results/compatibility_matrix.json` |
| 3. 真实互通测试 | `live_negotiation.ps1` | `results/live_negotiation.json` |
| 4. 算法健康审计 | `algorithm_audit.ps1` | `results/algorithm_audit.json` |
| 5. Markdown 报告 | 内联生成 | `results/report.md` |
| 6. HTML 可视化报告 | `generate_html_report.ps1` | `results/report.html`（自动弹出浏览器） |

### 3.2 分步运行（可选）

```powershell
# 跳过真实互通 (无外网时)
PowerShell -ExecutionPolicy Bypass -File .\demo\scripts\run_all.ps1 -SkipLive

# 指定互通目标 (默认 github.com:22)
PowerShell -ExecutionPolicy Bypass -File .\demo\scripts\live_negotiation.ps1 `
    -Target <host> -Port 22 -User <user> -TimeoutSec 15
```

---

## 4. 预期输出

### 4.1 基线采集（本机实测）

```
客户端 KEX 算法数: 12 | 签名算法数: 11 | 密码套件: 10 | MAC: 16
```

基线 JSON 中 KEX 含 `curve25519-sha256`、`ecdh-sha2-nistp256/384/521`、
`diffie-hellman-group14/16/18-sha*` 等经典算法，**不含**任何 PQ 算法（本机 OpenSSH 9.5）。

### 4.2 断点矩阵（本机实测）

```
总场景数: 8 (双模式 x 4 = 8)
断点场景: 2
安全场景: 6
[断点] C2: 旧客户端 → 新服务端 (pre-PQ→hybrid) 失败类别: kex, hostkey
[断点] C3: 新客户端 → 旧服务端 (hybrid→pre-PQ) 失败类别: hostkey
```

| 场景 | KEX | Hostkey | 断点 |
|---|---|---|---|
| M1-C1 旧→旧 | diffie-hellman-group1-sha1 | ssh-ed25519 | 无 |
| M1-C2 旧→新(混合) | diffie-hellman-group14-sha256 | ssh-ed25519 | 无 |
| M1-C3 新→旧 | sntrup761x25519-sha512 | ssh-ed25519 | 无 |
| M1-C4 新→新(混合) | **mlkem768x25519-sha256** | **ssh-ed25519+ml-dsa-44** | 无 |
| M2-C2 旧→新(仅PQ) | **MISMATCH** | **MISMATCH** | **kex, hostkey** |
| M2-C3 新(仅PQ)→旧 | sntrup761x25519-sha512 | **MISMATCH** | **hostkey** |

### 4.3 真实互通（本机实测，连 github.com:22）

```
矩阵场景: C2 (pre-PQ -> hybrid) - 需服务端经典回退, 否则断点!
协商 KEX: curve25519-sha256
协商 Hostkey: ssh-ed25519
服务端含 PQ KEX: True   (github.com 已支持 sntrup761x25519)
本机含 PQ KEX: False    (OpenSSH 9.5 客户端未发送 PQ 算法)
是否协商出 PQ: False
```

> 实际印证：github.com 服务端已部署 NTRU 混合 KEX，但本机旧客户端不发送 PQ 算法，
> 双方回退到经典 `curve25519-sha256`——这正是 C2 场景的真实样本。

### 4.4 算法健康审计（本机实测）

```
待淘汰弱算法总数: 20
KEX: 3 (group1-sha1, group14-sha1, group-exchange-sha1)
Hostkey: 4 (ssh-dss, ssh-dss-cert, ssh-rsa, ssh-rsa-cert)
Cipher: 4 (3des-cbc, aes128/192/256-cbc)
MAC: 9 (hmac-md5*, hmac-sha1*, umac-64)
```

---

## 5. 严格性说明（M1 软迁移 vs M2 硬迁移）

本 demo 的兼容性矩阵在两种模式下运行，以体现**迁移严格性**的差异：

| 模式 | 服务端算法配置 | 断点数量 | 结论 |
|---|---|---|---|
| **M1-soft**（推荐） | 混合部署：经典 + PQ 双轨 | 0 | 渐进迁移，向后兼容，无断点 |
| **M2-strict** | 仅启用 PQ 算法，删除经典 | 2 | 旧客户端直接无法连接（硬迁移断点） |

**含义：**
- **迁移敏捷性** = 采用 M1 软迁移，任何时候可回退到经典算法，业务零中断。
- **严格性阈值** = 只有当无 PQ 能力的客户端占比清零后，才可切到 M2 硬迁移
  彻底移除经典算法（见 `BREAKPOINTS.md` 第 4 节）。

**推荐落地顺序：**
```
阶段0: 清除 20 个弱算法 → 消灭降级攻击面
阶段1: 服务端启用 mlkem768x25519-sha256, 保留经典回退 (M1)
阶段2: 客户端 (libssh2 + 补丁) 升级, PQ 优先
阶段3: 监控无PQ连接占比清零 → 才移除经典算法 (M2)
```

---

## 6. 版本记录

| 版本 | 日期 | 变更 |
|---|---|---|
| v1.0 | 2026-09-16 | 首个可运行版本：基线采集 / 断点矩阵 / 真实互通 / 算法审计 / 双格式报告 |
| v1.1 | 2026-09-16 | 增加真实互通抓包 (`live_negotiation.ps1`)、算法审计 (`algorithm_audit.ps1`)、HTML 报告 |

### 6.1 组件版本清单（详见 `demo/VERSION_MATRIX.md`）

| 组件 | 迁移前(已验证) | 迁移后(推荐) | PQC 支持 |
|---|---|---|---|
| libssh2 | 1.11.x | 1.11.x + 补丁 | 🛠 需自实现集成 |
| OpenSSL | 3.0.x/3.2.x | >= 3.5.0 | ✅ ML-KEM/ML-DSA 原生 |
| liboqs | — | >= 0.12.0 | ✅ |
| oqs-provider | — | >= 0.8.0 | ✅ |
| OpenSSH | 9.5p2 | >= 9.9 | ✅ mlkem768x25519 |

### 6.2 自实现部分（SELF-IMPLEMENT）

| 文件 | 功能 | 依赖 | 参考标准 |
|---|---|---|---|
| `demo/self_implemented/hybrid_kex.c/.h` | ML-KEM-768 + X25519 混合 KEX | OpenSSL 3.5 EVP_KEM / liboqs | RFC 9708, draft-ssh-hybrid |
| `demo/self_implemented/hybrid_signature.c/.h` | ML-DSA-44 + Ed25519 混合签名 | OpenSSL 3.5 EVP_SIGNATURE | draft-ssh-hybrid-signatures-04 |
| `demo/self_implemented/libssh2_pq.patch` | libssh2 集成补丁 | libssh2 1.11 源码 | — |

---

## 7. 断点说明（链接测试报告）

**断点定义**：SSH 2.0 协商中，客户端 offer 的算法列表与服务端 offer 在
KEX / hostkey / cipher / MAC **任一类别无交集**，握手即失败——这就是迁移断点。

### 7.1 本 demo 检测到的断点（详见 [测试报告](demo/results/report.html)）

| 场景 | 失败类别 | 成因 |
|---|---|---|
| M2-C2：旧客户端 → 仅PQ服务端 | kex, hostkey | 旧客户端不认识 `mlkem768x25519-sha256` / `ssh-ed25519+ml-dsa-44`，服务端无经典回退 |
| M2-C3：仅PQ客户端 → 旧服务端 | hostkey | 严格客户端只发混合签名，旧服务端只有纯 `ssh-ed25519` |

### 7.2 断点消除策略

1. **双轨配置**：服务端同时启用经典 + 混合算法（`KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,...`）
2. **混合优先、经典兜底**：客户端 PQ 算法置顶，经典算法保留在列表尾部
3. **签名 OR/AND**：混合签名过渡期先 OR（任一通过），稳定后切 AND
4. **配额灰度 + 监控**：无 PQ 连接占比清零后再移除经典算法

> 详细分析见 [`demo/BREAKPOINTS.md`](demo/BREAKPOINTS.md)；
> 最新一次运行结果见 [`demo/results/`](demo/results/) 目录。

---

## 许可证

本项目仅为 libssh2 的迁移测试框架，libssh2 源码版权归其原项目所有。
测试脚本与自实现代码按本项目仓库许可证分发。
