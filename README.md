# JSSE 后量子（PQC）迁移测试

针对 `javax.net.ssl.SSLSocket` / `SSLServerSocket`（JSSE）在 TLS 场景下的后量子迁移测试工程。
通过三条路线验证 PQC（ML-KEM / ML-DSA）在 Java TLS 中的可用性，并给出具体的接入改造代码。

| 路线 | 名称 | 技术栈 | 端口 | 说明 |
|------|------|--------|------|------|
| A | BC BCTLS | BC `bctls` + `bcprov` 1.86 | 18443 | BC JSSE Provider 实现 PQC 混合密钥交换 |
| B | JDK 原生 | JDK 27 内置（JEP 496/497） | 18444 | 原生 ML-KEM / ML-DSA + `X25519MLKEM768` |
| C | 自实现 | 自实现 TLS 1.3 + ML-DSA-65 | 18446 | 绕开 JSSE，验证"算法可用、协议不可用"断点 |

详细分析见测试报告：
- [Markdown 版](./PQC_迁移测试报告.md)
- [HTML 可视化版](./PQC_迁移测试报告.html)（推荐浏览器打开）

---

## 1. 环境要求

### 1.1 JDK

| 场景 | JDK 版本 | 说明 |
|------|----------|------|
| 路线 B（JDK 原生 PQC） | **JDK 24+**（本工程实测 **JDK 27** build 27+35-2325） | 需要 JEP 496/497（ML-KEM / ML-DSA 原生实现）及 `SSLParameters.setNamedGroups()`（JDK 21+ 已有） |
| 路线 A（BC BCTLS） | **JDK 8+**（本工程实测 **JDK 21** 与 JDK 27 均可） | BC `jdk18on` 全系列 jar 为 Java 8 兼容；JDK 21 上 BC 自含 PQC 实现，无需原生支持 |
| 路线 C（自实现） | JDK 17+（实测 JDK 27） | 依赖 `ML-DSA` 签名原语：JDK 24+ 用原生，JDK 21 以下需 `bcprov` |

> 注意：路线 B 依赖 JDK 24+ 原生 PQC，**无法在 JDK 21 及以下运行**（无 JEP 496/497）。

### 1.2 操作系统

Windows x86-64（本工程开发/测试平台）。脚本为 `.bat`（cmd.exe），需 **CRLF 行尾**、ASCII 编码（已处理）。
Linux/macOS 需将脚本改写为 `.sh` 并调整 JDK 路径。

### 1.3 端口

- 18443：路线 A BC BCTLS
- 18444：路线 B JDK 原生
- 18446：路线 C 自实现

确保这些端口未被占用（每次运行会自建临时连接，服务端为一次性进程）。

---

## 2. 依赖安装

### 2.1 BC 依赖（路线 A 必需，路线 C 在 JDK<24 时必需）

jar 已随工程附带在 `lib/` 下，无需联网下载：

```
lib/bctls-jdk18on-1.86.1.jar   (BC JSSE / TLS)
lib/bcprov-jdk18on-1.86.jar    (PQC 原语: ML-KEM / ML-DSA / Falcon)
lib/bcpkix-jdk18on-1.86.jar    (证书/KeyStore 扩展)
lib/bcutil-jdk18on-1.86.jar    (工具库)
```

来源：Maven Central `org.bouncycastle`（bctls 最新 1.86.1，bcprov/bcpkix/bcutil 最新 1.86）。

### 2.2 keytool（JDK 自带）

- 路线 B 运行脚本内自动生成 EC 自签名证书 `server.p12`（secp256r1）。
- 路线 C 运行脚本内自动生成 ML-DSA-65 自签名证书 `mldsa.p12`（keyalg `ML-DSA`，groupname `ML-DSA-65`）。

两个证书均使用密码 `changeit`。无需手工准备。

### 2.3 无需构建工具

无 Maven/Gradle。使用 `javac`/`java` 命令行 + `.bat` 脚本，或直接 `java <类名>`。

---

## 3. 运行

### 3.0 前置：确认 JDK 路径

三个脚本顶部硬编码了 JDK 路径：

```
set JAVAC="C:\Program Files\Java\latest\jdk-27\bin\javac.exe"
set JAVA="C:\Program Files\Java\latest\jdk-27\bin\java.exe"
```

若你的 JDK 27 路径不同，请修改脚本第 5-6 行（路线 B/C 另有第 7 行 `KEYTOOL`）。
或在命令前临时设置 `JAVA_HOME` 并改用 `%JAVA_HOME%\bin\javac.exe`。

### 3.1 路线 A：BC BCTLS PQC TLS 1.3

```bat
run_bc_demo.bat
```

- 自动编译 `BCPqcTlsServer.java` + `BCPqcTlsClient.java`
- 启动服务器（新窗口，端口 18443）→ 等待 3 秒 → 运行客户端
- 完成后需手动关闭服务器窗口

### 3.2 路线 B：JDK 27 原生 PQC

```bat
run_jdk_demo.bat
```

- 步骤 1/4：生成 EC 证书 `server.p12`
- 步骤 2/4：编译 3 个类
- 步骤 3/4：运行 `JdkPqcPrimitives` 原语性能测试
- 步骤 4/4：原生 `X25519MLKEM768` TLS 1.3 握手
- 结束后自动删除 `server.p12`

### 3.3 路线 C：自实现 TLS 1.3 + ML-DSA 签名

```bat
run_selfimpl_demo.bat
```

- 首次运行自动生成 `mldsa.p12`（ML-DSA-65），之后跳过
- 编译并运行 `SelfImplementedPqcTls`，端口 18446

### 3.4 手动运行（可选）

```bat
:: 路线 A
javac -encoding UTF-8 -cp "lib\bctls-jdk18on-1.86.1.jar;lib\bcprov-jdk18on-1.86.jar;lib\bcpkix-jdk18on-1.86.jar;lib\bcutil-jdk18on-1.86.jar" -d . BCPqcTlsServer.java BCPqcTlsClient.java
start java -cp ".;lib\bctls-jdk18on-1.86.1.jar;..." BCPqcTlsServer
java -cp ".;lib\..." BCPqcTlsClient
```

---

## 4. 预期输出

### 4.1 路线 A（BC BCTLS）

客户端输出要点：

```
Protocol: TLSv1.3
Cipher suite: TLS_CHACHA20_POLY1305_SHA256
Negotiated named group(s): [X25519MLKEM768]
[CLIENT] SUCCESS: full PQC handshake + encrypted message exchange verified
```

服务器端输出要点：

```
Group 'X25519MLKEM768' available
Using PQC named group: X25519MLKEM768
Protocol: TLSv1.3
Cipher suite: TLS_CHACHA20_POLY1305_SHA256
=== Connection complete ===
```

### 4.2 路线 B（JDK 原生）

- 步骤 3/4 输出 ML-KEM / ML-DSA 原语性能表（封装/解封装、签名/验签、密钥/密文/签名大小）。
- 步骤 4/4 输出：

```
Protocol: TLSv1.3
Cipher suite: TLS_AES_256_GCM_SHA384
Negotiated named group(s): [X25519MLKEM768]
[CLIENT] SUCCESS
```

### 4.3 路线 C（自实现）

输出握手各阶段检查点，末尾形如：

```
=== Checkpoint 4: Server Finished verification: OK
=== Checkpoint 5: Client Finished verification: OK
[Client] received echo: <明文>
=== ALL CHECKPOINTS PASSED ===
```

### 4.4 失败判定

- 编译失败 → 打印 `Compile FAILED`，脚本退出码 1。
- 路线 B 在 JDK 24 以下运行 → `java.lang.NoSuchAlgorithmException: ML-KEM ... not available`。
- 路线 A 缺 jar → `ClassNotFoundException: org.bouncycastle...`。
- 端口被占 → `BindException` / 连接超时。

---

## 5. 严格性说明

本工程为**演示/可行性验证**性质，**非生产安全实现**，请勿直接用于生产环境：

1. **路线 A / B 证书仍为经典签名**（SHA256withECDSA），仅密钥交换为 PQC 混合。**签名链路未后量子化**。
2. **路线 C 为最小 TLS 1.3 协议栈**：
   - 握手阶段**明文传输**（演示用，真实 TLS 需加密 ClientHello→Finished 之间报文）；
   - 未实现会话恢复 / 0-RTT / 重协商 / 扩展错误处理；
   - 应用数据使用 AES-128-GCM，密钥派生遵循 RFC 8446 §7.1 HKDF。
3. **信任策略简化**：客户端使用 trust-all `TrustManager`（路线 A）——仅用于测试，生产必须校验证书链。
4. **密钥库密码** `changeit` 为演示默认值，生产需替换为强口令并安全托管。
5. **性能数据**为单机演示级，不代表生产吞吐。
6. **ML-DSA-65 证书有效期 30 天**（脚本内 `-validity 30`），过期后需删除 `mldsa.p12` 重新生成。

## 6. 版本记录

| 版本 | 日期 | 内容 |
|------|------|------|
| v1.0 | 2026-10 | 三路线 demo 建立：路线 A（BC BCTLS X25519MLKEM768）、路线 B（JDK 27 原生）、路线 C（自实现 TLS 1.3 + ML-DSA-65）；初版测试报告 |
| v1.1 | 2026-10 | 补充 ML-DSA 证书 TLS 握手失败实证（报告 §4.5）；补充迁移断点分析 §6.8；自实现清单 §7.7；修复 `.bat` 脚本 CRLF/编码/路径问题 |
| v1.2 | 2026-10 | 新增 §4.7/§3.5 **BC 接入改造代码**（注册 Provider、`getInstance("TLSv1.3","BCJSSE")`、`setNamedGroups` 等）；**JDK 21 + BC 兼容性实测通过**（JDK 21.0.12.1 LTS + BC 1.86，TLS 握手与 149 项 PQC 原语均验证） |

### 版本兼容矩阵（实测）

| JDK | 路线 A (BC) | 路线 B (原生) | 路线 C (自实现) |
|-----|:-----------:|:-------------:|:---------------:|
| JDK 27 (build 27+35-2325) | ✅ | ✅ | ✅（ML-DSA 用原生） |
| JDK 21 (21.0.12.1 LTS) | ✅（BC 自含实现） | ❌（无 JEP 496/497） | ✅（ML-DSA 需 `bcprov`） |

---

## 7. 断点说明

> 核心结论：**后量子算法在 JDK 已可用，但 JSSE 协议层存在集成断点。**
> 完整断点分析见测试报告 [§6 迁移断点分析](./PQC_迁移测试报告.md)。

| # | 断点 | 现象 | 影响 | 报告章节 |
|---|------|------|------|----------|
| 1 | 证书签名算法仅支持经典 ECDSA/RSA | 证书无法用 ML-DSA 签发并走通 JSSE 握手 | PQC 证书签名链路不可用 | §6.1 |
| 2 | NamedGroup 协商结果无法直接查询 | `SSLParameters.getNamedGroups()` 返回的是**配置值**而非协商值 | 需 try-catch 探测 | §6.2 |
| 3 | 纯 JDK 无公开 X.509 证书构建器 | 需 `keytool` 预生成或引入 BC | 部署复杂化 | §6.3 |
| 4 | TrustManager 默认不信任自签 PQC 证书 | 需 trust-all 或导入信任库 | 测试期只能简化信任 | §6.4 |
| 5 | BC BCTLS 无 `getNamedGroups()` API | BC 1.86.1 返回 null | 探测依赖名称硬编码 | §6.5 |
| 6 | JDK 原生 TLS PQC 组合受限 | 仅 `X25519MLKEM768` 一类混合组 | 无纯 ML-KEM 组、无 ML-DSA 签名 | §6.6 |
| 7 | 经典 PQC + JSSE 迁移路径图 | 见报告迁移路径建议 | 需按图分阶段迁移 | §6.7 |
| 8 | **JSSE `signature_algorithms` 列表硬编码** | ML-DSA 证书握手失败：`handshake_failure: No available authentication scheme` | **算法可用、协议不可用**——根因 | §6.8 |

### 关键结论

- **密钥交换**：`X25519MLKEM768`（X25519 + ML-KEM-768 混合）在路线 A / B 均已验证可协商，安全性 ≥ max(经典, 后量子)。
- **证书签名**：JSSE 无法使用 ML-DSA → 需依赖自实现协议栈（路线 C 已验证可运行）或等待 JDK JSSE 扩展。
- **改造代码**：接入 BC 只需 5 处改动（注册 Provider、指定 `BCJSSE`、KeyStore/KMF/TMF 指定 BC、`setNamedGroups`、BC 证书构建），**业务代码零侵入**，详见报告 §4.7。

---

## 8. 文件清单

```
JSSE-java/
├── BCPqcTlsServer.java        # 路线 A 服务端 (BC BCTLS, 18443)
├── BCPqcTlsClient.java        # 路线 A 客户端
├── JdkPqcPrimitives.java      # 路线 B 原语性能测试
├── JdkPqcTlsServer.java       # 路线 B 服务端 (JDK 原生, 18444)
├── JdkPqcTlsClient.java       # 路线 B 客户端
├── SelfImplementedPqcTls.java # 路线 C 自实现 TLS 1.3 + ML-DSA-65 (18446)
├── run_bc_demo.bat            # 路线 A 一键运行
├── run_jdk_demo.bat           # 路线 B 一键运行
├── run_selfimpl_demo.bat      # 路线 C 一键运行
├── lib/                       # BC 依赖 jar + 探测用 ProbeBC*.java
├── mldsa.p12                  # 路线 C 生成的 ML-DSA-65 证书（脚本自动生成）
├── server.p12                 # 路线 B 临时证书（脚本自动生成并清理）
├── PQC_迁移测试报告.md         # 详细测试报告（Markdown）
└── PQC_迁移测试报告.html       # 可视化测试报告（浏览器打开）
```
