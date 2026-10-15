# Jetty 12 PQC 后量子迁移测试

对 Eclipse Jetty 12.1.13 进行后量子密码（PQC, Post-Quantum Cryptography）迁移的测试验证项目。覆盖 **8 个迁移点** 的实现、实机验证与可视化报告。

- **可视化测试验证报告**：[`results/report.html`](results/report.html)（浏览器直接打开）
- **详细迁移报告**：[`Jetty_PQC_迁移测试报告.md`](Jetty_PQC_迁移测试报告.md)

---

## 1. 环境要求

| 项目 | 要求 | 说明 |
|------|------|------|
| 操作系统 | Windows x86-64 | 已在 Windows 上实机验证；Linux/macOS 理论可行但未验证 |
| JDK | **JDK 27**（必须） | SunJSSE 原生支持 PQC named group `X25519MLKEM768`（JEP 496/497） |
| 磁盘空间 | ≥ 100 MB | `lib/` 依赖约 16 MB + 编译产物 |
| 网络 | 首次需访问 Maven Central / GitHub | 若走代理需配置 git 代理（见下文） |
| 端口占用 | 18443/18445/18446 需空闲 | 测试服务器监听端口 |

> **为什么必须 JDK 27？**
> 迁移点 1 的核心依赖 `SSLParameters.setNamedGroups(String[])` 是 JDK 27 公开 API，
> 且 JDK 27 SunJSSE 默认 named groups 首位即 `X25519MLKEM768`。JDK 24-26 仅有 ML-KEM/ML-DSA
> 原语（JEP 496/497）但 JSSE 未集成 PQC 组；JDK 22- 完全不支持。

---

## 2. 依赖安装

所有依赖 jar 已随项目提交在 **`lib/`**（42 个），**无需联网下载即可运行**：

| 依赖 | 版本 | 用途 |
|------|------|------|
| Eclipse Jetty（core/ee10/http2/http3/quic/session/security/openid/jmx/compression） | 12.1.13 | 被测对象 |
| Bouncy Castle（bcprov/bcpkix/bctls/bcutil） | 1.86 | JCE Provider / TLS 参考 |
| SLF4J（api/simple） | 2.0.17 | 日志 |
| nimbus-jose-jwt | 10.0.1 | OIDC/JWT 算法评估（迁移点 6） |
| Caffeine | 3.2.0 | 缓存依赖 |
| Jakarta Servlet API | 6.0.0 | ee10 认证 demo（迁移点 3） |

如要自行重建 `lib/`，可参考以下 Maven Central 坐标（版本号同表）：

```
org.eclipse.jetty:jetty-server:12.1.13
org.eclipse.jetty:jetty-client:12.1.13
org.eclipse.jetty:jetty-security:12.1.13
org.eclipse.jetty:jetty-session:12.1.13
org.eclipse.jetty:jetty-openid:12.1.13
org.eclipse.jetty:jetty-http2-server:12.1.13
org.eclipse.jetty.http3:jetty-http3-server:12.1.13
org.eclipse.jetty:jetty-compression-gzip:12.1.13
org.eclipse.jetty.ee10:jetty-ee10-servlet:12.1.13
org.eclipse.jetty.ee10:jetty-ee10-servlets:12.1.13
org.slf4j:slf4j-api:2.0.17
com.nimbusds:nimbus-jose-jwt:10.0.1
com.github.ben-manes.caffeine:caffeine:3.2.0
jakarta.servlet:jakarta.servlet-api:6.0.0
org.bouncycastle:bcprov-jdk18on:1.86
org.bouncycastle:bctls-jdk18on:1.86.1
```

**代理提示**：若本机启用系统代理（如 Clash/V2Ray），git 默认不读取系统代理，需手动配置：

```powershell
git config --global http.proxy http://127.0.0.1:17897
git config --global https.proxy http://127.0.0.1:17897
```

---

## 3. 运行

### 3.1 一键运行（Windows）

```bat
cd D:\PQC-test\jetty
run_jetty_pqc.bat
```

脚本自动：编译 `src/` → 启动 HTTPS 服务器 → 依次运行 8 个迁移点 demo → 停止服务器。

### 3.2 手动运行单个迁移点

```powershell
# 编译（一次性）
javac -encoding UTF-8 -cp "lib\*" -d out src\*.java

# 迁移点 1+7：HTTPS 服务器（另开窗口）+ HttpClient 出站 TLS
java -cp "lib\*;out" JettyPqcServer etc\keystore.p12 18443
java -cp "lib\*;out" JettyPqcClient https://localhost:18443/hello

# 迁移点 2：ML-DSA 证书阻断验证
java -cp "lib\*;out" MldsaCertBlockTest etc\mldsa.p12 18445

# 迁移点 3：Digest 认证 SHA-256
java -cp "lib\*;out" DigestAuthPqcTest 18446

# 迁移点 4：口令哈希迁移
java -cp "lib\*;out" PasswordHashPqcTest

# 迁移点 5：会话安全审计
java -cp "lib\*;out" SessionSecurityPqcTest

# 迁移点 6：OIDC/JWT 算法评估
java -cp "lib\*;out" OidcJwtPqcTest

# 迁移点 8：HTTP/3 评估
java -cp "lib\*;out" Http3PqcTest
```

> `etc/keystore.p12`（EC 证书）与 `etc/mldsa.p12`（ML-DSA-65 证书）已随项目提供，密码均为 `changeit`。

---

## 4. 预期输出

完整运行后控制台依次输出（节选关键断言）：

```
[1/9] MigPoint1+7: Jetty HTTPS server + HttpClient (X25519MLKEM768)
  [CLIENT] GET https://localhost:18443/hello -> 200 (OK)
  [CLIENT] SUCCESS: HttpClient outbound TLS negotiated PQC hybrid group (X25519MLKEM768)

[2/9] MigPoint2: ML-DSA cert blocker
  [ OK ] Jetty SslContextFactory 加载 ML-DSA 证书: 成功
  [TLS] 握手失败 (预期): SSLHandshakeException -> (handshake_failure) No available authentication scheme

[3/9] MigPoint3: Digest auth hash migration
  Digest 认证请求 -> 200 (OK)  / 响应: Protected resource OK - authenticated as alice

[4/9] MigPoint4: Password/Realm hash migration
  校验正确密码: true, 校验错误密码: false
  => 迁移后哈希校验链路可用

[5/9] MigPoint5: Session security audit
  生成 10000 个, 重复=0, 唯一=是

[6/9] MigPoint6: OIDC/JWT algorithm assessment
  RS256 (RSA-3072): verify=true   /   ES256 (P-256): verify=true
  ML-DSA-65 -> 不可用 (JOSE PQC 标准未定)

[7/9] MigPoint8: HTTP/3 (QUIC) assessment
  PQC 混合组可用: true   /   Quiche 原生库: 缺失 (环境依赖)
```

各迁移点原始输出已归档在 `results/`：

| 文件 | 对应 |
|------|------|
| `mig1_7_tls.txt` | 迁移点 1+7 |
| `mig2_mldsa_block.txt` | 迁移点 2 |
| `mig3_digest.txt` | 迁移点 3 |
| `mig4_password_hash.txt` | 迁移点 4 |
| `mig5_session.txt` | 迁移点 5 |
| `mig6_jwt.txt` | 迁移点 6 |
| `mig8_http3.txt` | 迁移点 8 |

---

## 5. 严格性说明

本测试的**验证强度**分三档，请据此解读结论：

| 级别 | 含义 | 涉及迁移点 |
|------|------|-----------|
| **实机握手验证** | 真实 TLS 1.3 握手/HTTP 请求通过，且客户端仅通告 PQC 单组 `X25519MLKEM768` 仍成功 → 严格证明服务器协商了 PQC 组 | 1, 7 |
| **链路验证** | 完整业务链路跑通（401 挑战 → SHA-256 response → 200；SHA3 凭证生成/校验；10000 次会话 ID 唯一性） | 3, 4, 5 |
| **评估/断言验证** | 通过 API 探测断言"算法不可用"或"依赖缺失"（`ClassNotFound` / `ParseException`），并给出根因 | 2, 6, 8 |

**必须注意的边界：**

- **迁移点 2 的"阻断"是结论而非失败**：`握手失败` 是预期结果，用来实证 JSSE `signature_algorithms` 硬编码缺位。**不要**将脚本的 `[2/9]` 段误判为测试失败。
- 迁移点 1 中 `getDefaultSSLParameters().getNamedGroups()` 打印的是系统默认列表（含全部组），真正生效的是 `customize()` 内 `setNamedGroups` 的设置——验证判据是**客户端仅通告单组仍握手成功**。
- 迁移点 8 的 Quiche 缺失是**环境依赖**（原生库不在 Maven Central），非 Jetty 代码缺陷。
- 迁移点 6 的 PQC 不可用是**标准未定**（IETF jose-pqc），非实现缺陷。
- 自签名证书仅用于测试；生产环境需正式 CA 签发。`keystore.p12`/`mldsa.p12` 密码 `changeit` 为测试密码。

---

## 6. 版本记录

| 版本 | 日期 | 变更 |
|------|------|------|
| v1.0 | 2026-09-21 | 首版：8 个迁移点实现 + 实机验证 + 可视化报告（`report.html`）；JDK 27 / Jetty 12.1.13 / BC 1.86 |
| v1.1 | 2026-09-21 | 报告补充各迁移点**代码改造点**（含代码片段、API 差异、阻断定位）；修复代码块换行显示 |

---

## 7. 迁移点与断点说明

### 7.1 迁移点总览

| # | 迁移点 | 现状算法 | PQC 目标 | 状态 |
|---|--------|---------|---------|------|
| 1 | TLS 密钥交换 | ECDHE(X25519) | **X25519MLKEM768** | ✅ 可迁移（已实证） |
| 2 | TLS 证书签名 | ECDSA/RSA | ML-DSA | ⛔ **阻断** |
| 3 | HTTP 摘要认证 | MD5 | SHA-256/SHA3 | ✅ 可迁移（已实证） |
| 4 | 口令哈希/Realm | MD5/SHA-1 | SHA2/SHA3/Argon2 | ✅ 可迁移（已实证） |
| 5 | 会话安全 | SecureRandom | DRBG+配置 | ✅ 可迁移（已实证） |
| 6 | OIDC/JWT | RS256/ES256 | ML-DSA(JOSE) | ⚠️ 依赖 IETF |
| 7 | HttpClient 出站 TLS | ECDHE(X25519) | X25519MLKEM768 | ✅ 可迁移（已实证） |
| 8 | HTTP/3 (QUIC) | TLS 1.3 | 同迁移点 1 | ⚠️ 依赖 Quiche |

### 7.2 三个断点

| 断点 | 表现 | 根因 | 当前应对 |
|------|------|------|---------|
| **JSSE signature_algorithms 硬编码** | ML-DSA 证书加载 OK、真实握手失败（`No available authentication scheme`） | JSSE 仅注册 18 种经典签名方案，不经 Provider/配置扩展 | 保持 EC/RSA 证书 + X25519MLKEM768 混合密钥交换（已达 CNSA 2.0 第一阶段）；跟踪 JDK-8332706 / IETF LAMPS |
| **JOSE 无 PQC 算法** | `ML-DSA-65` 等 `JWSAlgorithm.parse()` 抛异常 | IETF jose-pqc 标准未落地 | 提升经典强度（RSA-3072+/P-384+），等待标准 |
| **HTTP/3 依赖 Quiche** | `org.eclipse.jetty.quiche.Quiche` 缺失 | 原生库需自行构建，不在 Maven Central | 需构建 jetty-quiche-native 并加入 classpath |

### 7.3 断点与测试报告的对应

每个断点的**完整实证过程、根因分析、代码改造点与迁移路线**见：

- 可视化报告：[`results/report.html`](results/report.html)（第 3 节断点实证、第 8 节断点根因表、第 9 节路线图）
- 详细报告：[`Jetty_PQC_迁移测试报告.md`](Jetty_PQC_迁移测试报告.md)（第 4 节断点总结、第 5 节迁移阶段路线）
- 断点复现源码：`src/MldsaCertBlockTest.java`（断点 1）、`src/OidcJwtPqcTest.java`（断点 2）、`src/Http3PqcTest.java`（断点 3）

---

## 目录结构

```
jetty/
├── src/                          # 8 个迁移点 demo 源码
├── lib/                          # Jetty 12.1.13 + 依赖 jars（42 个，已提交）
├── etc/                          # keystore.p12 (EC)、mldsa.p12 (ML-DSA-65)
├── results/                      # 运行输出归档 + 可视化报告 report.html
├── out/                          # 编译产物（.gitignore 排除，不提交）
├── run_jetty_pqc.bat             # 一键运行
├── Jetty_PQC_迁移测试报告.md       # 详细迁移报告
└── README.md                     # 本文档
```
