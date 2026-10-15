# Angus Mail 后量子（PQC）迁移测试

Eclipse Angus Mail（Jakarta Mail 官方参考实现）的后量子密码学迁移测试工程：**5 个迁移点（P1–P5）全部实现**、**三条技术路线（JDK 内置 / BouncyCastle / 混合双栈）可运行可复现**、**6 个迁移断点全部有对策**。

- 详细技术报告（含每个迁移点代码、版本配套、断点根因）：[AngusMail_PQC_迁移测试报告.md](reports/AngusMail_PQC_迁移测试报告.md)
- 可视化 HTML 报告（多色代码高亮）：[AngusMail_PQC_迁移测试报告.html](reports/AngusMail_PQC_迁移测试报告.html)

## 目录结构

```
angus-mail/
├── lib/                        # 全部依赖 jar（见「依赖安装」）
├── certs/                      # 测试证书（CN=localhost + SAN，keytool 生成）
│   ├── server-ecdsa.p12        # ECDSA 证书（方案A/B/C 通用）
│   ├── server-legacy.p12       # 传统 EC 证书（回退测试）
│   └── server-bc-mldsa.p12     # ML-DSA-65 证书（方案B）
├── logs/                       # 运行日志（含 TLS 握手调试）
│   ├── runA.log / runB.log / runC.log
├── reports/                    # 迁移测试报告（.md + .html）
├── src/pqc/
│   ├── common/                 # PqcSsl / PqcSocketFactory / MailPqcConfig / PqcMailServer / PqcMailCrypto / PqcVault / PqcDkim
│   ├── sasl/                   # PqcSaslClient / PqcSaslClientFactory / PqcSaslProvider
│   ├── approachA/              # MainA（JDK 27 原生）
│   ├── approachB/              # MainB（BouncyCastle BCJSSE）
│   └── approachC/              # MainC（混合双栈 + P2–P5 全迁移点）
├── build.ps1                   # 编译脚本（纯 javac，无需 Maven）
├── run-all.ps1                 # 一键运行三方案并生成日志
├── pom.xml                     # Maven 依赖参考（CI 环境）
└── README.md
```

---

## 一、环境要求

| 项目 | 要求 | 说明 |
|---|---|---|
| 操作系统 | Windows（本工程在 Windows x86-64 验证） | 脚本为 PowerShell |
| **JDK** | **27+**（本工程在 JDK 27 验证） | 依赖 JEP 496（ML-KEM）、JEP 497（ML-DSA）、TLS 1.3 混合组 `X25519MLKEM768` |
| PowerShell | 5.1+ | 运行 `build.ps1` / `run-all.ps1` |
| Git（可选） | 任意 | 仅版本管理使用，运行测试不需要 |

> **JDK 版本敏感性**（详见断点 4）：
> - **JDK 27+**：方案A 开箱即用（SunJSSE 原生支持 `X25519MLKEM768`）。
> - **JDK 24–26**：仅有 ML-KEM/ML-DSA 原语，JSSE 无 PQC 群组 → 只能跑**方案B**（BC BCTLS）。
> - **JDK 22-**：完全无 PQC 支持，需全部依赖 BC。

---

## 二、依赖安装

本项目采用「纯 javac + 本地 jar 目录」的方式，**无需 Maven**。`lib/` 已内置全部依赖。

### 依赖清单（lib/ 下已内置）

| 组件 | 版本 | 用途 |
|---|---|---|
| angus-mail | 2.0.5 | Jakarta Mail 参考实现（SMTP/IMAP/POP3 Provider） |
| jakarta.mail-api | 2.1.5 | Jakarta Mail API |
| angus-activation | 2.0.3 | Jakarta Activation 实现（MIME DataHandler） |
| jakarta.activation-api | 2.1.4 | Jakarta Activation API |
| bcprov-jdk18on | 1.86 | BC 原语 Provider（ML-KEM / ML-DSA，方案B/C 必需） |
| bctls-jdk18on | 1.86.1 | BCJSSE TLS Provider（方案B/C 必需） |
| bcpkix-jdk18on | 1.86 | X.509 / CMS 证书工具 |
| bcutil-jdk18on | 1.86 | BC 公共工具（ASN.1，1.86 起必需） |

### 重新安装依赖（可选）

如需从 Maven Central 重新下载，或使用 Maven 工程：

```powershell
# 方式1：直接使用内置 lib/（推荐，无需任何操作）
# 方式2：Maven 工程
mvn dependency:copy-dependencies -DoutputDirectory=lib
# 方式3：手工下载（版本配套关系见 reports 报告 §3）
```

依赖版本配套由 angus-mail 2.0.5 父 POM 统一锁定（mail-api 2.1.5 / activation 2.1.4 / angus-activation 2.0.3），**请勿随意改动 mail-api 版本**。

### 证书准备（certs/ 已内置）

测试证书已用 keytool 预生成（密码统一为 `changeit`）：
- CN=localhost，SAN=`dns:localhost,ip:127.0.0.1` —— **必须包含实际连接主机名**，否则触发主机名校验失败（断点 2）。
- 如需重新生成：

```powershell
keytool -genkeypair -alias ecdsa -keyalg EC -groupname secp256r1 `
  -dname "CN=localhost, OU=PQC Mail Test, O=PQC, C=CN" `
  -ext san=dns:localhost,ip:127.0.0.1 -validity 365 `
  -storetype PKCS12 -keystore certs\server-ecdsa.p12 -storepass changeit
keytool -genkeypair -alias server -keyalg ML-DSA -groupname ML-DSA-65 `
  -dname "CN=localhost, OU=PQC, O=PQC, C=CN" `
  -ext san=dns:localhost,ip:127.0.0.1 -validity 365 `
  -storetype PKCS12 -keystore certs\server-bc-mldsa.p12 -storepass changeit
```

---

## 三、运行

```powershell
# 1. 编译（纯 javac，输出到 out/）
powershell -ExecutionPolicy Bypass -File build.ps1

# 2. 一键运行三个方案（含 TLS 握手调试日志，写入 logs/）
powershell -ExecutionPolicy Bypass -File run-all.ps1
```

如需单独运行某个方案：

```powershell
$cp = (Get-ChildItem "lib" -Filter *.jar | ForEach-Object { $_.FullName }) -join ';'
java -cp "out;$cp" pqc.approachA.MainA     # 方案A：JDK 原生
java -cp "out;$cp" pqc.approachB.MainB     # 方案B：BouncyCastle
java -cp "out;$cp" pqc.approachC.MainC     # 方案C：混合双栈 + P2–P5 全迁移点
```

> 方案B/C 需要 BC jar（已内置）；本地端口占用 2543–2546、2643–2647、2743–2746，请确保空闲。

---

## 四、预期输出

### 方案A（JDK 27 原生）—— 协商后量子混合组 X25519MLKEM768

```
[server] SMTP TLS1.3 named groups = X25519MLKEM768,x25519 (provider=SunJSSE)
--- 场景1 SMTP 发送（PQC 混合密钥交换 X25519MLKEM768）---
[client] SMTP 发送 完成 | alice@pqc.local -> bob@pqc.local
          协议=TLSv1.3 | 密码套件=TLS_AES_256_GCM_SHA384
--- 场景2 IMAP 连接 / 场景3 POP3 连接 ---（均完成）
--- 场景4 回退：PQC 优先客户端 → 传统服务器(仅 x25519) --- 完成
```

握手调试日志中应出现 `"named group": X25519MLKEM768`（协商值）。

### 方案B（BouncyCastle）—— ML-DSA-65 PQC 证书 + 混合群组

```
[服务端] smtpMldsa=TLSv1.3/TLS_CHACHA20_POLY1305_SHA256 证书=ML-DSA-65
[client] SMTP 发送 完成 | IMAP 连接 完成 | POP3 连接 完成
[client] SMTP 互操作 完成（JDK↔BC、BC↔JDK ECDSA 证书）
[预期失败] JDK JSSE signature_algorithms 不含 mldsa -> 断点4 实证
```

### 方案C（混合双栈 + 全迁移点）—— P1–P5 全通过

```
================ 迁移点 P1：TLS 传输（混合双栈） ================  场景1/2/3 全部完成
================ 迁移点 P2：PQC-SIGN SASL 认证 ================
[client] SMTP 发送（PQC-SIGN 认证） 完成
[预期失败] 错误 ML-DSA 私钥被服务器拒绝 -> 535 Authentication credentials invalid
================ 迁移点 P3：S/MIME 式混合端到端加密 ================
明文=87B | 密文=1470B | 解密还原=true
混合签名(ML-DSA-65 + Ed25519): 签名=5407B | 验签=true
Angus Mail MimeMessage 承载密文往返: 解密还原=true
================ 迁移点 P4：本地凭证量子抗性 Vault ================
Vault(ML-KEM-768 封装 DEK + AES-256-GCM): 明文=23B | blob=1150B | 恢复=smtp-password-@XyZ2026! | 匹配=true
================ 迁移点 P5：混合 DKIM 签名 ================
经典 DKIM a=ed25519-sha256 验证=true | PQC DKIM a=mldsa65 验证=true
```

**判定标准**：三个方案均以 `xxx 测试结束` 收尾且无未预期的 `Exception`；方案B/C 中标注 `[预期失败]` 的行必须按预期失败（这是断点实证，属正常现象）。

---

## 五、严格性说明

本工程定位为**迁移可行性验证 Demo**，以下简化项在使用到生产环境前必须升级：

| 项 | 现状 | 生产要求 |
|---|---|---|
| **证书信任** | 自签名证书 + 以证书库自身作 truststore；测试环境为「信任即证书」 | 生产应使用受信任 CA 签发的证书链（或内部 CA），证书 CN/SAN 匹配真实主机名 |
| **邮件服务器** | `PqcMailServer` 为极简 SMTP/IMAP/POP3 测试实现（仅覆盖协议最小子集） | 生产对接真实邮件服务器 |
| **PQC-SIGN 认证** | 自定义 SASL 机制原型（客户端 ML-DSA 私钥经会话属性传入） | 生产私钥应存硬件/安全模块；服务器需注册公钥 |
| **P3 混合加密** | 自定义信封格式（`PQCENC1` / `PQCSIGN1`），非标准 S/MIME/CMS | RFC 9629 / LAMPS 标准成熟后，同一套原语嵌入 BC `CMSSignedData`/`CMSEnvelopedDataGenerator` |
| **P4 凭证 Vault** | 自定义 blob 格式（`PQCVAULT1`） | 生产结合系统密钥库/HSM 管理 ML-KEM 私钥 |
| **P5 DKIM** | 简化的 header 规范化 + 正文哈希原型 | 生产需实现 RFC 6376 完整 relaxed/simple 规范化 |
| **握手协商组验证** | JSSE 无「读取实际协商 NamedGroup」API，依赖 `-Djavax.net.debug=ssl:handshake` 日志佐证 | 生产可观察 `SSLSession` 密码套件 + 服务端记录 |
| **TLS 协议** | 仅 TLSv1.3（PQC 混合组不支持 TLS1.2） | 收敛期可保留 TLS1.3 单协议 |
| **会话复用/故障切换** | 未覆盖 | 生产需补充连接池、会话复用、超时策略 |

**已验证范围**：TLS 1.3 握手、`X25519MLKEM768` 协商、ML-DSA 证书签名（BC 栈）、PQC-SIGN 挑战-响应、混合信封加解密、双签名验签、Vault 封/解封、DKIM 双验签、三方案互操作与回退。

**未覆盖范围**：客户端证书（mTLS）、证书链深验证、IMAP/POP3 的完整命令集、S/MIME 标准格式互通、生产级密钥管理。

---

## 六、版本记录

| 版本 | 日期 | 变更 |
|---|---|---|
| 1.0.0 | 2026-09-29 | 初始版本：P1–P5 全迁移点实现、三方案（A/B/C）实测、6 断点对策、可视化报告（.md + .html） |

### 配套组件版本（当前已验证组合）

| 组件 | 版本 |
|---|---|
| JDK | 27 (build 27+35-2325) |
| angus-mail | 2.0.5 |
| jakarta.mail-api | 2.1.5 |
| angus-activation | 2.0.3 |
| jakarta.activation-api | 2.1.4 |
| BouncyCastle (bcprov/bcutil/bcpkix) | 1.86 |
| BouncyCastle (bctls) | 1.86.1 |

---

## 七、断点说明

> 完整根因分析与解决代码见：[迁移测试报告 §9 迁移断点与解决方案](reports/AngusMail_PQC_迁移测试报告.md#9-迁移断点与解决方案)

| # | 断点 | 一句话说明 | 解决方案 |
|---|---|---|---|
| 1 | [SocketFactory 静态 `getDefault()` 约定](reports/AngusMail_PQC_迁移测试报告.md#断点-1angus-自定义-socketfactory-需要静态-getdefault) | Angus `SocketFetcher` 反射调用 `getMethod("getDefault")`，缺失则静默回退默认 SSL 工厂 | 自定义工厂补 `public static SSLSocketFactory getDefault()` |
| 2 | [SocketFetcher 强制主机名校验](reports/AngusMail_PQC_迁移测试报告.md#断点-2socketfetcher-强制主机名校验) | 无条件设置 endpoint identification，证书不含主机名即 `No name matching localhost` | 证书 CN/SAN 含真实主机名（本项目用 `-ext san=dns:localhost,ip:127.0.0.1`） |
| 3 | [JDK `Sasl` 不扫描 classpath 服务](reports/AngusMail_PQC_迁移测试报告.md#断点-3jdk-sasl-不扫描-classpath-的-meta-infservices) | `Sasl.createSaslClient` 不加载 `META-INF/services` 注册的工厂 | 改用 `Security.addProvider(new PqcSaslProvider())` 注册 `SaslClientFactory.PQC-SIGN` |
| 4 | [JDK 版本决定 JSSE PQC 能力](reports/AngusMail_PQC_迁移测试报告.md#断点-4jdk-版本决定-jsse-层-pqc-能力) | JDK 27 的 `signature_algorithms` 无 `mldsa*`；JDK 24-26 无 `X25519MLKEM768` 组 | JDK<27 切 BC BCTLS（方案B）；PQC 证书签名仅 BC 栈；等 IETF LAMPS 标准 |
| 5 | [writetimeout 引入 WriteTimeoutSocket 包装](reports/AngusMail_PQC_迁移测试报告.md#断点-5mailsmtpwritetimeout-引入-writetimeoutsocket-包装层) | 设置 `writetimeout` 时 SocketFetcher 先包装再交给自定义工厂 | 演示工程不设 writetimeout；生产可保留 |
| 6 | [单 Part `application/octet-stream` DCH 缺失](reports/AngusMail_PQC_迁移测试报告.md#断点-6单-part-applicationoctet-stream-的-dch-缺失) | String/byte[] 内容无对应 DataContentHandler，`writeTo` 报 `UnsupportedDataTypeException` | 改用 `DataHandler(new ByteArrayDataSource(bytes, "application/octet-stream"))` |

---

## License

本项目为后量子密码迁移测试工程，依赖组件版权归其各自作者（Eclipse Angus / Jakarta EE / BouncyCastle / Oracle）。
