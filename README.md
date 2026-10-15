# HttpClient5 后量子（PQC）迁移测试

Apache HttpClient 5 的后量子密码学迁移测试工程：三种迁移方案的**可运行 Demo**、**迁移测试报告**与**实测断点结论**。

## 背景与结论

HttpClient5 是纯应用层库，密码学全部委托 JSSE/TLS 层，因此 PQC 迁移全部集中在 `SSLContext` / `SSLSocketFactory` 构建链路。本项目实测验证了三条迁移路径：

| 方案 | 技术栈 | 能力 | 结论 |
|---|---|---|---|
| **A** | JDK 21+ 内置（SunJSSE） | 混合密钥交换 `X25519MLKEM768`；证书仍 ECDSA | 可立即上线保护会话密钥，零第三方依赖 |
| **B** | BouncyCastle BCJSSE (1.86) | 全链路 PQC：ML-DSA-65 证书 + 混合/纯 ML-KEM | 全链路量子抗性，需第三方依赖 |
| **C** | JDK + BC 双栈（推荐） | PQC 优先 + x25519 回退 + 双栈互操作 | 生产推荐：量子抗性 + 兼容 + 可回滚 |

## 1. 环境要求

| 项 | 要求 | 说明 |
|---|---|---|
| JDK | **21+** | 需内置 TLS 群组 `X25519MLKEM768` 与 ML-KEM/ML-DSA 实现；本项目在 **JDK 27** 验证 |
| 操作系统 | Windows（PowerShell） | 脚本为 PowerShell；Linux/macOS 可自行用等价 javac/java 命令 |
| Git | 可选 | 仅用于拉取/提交，运行测试不需要 |
| Maven | **不需要** | 本地构建用纯 `javac`（`build.ps1`）；`pom.xml` 仅作 CI/正式工程参考 |
| 网络 | 首次需联网 | `lib/` 已内置全部依赖 jar，**离线可直接运行**；只有需要重新下载依赖时才联网 |

> 端口占用：三个方案固定使用本机回环端口（A: 9443-9445，B: 9543-9546，C: 9643-9646）。运行前请确保这些端口未被占用。

## 2. 依赖安装

### 2.1 内置依赖（无需安装）

所有运行时依赖已下载至 `lib/`，开箱即用：

| jar | 版本 | 用途 |
|---|---|---|
| httpclient5 / httpcore5 / httpcore5-h2 | 5.6.4 / 5.4.3 / 5.4.3 | HttpClient5 核心 |
| bcprov-jdk18on / bcutil-jdk18on / bctls-jdk18on | 1.86 | BouncyCastle 密码/ASN.1/BCJSSE（方案B/C） |
| bcpkix-jdk18on | 1.86 | BC 证书生成（方案B ML-DSA 证书） |
| slf4j-api / slf4j-simple | 2.0.17 | 日志 |
| commons-codec | 1.22.1 | HttpClient5 传递依赖 |

### 2.2 重新下载依赖（可选）

```powershell
# 依赖缺失时，从 Maven Central 重新拉取：
# 中心库地址 https://repo1.maven.org/maven2/
# 路径示例 org/apache/httpcomponents/client5/httpclient5/5.6.4/httpclient5-5.6.4.jar
```
> 注意：BC 1.86 起 `bctls` 依赖 `bcutil`（部分 ASN.1 类移入），**缺 bcutil 会报 `NoClassDefFoundError: org/bouncycastle/asn1/oiw/OIWObjectIdentifiers`**。

### 2.3 Maven 工程（CI/正式环境）

`pom.xml` 已提供全部依赖坐标，`mvn dependency:copy-dependencies` 或直接构建即可。

## 3. 运行

```powershell
# 1. 编译（输出到 out/，.gitignore 已排除该目录）
powershell -ExecutionPolicy Bypass -File build.ps1

# 2. 一键运行三个方案（含 TLS 握手调试日志）
powershell -ExecutionPolicy Bypass -File run-all.ps1
```

运行产物：

| 文件 | 内容 |
|---|---|
| `logs/runA.log` | 方案A 结果 + JSSE 握手调试（TLS 群组/签名方案/告警） |
| `logs/runB.log` | 方案B 结果 + 握手调试 |
| `logs/runC.log` | 方案C 结果 + 握手调试 |
| `reports/*.md` | 三份迁移测试报告：含**改造前/改造后代码对比**、Mermaid 可视化图、断点分析（详见第 7 节） |
| `reports/dashboard.html` | **可视化仪表盘**（浏览器打开）：PASS/断点计数、PQC 能力雷达图、场景耗时柱状图 |

也可单跑某个方案：
```powershell
$cp = (Get-ChildItem lib -Filter *.jar | ForEach-Object { $_.FullName }) -join ';'
java -Djavax.net.debug=ssl:handshake -cp "out;$cp" pqc.approachA.MainA
java -Djavax.net.debug=ssl:handshake -cp "out;$cp" pqc.approachB.MainB
java -Djavax.net.debug=ssl:handshake -cp "out;$cp" pqc.approachC.MainC
```

## 4. 预期输出

每个方案输出格式：场景标题 → `[PASS]`/`[FAIL]` → HTTP 状态与耗时 → TLS 会话协议/密码套件。

### 方案A（JDK 内置）——预期 1 PASS / 3 FAIL（均为断点）

| 场景 | 预期结果 | 预期会话 |
|---|---|---|
| 场景1 正向：JDK↔JDK 混合密钥交换 | ✅ PASS, HTTP 200 | TLSv1.3 / TLS_AES_256_GCM_SHA384 |
| 场景2 断点：JDK JSSE 用 ML-DSA 证书 | ❌ FAIL（预期） | `No available authentication scheme` |
| 场景3 断点：无共同群组 | ❌ FAIL（预期） | `No common named group` |
| 场景4 断点：强制 TLS1.2 | ❌ FAIL（预期） | `protocol_version` |

### 方案B（BouncyCastle）——预期 4 PASS / 3 FAIL（均为断点）

| 场景 | 预期结果 | 预期会话 |
|---|---|---|
| 场景1 正向：BC 全链路（ML-DSA 证书+混合KEX） | ✅ PASS, HTTP 200 | TLSv1.3 / TLS_CHACHA20_POLY1305_SHA256 |
| 场景2 正向：BC 纯 MLKEM768 | ✅ PASS, HTTP 200 | TLSv1.3 / TLS_CHACHA20_POLY1305_SHA256 |
| 场景3 互操作：JDK 客户端↔BC 服务端 | ✅ PASS, HTTP 200 | TLSv1.3 / TLS_CHACHA20_POLY1305_SHA256 |
| 场景4 互操作：BC 客户端↔JDK 服务端 | ✅ PASS, HTTP 200 | TLSv1.3 / TLS_AES_256_GCM_SHA384 |
| 场景5-7 断点 | ❌ FAIL（预期） | 见报告 |

### 方案C（混合式）——预期 5 PASS / 1 FAIL（断点）

| 场景 | 预期结果 | 说明 |
|---|---|---|
| 场景1-2 互操作（JDK↔BC 双向） | ✅ PASS | 混合 KEX 双栈互通 |
| 场景3-4 回退（PQC 优先↔传统服务器） | ✅ PASS | 自动回退 x25519 |
| 场景5 断点：未迁移客户端↔PQC-only 服务器 | ❌ FAIL（预期） | `No common named group` |
| 场景6 正向：JDK↔JDK 生产默认 | ✅ PASS | TLSv1.3 |

```
服务端最终协商示例（方案A）：
[服务端最后协商] pServer=TLSv1.3 / TLS_AES_256_GCM_SHA384 | mldsa=none | pOnly=none
```

## 4.5 可视化报告

每个方案报告内置 **Mermaid 可视化图**（GitHub 上直接渲染）：
- **迁移前 → 迁移后架构图**：改造前后 TLS 握手链路对比
- **结果饼图**：PASS / 断点占比

另有汇总可视化仪表盘 **`reports/dashboard.html`**（浏览器打开，需联网加载 ECharts/Mermaid CDN）。看板**完整呈现三份报告全部详情**：
- **总览页**：PASS/断点计数柱状图、PQC 能力雷达图、各场景耗时柱状图、全场景结果明细表
- **方案A/B/C 三页**（Tab 切换）：
  - 概述表 + 迁移前→迁移后 Mermaid 架构图 + 结果饼图/能力图 + 结论
  - 迁移方案（优先级/步骤/阶段与风险）
  - **全部改造点「改造前 vs 改造后」代码对比**（红=前 / 绿=后，含变化说明）
  - 断点分析（现象/根因/影响/对策）
  - 测试结果明细表 + 服务端最终协商

## 5. 严格性说明

> **如何解读 PASS/FAIL**：`FAIL` 行均为**预期失败的断点验证**，用于证明"未按迁移方案实施时的故障形态"，并非测试失败。请以"预期 PASS 数 / 预期 FAIL 数"核对，见第 4 节。

本项目为**功能/互操作验证 Demo**，以下方面有意从简，**不直接代表生产强度**：

| 项 | 说明 |
|---|---|
| 主机名校验 | 使用 `NoopHostnameVerifier`（测试用自签名证书，CN 与 localhost 不匹配）→ **生产必须启用严格校验** |
| 证书 | 全部为自签名 PKCS12（keytool/BC 生成），**仅测试用途** |
| 测试服务器 | `PqcHttpServer` 为 SSLSocket 极简实现，支持 TLS1.3 + 自定义群组，但**非生产级 HTTP 服务器**（无并发控制、无超时、仅回环监听） |
| 耗时数据 | 单位为 ms，受 JIT 预热、机器负载影响，**仅作参考，非性能基准** |
| 日志量 | 开启 `-Djavax.net.debug=ssl:handshake`，日志可达数百 KB；生产环境请关闭 |
| 无害告警 | BCJSSE 启动时打印 `Ignoring unsupported entry in 'jdk.tls.disabledAlgorithms'`（rsa_pkcs1_sha1 等）→ 无害，可忽略 |
| 端口冲突 | 方案使用固定端口；若本机被占用，请先释放或调整代码中端口 |
| JVM 残留 | 若上次运行异常退出，可能有 java 进程残留占用端口；`Get-Process java | Stop-Process` 清理 |

## 6. 版本记录

| 版本 | 日期 | 内容 |
|---|---|---|
| 1.0.0 | 2026-09-24 | 首版：三方案 Demo + 迁移测试报告 + 断点验证 |

**依赖版本锁定**（`lib/` 与 `pom.xml` 一致）：

| 组件 | 版本 |
|---|---|
| JDK（验证环境） | Oracle JDK 27 (build 27+35-2325)，**要求 JDK 21+** |
| httpclient5 | 5.6.4 |
| httpcore5 / httpcore5-h2 | 5.4.3 |
| BouncyCastle（bcprov/bcutil/bctls/bcpkix） | 1.86 |
| slf4j-api / slf4j-simple | 2.0.17 |
| commons-codec | 1.22.1 |

## 7. 断点说明（详见测试报告）

以下为实测确认的关键断点，详细根因、复现日志与对策见各方案报告：

| # | 断点 | 影响 | 报告链接 |
|---|---|---|---|
| 1 | **JDK JSSE 无 ML-DSA TLS 签名方案**（`SignatureScheme` 枚举无 mldsa44/65/87）→ ML-DSA 证书 TLS 认证报 `No available authentication scheme` | 纯 JDK 只能用 ECDSA/RSA 证书 | [方案A 报告 §4.1](reports/方案A-JDK内置-迁移测试报告.md) |
| 2 | **JDK 仅支持混合群组 `X25519MLKEM768`**，无纯 `MLKEM768` | 纯 ML-KEM 仅 BC 可用 | [方案B 报告 §4.4](reports/方案B-BouncyCastle-迁移测试报告.md) |
| 3 | **BCJSSE 默认签名方案不含 mldsa** → 需显式 `BCSSLParameters.setSignatureSchemes(["mldsa65",...])`，否则 ML-DSA 证书握手报 `found no selectable cipher suite` | PQC 证书必须显式开启 | [方案B 报告 §4.1](reports/方案B-BouncyCastle-迁移测试报告.md) |
| 4 | **BC 客户端对 JDK 服务端不可显式设置签名方案**（触发 JDK 服务端 `No X.509 cert selected for EC`） | 跨栈互操作需按目标定制 | [方案B 报告 §4.2](reports/方案B-BouncyCastle-迁移测试报告.md) |
| 5 | **PQC 混合群组仅支持 TLS 1.3**；未启用 PQC 群组的一端与 PQC-only 端无法协商 | 迁移必须强制 TLS1.3 + 群组 `[X25519MLKEM768, x25519]` | [方案A 报告 §4.2-4.3](reports/方案A-JDK内置-迁移测试报告.md) |
| 6 | **BCJSSE `setSSLParameters` 清空默认密码套件**；注册 BC 后 `"TLS"` 默认选 BCJSSE | 工程实现必须显式回填套件 / pin provider | [方案B 报告 §4.5](reports/方案B-BouncyCastle-迁移测试报告.md) |
| 7 | **`bctls` 依赖 `bcutil`**（1.86 起 ASN.1 类拆分） | 缺 jar 即 `NoClassDefFoundError` | [方案B 报告 §4.5](reports/方案B-BouncyCastle-迁移测试报告.md) |

## 8. 迁移纪律（跨方案通用）

- 群组顺序：`[X25519MLKEM768, x25519]`（PQC 优先，x25519 兜底，直到全量收敛）。
- 强制 TLS 1.3（PQC 混合群组不支持 TLS1.2）。
- 证书演进：ECDSA → ML-DSA（仅 BC 栈）；收敛期再切纯 ML-KEM。
- 双栈共存时显式指定 provider（`SunJSSE` / `BCJSSE`）。
- 生产环境必须开启主机名校验，替换测试证书。

## 目录结构

```
├── src/pqc/
│   ├── common/          # 共享代码：SSLContext工厂、PQC套接字工厂、HTTPS测试服务器、HttpClient5接入
│   ├── approachA/       # 方案A 主程序 MainA
│   ├── approachB/       # 方案B 主程序 MainB
│   ├── approachC/       # 方案C 主程序 MainC
│   └── probe/           # 能力探测与根因验证程序（调试过程留档）
├── certs/               # 测试证书（keytool + BC 生成）
├── lib/                 # 依赖 jar（Maven Central 下载，离线可用）
├── logs/                # 运行日志（含 TLS 握手调试）
├── reports/             # 三份迁移测试报告
├── build.ps1            # 编译脚本（纯 javac）
├── run-all.ps1          # 一键运行三个方案
└── pom.xml              # Maven 依赖参考（CI 环境使用）
```
