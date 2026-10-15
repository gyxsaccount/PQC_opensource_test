# HttpClient5 后量子（PQC）迁移测试

Apache HttpClient 5 的后量子密码学迁移测试工程：三种迁移方案的**可运行 Demo** 与**迁移测试报告**。

## 背景与结论

HttpClient5 是纯应用层库，密码学全部委托 JSSE/TLS 层，因此 PQC 迁移全部集中在 `SSLContext` / `SSLSocketFactory` 构建链路。本项目实测验证了三条迁移路径：

| 方案 | 技术栈 | 能力 | 结论 |
|---|---|---|---|
| **A** | JDK 21+ 内置（SunJSSE） | 混合密钥交换 `X25519MLKEM768`；证书仍 ECDSA | 可立即上线保护会话密钥，零依赖 |
| **B** | BouncyCastle BCJSSE (1.86) | 全链路 PQC：ML-DSA-65 证书 + 混合/纯 ML-KEM | 全链路量子抗性，需第三方依赖 |
| **C** | JDK + BC 双栈（推荐） | PQC 优先 + x25519 回退 + 双栈互操作 | 生产推荐：量子抗性 + 兼容 + 可回滚 |

## 目录结构

```
├── src/pqc/
│   ├── common/          # 共享代码：SSLContext工厂、PQC套接字工厂、HTTPS测试服务器、HttpClient5接入
│   ├── approachA/       # 方案A 主程序 MainA
│   ├── approachB/       # 方案B 主程序 MainB
│   ├── approachC/       # 方案C 主程序 MainC
│   └── probe/           # 能力探测与根因验证程序（调试过程留档）
├── certs/               # 测试证书（keytool + BC 生成）
├── lib/                 # 依赖 jar（Maven Central 下载）
├── logs/                # 运行日志（含 TLS 握手调试）
├── reports/             # 三份迁移测试报告
├── build.ps1            # 编译脚本（纯 javac）
├── run-all.ps1          # 一键运行三个方案
└── pom.xml              # Maven 依赖参考（CI 环境使用）
```

## 快速开始

```powershell
# 1. 编译（纯 javac，无需 Maven）
powershell -ExecutionPolicy Bypass -File build.ps1

# 2. 运行三个方案（含 TLS 握手调试日志）
powershell -ExecutionPolicy Bypass -File run-all.ps1
```

产物：
- `logs/runA.log` `logs/runB.log` `logs/runC.log` —— 各方案运行结果与握手调试
- `reports/方案A-JDK内置-迁移测试报告.md`、`方案B-BouncyCastle-迁移测试报告.md`、`方案C-混合式-迁移测试报告.md`

## 关键断点发现（实测）

1. **JDK JSSE 无 ML-DSA TLS 签名方案**（`sun.security.ssl.SignatureScheme` 枚举无 mldsa44/65/87）→ 纯 JDK 无法用 ML-DSA 证书做 TLS 服务端认证。
2. **JDK 仅支持混合群组 `X25519MLKEM768`**，无纯 MLKEM768 → 纯 ML-KEM 是 BC 独有能力。
3. **BCJSSE 默认签名方案不含 mldsa** → 必须显式 `BCSSLParameters.setSignatureSchemes(["mldsa65",...])`，否则 ML-DSA 证书握手报 "no selectable cipher suite"。
4. **BC 客户端对 JDK 服务端不能显式设置签名方案**（会触发 JDK 服务端证书选择失败）。
5. **BCJSSE `setSSLParameters` 会清空默认密码套件** → 需显式回填。
6. **注册 BC 后 `SSLContext.getInstance("TLS")` 优先 BCJSSE** → JDK 上下文必须 pin `SunJSSE`。
7. **`bctls` 依赖 `bcutil`**（1.86 起 ASN.1 部分类移入），缺 jar 会 `NoClassDefFoundError`。

## 迁移纪律（跨方案通用）

- 群组顺序：`[X25519MLKEM768, x25519]`（PQC 优先，x25519 兜底，直到全量收敛）。
- 强制 TLS 1.3（PQC 混合群组不支持 TLS1.2）。
- 证书演进：ECDSA → ML-DSA（仅 BC 栈）；收敛期再切纯 ML-KEM。
- 双栈共存时显式指定 provider（`SunJSSE` / `BCJSSE`）。

## 版本

- HttpClient 5.6.4 / HttpCore5 5.4.3
- BouncyCastle 1.86（bcprov / bcutil / bctls / bcpkix）
- JDK 21+（本项目在 JDK 27 验证）
