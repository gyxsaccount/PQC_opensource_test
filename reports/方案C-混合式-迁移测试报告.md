# 方案C 迁移测试报告 —— 混合式双栈（JDK 内置 + BouncyCastle，推荐生产方案）

## 1. 测试概述

| 项 | 内容 |
|---|---|
| 被测对象 | Apache HttpClient 5.6.4 + JDK JSSE + BouncyCastle BCJSSE 双栈并存 |
| 环境 | JDK 27 (Oracle, build 27+35)，Windows |
| 目标 | 验证生产推荐架构：PQC 优先、无缝回退、双栈互操作 |
| 结果 | **正向/互操作/回退 5 项通过；断点 1 项按预期失败** |

## 2. 迁移方案（方案C：分阶段收敛策略）

### 2.1 核心策略
```
客户端群组顺序： [X25519MLKEM768, x25519]
                 └─ 优先 PQC（混合式） ──┴─ 传统回退（兼容未迁移对端）
```
- **服务端先宽后严**：先同时启用混合群组与 `x25519`；对端全部就绪后再收敛为纯 `X25519MLKEM768` / `MLKEM768`。
- **证书先传统后 PQC**：互操作期用 ECDSA 证书；PQC 证书（ML-DSA）仅 BCJSSE 服务端可用，收敛期启用。
- **双栈共存**：JDK 栈负责日常，BC 栈负责 PQC 证书/纯 ML-KEM，通过 provider 顺序共存（JDK 上下文必须 pin `SunJSSE`）。

### 2.2 迁移阶段
| 阶段 | 动作 | 风险 |
|---|---|---|
| P1 | JDK 21+，TLS1.3 强制，群组 [X25519MLKEM768, x25519] | 低（x25519 兜底） |
| P2 | 服务端同时提供 PQC 群组 + x25519，证书仍 ECDSA | 低 |
| P3 | 引入 BC 栈，服务端启用 ML-DSA 证书（仅 BC） | 中（需显式签名方案） |
| P4 | 收敛：纯 X25519MLKEM768 / 纯 MLKEM768，全链路 PQC | 高（两端必须就绪） |

## 3. 改造点（含代码）

> 方案C 复用方案A/B 的全部改造点，核心差异在于**双栈共存时的提供者管理**与**按目标选择签名方案**。

### 改造点 1：双栈注册 + JDK 上下文 provider 固定（共存关键）
```java
// src/pqc/common/PqcSsl.java
public static void installBouncyCastle() {
    Security.removeProvider(BC_JCE);
    Security.removeProvider(BC_JSSE);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);   // 位置 1
    Security.insertProviderAt(new BouncyCastleJsseProvider(), 2); // 位置 2
}
// JDK 上下文必须 pin：SSLContext.getInstance("TLS", "SunJSSE")
// BCJSSE 上下文：SSLContext.getInstance("TLS", "BCJSSE")
```

### 改造点 2：按目标栈选择签名方案（互操作细节）
```java
// src/pqc/common/PqcSsl.java
// 对 BC ML-DSA 服务端（需提供 mldsa 方案）：
public static final String[] PQC_SIGNATURE_SCHEMES = {
    "mldsa87", "mldsa65", "mldsa44",
    "ecdsa_secp256r1_sha256", "ed25519", "rsa_pss_rsae_sha256" };

// 对 JDK 服务端：BC 客户端【不设置】签名方案（用 BC 默认），实测互通
// （若显式设置会导致 JDK 服务端 "No X.509 cert selected for EC"）
```

### 改造点 3：服务端群组注入（含回退）
```java
// src/pqc/common/PqcHttpServer.java
SSLParameters params = ss.getSSLParameters();
params.setProtocols(new String[]{"TLSv1.3"});
params.setNamedGroups(namedGroups);                      // 传入 ["X25519MLKEM768","x25519"] 或 ["x25519"] 等
params.setCipherSuites(ss.getEnabledCipherSuites());     // 保留默认套件
ss.setSSLParameters(params);
```

### 改造点 4：HttpClient5 客户端构建（PQC 优先 + 回退）
```java
// src/pqc/approachC/MainC.java —— 生产客户端
PqcClient client = HttpClientFactory.build("方案C-生产客户端",
        jdkClientCtx,                                // JDK(SunJSSE) 或 BC 上下文
        new String[]{"X25519MLKEM768", "x25519"});   // PQC 优先，x25519 回退
```

## 4. 断点分析

### 4.1 【断点】未启用 PQC 群组的传统客户端 ↔ PQC-only 服务端
- **现象**：客户端仅 `x25519`，服务端仅 `X25519MLKEM768` → `No common named group`（unexpected_message）。
- **结论**：**混合式迁移的正确姿势是"客户端 PQC 优先 + x25519 回退"，而不是只升级一端就强制收紧**。该断点正是"只迁移服务端、客户端未动"的失败形态，验证了方案C 策略的必要性。

### 4.2 【复用断点（详见方案A/B）】
- JDK JSSE 无 mldsa TLS 签名方案 → PQC 证书依赖 BC 栈。
- JDK 无纯 MLKEM 群组 → 纯 ML-KEM 仅 BC 收敛期可用。
- BCJSSE 默认不含 mldsa 签名方案 → 必须显式注入。
- BC 客户端对 JDK 服务端不能显式设置签名方案。
- `SSLContext.getInstance("TLS")` 在 BC 注册后优先 BCJSSE → 必须 pin provider。

## 5. 测试结果明细

| # | 场景 | 配置 | 结果 | 明细 |
|---|---|---|---|---|
| 1 | 互操作：JDK 客户端 ↔ BC 服务端 | [X25519MLKEM768,x25519] | ✅ PASS | HTTP 200, 179ms, TLSv1.3 |
| 2 | 互操作：BC 客户端 ↔ JDK 服务端 | BC 默认签名方案 | ✅ PASS | HTTP 200, 34ms, TLSv1.3 / TLS_AES_256_GCM_SHA384 |
| 3 | 回退：JDK 客户端 ↔ 传统服务器 | 客户端 PQC 优先，服务器仅 x25519 | ✅ PASS | HTTP 200, 65ms（自动回退 x25519） |
| 4 | 回退：BC 客户端 ↔ 传统服务器 | 同上 | ✅ PASS | HTTP 200, 66ms |
| 5 | 断点：未迁移客户端 ↔ PQC-only 服务器 | 客户端仅 x25519，服务器仅 X25519MLKEM768 | ❌ 预期失败 | No common named group |
| 6 | 正向：JDK ↔ JDK（生产默认） | [X25519MLKEM768,x25519] | ✅ PASS | HTTP 200, 37ms, TLSv1.3 |

服务端最终协商：`bc=TLSv1.3/TLS_CHACHA20_POLY1305_SHA256`、`jdk=TLSv1.3/TLS_AES_256_GCM_SHA384`、`legacy=TLSv1.3/TLS_AES_256_GCM_SHA384`、`pqcOnly=none`（断点场景）。

## 6. 结论与上线建议

- **方案C 是推荐生产路径**：双栈共存 + PQC 优先 + 传统回退，兼顾**量子抗性、兼容性、可回滚**。
- **关键纪律**：
  1. 群组顺序必须是 `[X25519MLKEM768, x25519]`，x25519 是兼容兜底，不可省略直到全量收敛；
  2. TLS 必须强制 1.3（PQC 群组不支持更低版本）；
  3. JDK 与 BC 上下文显式指定 provider，避免默认选择漂移；
  4. 跨栈签名方案按目标服务端定制。
- **后续收敛**：当全部对端支持 PQC 后，可逐步移除 `x25519` 与 ECDSA 证书，切换纯 ML-KEM + ML-DSA 全链路。

---
*运行方式：`powershell -ExecutionPolicy Bypass -File run-all.ps1`；本报告数据对应 `logs/runC.log`。*
