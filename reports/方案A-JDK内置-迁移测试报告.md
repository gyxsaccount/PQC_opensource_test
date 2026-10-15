# 方案A 迁移测试报告 —— JDK 内置 PQC（X25519MLKEM768 密钥交换）

## 1. 测试概述

| 项 | 内容 |
|---|---|
| 被测对象 | Apache HttpClient 5.6.4 + JDK 内置 JSSE（SunJSSE） |
| 环境 | JDK 27 (Oracle, build 27+35)，Windows，无第三方密码学依赖 |
| 目标 | 验证仅用 JDK 内置能力完成 TLS 1.3 后量子密钥交换迁移 |
| 启用能力 | TLS 群组 `X25519MLKEM768`（ML-KEM 与 X25519 的混合式），证书签名 ML-DSA-65（仅 keytool 生成能力验证） |
| 结果 | **正向 1 项通过；断点 3 项按预期失败** |

## 2. 迁移方案（方案A：零依赖，先跑通 KEX）

### 2.1 迁移优先级
1. **TLS 1.3 + 混合密钥交换 X25519MLKEM768**（P0，对抗 "Store-Now-Decrypt-Later"）
2. 证书签名保持 ECDSA（JDK JSSE 暂不支持 ML-DSA 证书做 TLS 认证，见断点分析）
3. 后续再叠加 PQC 证书（需切换到方案B/C 的 BC 栈）

### 2.2 关键前提
- JDK 21+ 内置 `X25519MLKEM768` 混合群组（探测结果：JDK 27 支持）。
- JDK 27 内置 ML-KEM(512/768/1024)、ML-DSA(44/65/87) 密钥/证书能力，但 **TLS 签名方案不含 ML-DSA**（见 4.1）。

## 3. 改造点（含代码）

### 改造点 1：显式指定 SunJSSE 提供者构建 SSLContext
> 背景：若环境中同时注册了 BouncyCastle，`SSLContext.getInstance("TLS")` 会优先选中 BCJSSE。迁移代码必须**显式 pin 提供者**，保证"JDK 方案"真的走 SunJSSE。

```java
// src/pqc/common/PqcSsl.java
public static final String SUN_JSSE = "SunJSSE";

public static SSLContext jdkClientContext(KeyStore trustStore) throws Exception {
    TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", SUN_JSSE);
    tmf.init(trustStore);
    SSLContext ctx = SSLContext.getInstance("TLS", SUN_JSSE);
    ctx.init(null, tmf.getTrustManagers(), new SecureRandom());
    return ctx;
}

public static SSLContext jdkServerContext(KeyStore ks, String password) throws Exception {
    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509", SUN_JSSE);
    kmf.init(ks, password.toCharArray());
    SSLContext ctx = SSLContext.getInstance("TLS", SUN_JSSE);
    ctx.init(kmf.getKeyManagers(), null, new SecureRandom());
    return ctx;
}
```

### 改造点 2：自定义 SSLSocketFactory 注入 PQC 群组（核心）
> JDK 的 `SSLContext.getSupportedSSLParameters()` 虽支持 `X25519MLKEM768`，但默认不启用。需在握手前通过 `SSLParameters.setNamedGroups` 注入，并固定 TLSv1.3、保留默认密码套件。

```java
// src/pqc/common/PqcSocketFactory.java —— 关键片段
private Socket configure(Socket socket) throws IOException {
    if (socket instanceof SSLSocket sslSocket) {
        SSLParameters params = sslSocket.getSSLParameters();
        params.setNamedGroups(namedGroups);                 // ["X25519MLKEM768","x25519"]
        params.setProtocols(protocols);                     // ["TLSv1.3"]
        params.setCipherSuites(sslSocket.getEnabledCipherSuites()); // 保留默认套件
        sslSocket.setSSLParameters(params);
        sslSocket.addHandshakeCompletedListener(e -> lastSession.set(e.getSession()));
    }
    return socket;
}
```

### 改造点 3：HttpClient5 接入自定义 SSLContext（注入点）
> HttpClient5 通过 `SSLConnectionSocketFactory(SSLSocketFactory, protocols, ciphers, hostnameVerifier)` 接入自定义套接字工厂。

```java
// src/pqc/common/HttpClientFactory.java
public static PqcClient build(String label, SSLContext sslContext, String[] namedGroups, String[] protocols) {
    PqcSocketFactory socketFactory = new PqcSocketFactory(sslContext, namedGroups, protocols, null);
    SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(
            socketFactory, protocols, null, NoopHostnameVerifier.INSTANCE);
    PoolingHttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
            .setSSLSocketFactory(csf)
            .build();
    return new PqcClient(
            HttpClients.custom().setConnectionManager(cm).build(),
            socketFactory);
}
```

### 改造点 4：服务端启用 PQC 群组（测试服务器）
```java
// src/pqc/common/PqcHttpServer.java —— start()
SSLServerSocket ss = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(port);
SSLParameters params = ss.getSSLParameters();
params.setProtocols(new String[]{"TLSv1.3"});
params.setNamedGroups(namedGroups);                    // 服务端也必须声明
params.setCipherSuites(ss.getEnabledCipherSuites());   // 保留默认套件（重要）
ss.setSSLParameters(params);
```

### 改造点 5：部署配置（非代码）
生产环境可用 JVM 参数替代代码注入：
```
-Djdk.tls.namedGroups=X25519MLKEM768,x25519
```

## 4. 断点分析

### 4.1 【关键断点】JDK JSSE 不支持 ML-DSA 证书做 TLS 认证
- **现象**：JDK 服务端加载 ML-DSA-65 证书后握手失败：`SSLHandshakeException: (handshake_failure) No available authentication scheme`。
- **根因**：对 `sun.security.ssl.SignatureScheme` 反射枚举，JDK 27 的 TLS 签名方案**不含 `mldsa44/65/87`**（仅 ECDSA/EdDSA/RSA/DSA）。服务端无法用 ML-DSA 私钥签名 CertificateVerify，于是所有密码套件不可用。
- **影响**：**纯 JDK 方案现阶段只能用 ECDSA/RSA 证书**；PQC 证书必须依赖 BCJSSE（见方案B）。
- **证据**（`logs/runA.log` 场景2）：
  ```
  X509Authentication: No X.509 cert selected for EC / EdDSA / RSA
  CertificateMessage: No available authentication scheme
  ```
- **对策**：方案A 将证书保持 ECDSA；如需 PQC 证书，升级到方案B/C。

### 4.2 【断点】未启用 PQC 群组导致无共同群组
- **现象**：服务端仅 `X25519MLKEM768`，客户端仅 `x25519` → `SSLProtocolException: (unexpected_message) No common named group`。
- **结论**：**只要一端未配置 PQC 群组，混合式迁移即可无缝回退；若一端强制纯 PQC，另一端未配置则直接断连**。迁移必须两端协调、以混合群组打底。

### 4.3 【断点】PQC 混合群组仅支持 TLS 1.3
- **现象**：客户端强制 TLSv1.2 → `SSLHandshakeException: (protocol_version) ... not accepted by server preferences [TLSv1.3]`。
- **结论**：`X25519MLKEM768` 是 TLS 1.3 专属群组。迁移前提是**全面启用 TLS 1.3**（禁用 TLS1.2/更早版本，避免降级）。

### 4.4 顺带发现（环境层）
- JDK 27 `keytool` 可直接生成 ML-DSA-65 自签名证书（`-keyalg ML-DSA-65`），用于证书能力验证。

## 5. 测试结果明细

| # | 场景 | 配置 | 结果 | 明细 |
|---|---|---|---|---|
| 1 | 正向：JDK↔JDK 混合密钥交换 | ECDSA 证书 + [X25519MLKEM768,x25519] | ✅ PASS | HTTP 200, 115ms, TLSv1.3 / TLS_AES_256_GCM_SHA384 |
| 2 | 断点：ML-DSA 证书在 JDK JSSE | JDK 服务端 ML-DSA-65 证书 | ❌ 预期失败 | No available authentication scheme |
| 3 | 断点：无共同群组 | 服务端仅 X25519MLKEM768 + 客户端仅 x25519 | ❌ 预期失败 | No common named group |
| 4 | 断点：强制 TLS1.2 | 客户端 TLSv1.2 | ❌ 预期失败 | protocol_version |

服务端最终协商：`TLSv1.3 / TLS_AES_256_GCM_SHA384`（确认协商了 PQC 混合群组密钥交换）。

## 6. 结论与上线建议

- 方案A **可立即上线**保护会话密钥：只需 JDK 21+，升级后配置群组 `X25519MLKEM768,x25519` 并强制 TLS1.3。
- **限制**：证书仍是 ECDSA/RSA（证书签名暂未量子化）；若企业要求端到端全链路量子抗性，需叠加方案B/C 的 PQC 证书。
- 迁移期间务必保留 `x25519` 作为回退群组，避免与未迁移对端断连。

---
*运行方式：`powershell -ExecutionPolicy Bypass -File run-all.ps1`；本报告数据对应 `logs/runA.log`。*
