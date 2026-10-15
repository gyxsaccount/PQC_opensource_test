# Angus Mail（Eclipse Angus / Jakarta Mail）后量子（PQC）迁移测试报告

## 目录

1. [测试概述](#1-测试概述)
2. [迁移点总览](#2-迁移点总览)
3. [组件版本配套关系](#3-组件版本配套关系)
4. [迁移点 P1：TLS 传输（SMTP/IMAP/POP3）](#4-迁移点-p1tls-传输)
5. [迁移点 P2：PQC-SIGN SASL 认证](#5-迁移点-p2pqc-sign-sasl-认证)
6. [迁移点 P3：S/MIME 式混合端到端加密](#6-迁移点-p3smime-式混合端到端加密)
7. [迁移点 P4：本地凭证量子抗性存储](#7-迁移点-p4本地凭证量子抗性存储)
8. [迁移点 P5：混合 DKIM 签名](#8-迁移点-p5混合-dkim-签名)
9. [迁移断点与解决方案](#9-迁移断点与解决方案)
10. [工程结构](#10-工程结构)
11. [结论与实施路线](#11-结论与实施路线)

---

## 1. 测试概述

**测试目标**：将 Eclipse Angus Mail（Jakarta Mail 官方参考实现）从经典密码学迁移到后量子（PQC），覆盖邮件客户端的**全部密码学使用面**，提供可运行的迁移 Demo 与实测证据。

**核心结论**：

- Angus Mail 是纯应用层协议库，自身不实现密码学，SMTP/IMAP/POP3 的 TLS 全部委托 JSSE，认证委托 SASL，S/MIME/OpenPGP 委托 BouncyCastle → **迁移全部集中在「接入层」与「密码学装配层」，业务代码零侵入**。
- 实测打通 **5 个迁移点（P1–P5）**，三条技术路线（JDK 内置 / BouncyCastle / 混合双栈）全部可运行、可验证。
- 发现并解决 **3 个关键迁移断点**（详见 §9）：Angus 自定义 SocketFactory 的 `getDefault()` 静态约定、SocketFetcher 强制主机名校验、JDK `Sasl` 不扫描 classpath 服务注册。

**测试环境**：

| 项目 | 规格 |
|---|---|
| 操作系统 | Windows x86-64 |
| JDK | **JDK 27**（build 27+35-2325，2026-09-15），含 JEP 496（ML-KEM）、JEP 497（ML-DSA）、`X25519MLKEM768` 混合组 |
| Angus Mail | angus-mail **2.0.5** |
| BouncyCastle | bcprov/bcpkix/bctls/bcutil **1.86**（bctls 1.86.1） |
| 测试目录 | `D:\PQC-test\angus-mail\` |

---

## 2. 迁移点总览

| # | 迁移点 | 使用面 | 经典算法 | 后量子方案 | 状态 |
|---|---|---|---|---|---|
| **P1** | TLS 传输 | SMTP/IMAP/POP3 隐式 TLS + STARTTLS | ECDHE/X25519 + ECDSA 证书 | 混合密钥交换 **X25519MLKEM768**；BC 栈支持 **ML-DSA-65 证书** | ✅ 已实现/实测 |
| **P2** | 认证 | SASL（替代 CRAM-MD5/DIGEST-MD5 弱口令哈希） | 口令哈希 / OAuth2 令牌 | 自定义 **PQC-SIGN**（ML-DSA 挑战-响应签名） | ✅ 已实现/实测 |
| **P3** | 端到端加密 | S/MIME / OpenPGP 内容机密性 | RSA/ECDSA + AES | **混合信封**：ML-KEM-768 + RSA-OAEP 共同封装 AES-256-GCM；**混合签名** ML-DSA-65 + Ed25519 | ✅ 已实现/实测 |
| **P4** | 本地凭证 | 口令/OAuth2 令牌落盘 | AES-GCM + 口令 KDF | **ML-KEM-768 封装 DEK + AES-256-GCM**（PqcVault） | ✅ 已实现/实测 |
| **P5** | 邮件签名 | DKIM 防伪造 | RSA/Ed25519 | **混合 DKIM**：`a=ed25519-sha256` 与 `a=mldsa65` 双签名 | ✅ 已实现/实测 |

### 实测结果速览（logs/runA/B/C.log）

| 验证项 | 结果 |
|---|---|
| 方案A：SMTP 发送 / IMAP 连接 / POP3 连接（JDK 原生，握手协商 **X25519MLKEM768**） | ✅ 全部通过 |
| 方案A：PQC 优先客户端 → 传统服务器（自动回退 x25519） | ✅ 通过 |
| 方案B：BC 客户端 ↔ BC 服务器（**ML-DSA-65 证书** + X25519MLKEM768），SMTP/IMAP/POP3 | ✅ 全部通过 |
| 方案B：JDK↔BC、BC↔JDK 互操作（ECDSA 证书） | ✅ 通过 |
| 方案B：JDK 客户端 → BC ML-DSA 服务器（断点实证，预期失败） | ✅ 按预期失败 |
| 方案C：PQC-SIGN SASL 认证发送成功 / 错误私钥被 535 拒绝 | ✅ 通过 |
| 方案C：混合加密 87B→1470B 解密还原 / 混合签名 5407B 验签 / Angus MimeMessage 承载往返 | ✅ 通过 |
| 方案C：PqcVault 口令密封-解封 23B→1150B | ✅ 通过 |
| 方案C：混合 DKIM（ed25519 + mldsa65）双验签 | ✅ 通过 |

---

## 2.5 代码修改点一览

> **约定**：本文所有代码示例中，标有 `// [PQC-MOD]`（或行尾 `// 🔧 修改点`）的行 = 本次迁移新增/改造的代码行。Angus Mail 本体代码**零改动**。

| 迁移点 | 修改文件（新增） | 关键代码修改点 | 修改性质 |
|---|---|---|---|
| P1 | `PqcSocketFactory.java` | `public static SSLSocketFactory getDefault()`（断点1 对策）；`configure()` 注入 `setNamedGroups([X25519MLKEM768, x25519])` | 新增接入类 |
| P1 | `MailPqcConfig.java` | `p.put("mail.{proto}.ssl.socketFactory", new PqcSocketFactory())` | 新增属性装配 |
| P1 | `PqcSsl.java` / `PqcMailServer.java` | 双栈 SSLContext 工厂 / 本地 PQC 邮件测试服务器 | 新增测试基座 |
| P2 | `PqcSaslClient.java` | `evaluateChallenge()` 用 `Signature.getInstance("ML-DSA")` 签名响应 | 新增认证机制 |
| P2 | `PqcSaslProvider.java` | `put("SaslClientFactory.PQC-SIGN", ...)`（断点3 对策） | 新增 JCA Provider 注册 |
| P3 | `PqcMailCrypto.java` | `encrypt/decrypt/sign/verify` 混合信封（ML-KEM-768 + RSA-OAEP → AES-256-GCM） | 新增端到端加密 |
| P4 | `PqcVault.java` | `seal/open` ML-KEM-768 封装 DEK + AES-256-GCM | 新增凭证存储 |
| P5 | `PqcDkim.java` | `X-PQC-DKIM-Signature: a=mldsa65` 双签名头 | 新增邮件签名 |

---

## 3. 组件版本配套关系

### 3.1 依赖矩阵（lib/ 下全部实测兼容）

| 组件 | 版本 | 作用 | 配套说明 |
|---|---|---|---|
| **angus-mail** | 2.0.5 | Jakarta Mail 参考实现（SMTP/IMAP/POP3 Provider） | 通过 POM 确定其依赖版本 |
| jakarta.mail-api | 2.1.5 | Jakarta Mail API | 由 angus-mail 2.0.5 父 POM `mail-api.version` 锁定 |
| angus-activation | 2.0.3 | Jakarta Activation 实现（MIME DataHandler） | 由父 POM `angus.activation.version` 锁定 |
| jakarta.activation-api | 2.1.4 | Jakarta Activation API | 由父 POM `activation-api.version` 锁定 |
| **bcprov-jdk18on** | 1.86 | BC 原语 Provider（ML-KEM/ML-DSA/SLH-DSA/Falcon） | 方案B/C 必需 |
| **bctls-jdk18on** | 1.86.1 | BCJSSE TLS Provider | 依赖 bcprov+bcutil |
| **bcpkix-jdk18on** | 1.86 | X.509/CMS 证书工具 | 依赖 bcprov+bcutil |
| **bcutil-jdk18on** | 1.86 | BC 公共工具（ASN.1 等） | 1.86 起必需，缺失会 `NoClassDefFoundError` |
| JDK | **27** | SunJSSE + JEP 496/497 + `X25519MLKEM768` | 方案A 零依赖；< JDK 27 见 §9 断点 4 |

### 3.2 版本配套关系（关键约束）

```
angus-mail 2.0.5 ─┬─ jakarta.mail-api 2.1.5
                  ├─ angus-activation 2.0.3
                  └─ jakarta.activation-api 2.1.4

JDK 27 SunJSSE: TLSv1.3 + named group X25519MLKEM768（混合密钥交换）
  └── PQC 证书签名 (ML-DSA) ⚠️ 仅 BCJSSE 可用（JDK 27 的 signature_algorithms 无 mldsa）

BouncyCastle 1.86 (bcprov+bctls): 纯 ML-KEM768 / ML-DSA 证书 / 混合组 全部可用
```

**版本敏感性提示**：
- `angus-mail` 的依赖版本由父 POM 统一管理，**不要**随意升级 mail-api，避免 API 不兼容。
- BC `bctls` 与 `bcprov` 版本需一致（1.86.x），混用不同小版本会握手异常。
- JDK 24-26 仅有 ML-KEM/ML-DSA 原语但 JSSE 无 PQC 组 → 必须叠加 BC BCTLS（方案B）。

---

## 4. 迁移点 P1：TLS 传输

### 4.1 改造方式（Angus Mail 侧零代码改动）

Angus Mail 通过会话属性装配自定义 SocketFactory。所有密码学配置收敛到一个类：`PqcSocketFactory`（静态配置 + 无参构造 + 静态 `getDefault()`）。

```java
// MailPqcConfig.java —— 三个协议统一注入 PQC 套接字工厂 + TLSv1.3
private static Properties base(String proto, String host, int port) {
    Properties p = new Properties();
    p.setProperty("mail." + proto + ".host", host);
    p.setProperty("mail." + proto + ".port", String.valueOf(port));
    p.setProperty("mail." + proto + ".ssl.enable", "true");            // 隐式 TLS
    p.setProperty("mail." + proto + ".starttls.enable", "true");       // STARTTLS 通道
    p.setProperty("mail." + proto + ".ssl.protocols", "TLSv1.3");
    p.put("mail." + proto + ".ssl.socketFactory", new PqcSocketFactory()); // [PQC-MOD] 实例注入
    p.setProperty("mail." + proto + ".ssl.socketFactory.fallback", "false");
    return p;
}
```

```java
// PqcSocketFactory.java —— 在握手前把 PQC 命名群组注入 SSLSocket（JDK/BC 双栈）
public final class PqcSocketFactory extends SSLSocketFactory {
    private static volatile SSLContext context;           // 静态配置（各方案切换）
    private static volatile String[] namedGroups;
    private static volatile String[] signatureSchemes;
    private static volatile SSLSession lastSession;       // 记录最近握手会话供报告

    public static SSLSocketFactory getDefault() {         // [PQC-MOD] ★ Angus SocketFetcher 约定
        return new PqcSocketFactory();
    }

    public PqcSocketFactory() {                            // [PQC-MOD] 无参构造（Angus newInstance）
        this.delegate = context.getSocketFactory();
        this.bc = PqcSsl.BC_JSSE.equals(context.getProvider().getName());
    }

    private Socket configure(Socket socket) throws IOException {
        if (socket instanceof SSLSocket ssl) {
            if (bc && ssl instanceof BCSSLSocket bcSocket) {
                BCSSLParameters p = bcSocket.getParameters();
                p.setNamedGroups(namedGroups);            // [X25519MLKEM768, x25519]
                p.setProtocols(new String[]{"TLSv1.3"});
                p.setCipherSuites(ssl.getEnabledCipherSuites());
                if (signatureSchemes != null) p.setSignatureSchemes(signatureSchemes); // ML-DSA
                bcSocket.setParameters(p);
            } else {
                SSLParameters p = ssl.getSSLParameters();
                p.setNamedGroups(namedGroups);
                p.setProtocols(new String[]{"TLSv1.3"});
                p.setCipherSuites(ssl.getEnabledCipherSuites());
                ssl.setSSLParameters(p);
            }
            ssl.addHandshakeCompletedListener(e -> lastSession = e.getSession());
        }
        return socket;
    }
    // createSocket(host,port) / createSocket(raw,host,port,autoClose) ... 委托 + configure
}
```

### 4.2 三条技术路线

| 方案 | 技术栈 | SSLContext 构建 | 证书 | 能力 |
|---|---|---|---|---|
| **A** | JDK 27 原生 SunJSSE | `SSLContext.getInstance("TLS","SunJSSE")` | ECDSA | 混合组 `X25519MLKEM768`，零依赖 |
| **B** | BouncyCastle BCJSSE | `SSLContext.getInstance("TLS","BCJSSE")` | **ML-DSA-65** 或 ECDSA | 混合组 + **纯 MLKEM768** + PQC 证书 |
| **C** | JDK + BC 双栈 | 按场景切换 provider | 混合演进 | PQC 优先 + x25519 回退（生产推荐） |

```java
// PqcSsl.java —— 双栈 SSLContext 工厂（复用 httpclient5 同款）
public static SSLContext jdkClientContext(KeyStore trustStore) {
    TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
    tmf.init(trustStore);
    SSLContext ctx = SSLContext.getInstance("TLS", "SunJSSE");
    ctx.init(null, tmf.getTrustManagers(), new SecureRandom());
    return ctx;
}
public static SSLContext bcClientContext(KeyStore trustStore) {
    TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "BCJSSE");
    tmf.init(trustStore);
    SSLContext ctx = SSLContext.getInstance("TLS", "BCJSSE");
    ctx.init(null, tmf.getTrustManagers(), new SecureRandom());
    return ctx;
}
// 服务端同理：jdkServerContext / bcServerContext（KMF = SunX509 / X.509）
```

### 4.3 本地 PQC 邮件服务器（验证端）

`PqcMailServer` 基于 `SSLServerSocket` 实现极简 SMTP/IMAP/POP3 隐式 TLS 服务器，支持任意 SSLContext 与命名群组，可选支持 PQC-SIGN 认证（P2）。

```
客户端(Angus Mail + PqcSocketFactory)
   │  TLSv1.3 + X25519MLKEM768
   ▼
[SMTP 2543] 220 ESMTP / 250-AUTH PQC-SIGN / MAIL/RCPT/DATA/QUIT
[IMAP 2544] * OK CAPABILITY / LOGIN / LIST / SELECT / LOGOUT
[POP3 2545] +OK / CAPA / USER / PASS / STAT / QUIT
```

### 4.4 实测结果（握手调试日志）

```
ServerHello { "named group": X25519MLKEM768 }   ← 协商混合后量子组
Negotiated protocol version: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384 (JDK) / TLS_CHACHA20_POLY1305_SHA256 (BC)

[client] SMTP 发送 完成 | alice@pqc.local -> bob@pqc.local
[client] IMAP 连接 完成
[client] POP3 连接 完成
[服务端] smtpMldsa=TLSv1.3/TLS_CHACHA20_POLY1305_SHA256 证书=ML-DSA-65   ← PQC 证书签名
```

**调用链**：`Transport.send()` → `SMTPTransport` → `SocketFetcher.getSocket()` → 读 `mail.smtp.ssl.socketFactory`（实例）→ `getDefault()` → `PqcSocketFactory.createSocket(raw, host, port, true)`（layered）→ `configure()` 注入群组 → 握手。

---

## 5. 迁移点 P2：PQC-SIGN SASL 认证

### 5.1 协议设计

用 ML-DSA-65 挑战-响应签名替代 CRAM-MD5/DIGEST-MD5 的弱口令哈希认证：

```
客户端                                  服务器（预注册用户→ML-DSA 公钥）
  │  AUTH PQC-SIGN                        │
  │ ◄──────── 334 <base64 16B 挑战>       │
  │  响应 = user ":" base64(ML-DSA 签名)   │
  │  签名内容 = "PQC-SIGN" || 挑战 || user │
  │ ────────► 验证 → 235 / 535            │
```

### 5.2 实现（客户端）

```java
// PqcSaslClient.java
@Override
public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
    String user = authorizationId != null ? authorizationId : "anonymous";
    byte[] input = ("PQC-SIGN\0" + new String(challenge, ISO_8859_1) + "\0" + user)
            .getBytes(UTF_8);
    Signature sig = Signature.getInstance("ML-DSA");       // [PQC-MOD] JDK 27 原生 FIPS 204
    sig.initSign(KeyFactory.getInstance("ML-DSA")
            .generatePrivate(new PKCS8EncodedKeySpec(privateKey)));
    sig.update(input);
    String resp = user + ":" + Base64.getEncoder().encodeToString(sig.sign()); // [PQC-MOD] 挑战-响应
    complete = true;
    return resp.getBytes(UTF_8);
}
```

### 5.3 关键断点：JDK Sasl 不扫描 classpath 服务

实测发现：`Sasl.createSaslClient()` 在 JDK 27 上**不会**通过 `META-INF/services` 发现应用注册的工厂（探针枚举只返回 `com.sun.security.sasl.*` 内置工厂），必须用 **JCA Provider** 注册：

```java
// PqcSaslProvider.java —— 以 Security Provider 注册 SaslClientFactory 服务
public final class PqcSaslProvider extends Provider {
    public PqcSaslProvider() {
        super("PqcSasl", 1.0, "PQC-SIGN (ML-DSA challenge-response) SASL provider");
        put("SaslClientFactory.PQC-SIGN", PqcSaslClientFactory.class.getName()); // [PQC-MOD] 断点3 对策
    }
}
// 使用时：Security.addProvider(new PqcSaslProvider());
```

```java
// 会话属性装配（MailPqcConfig.smtpAuth）
props.setProperty("mail.smtp.auth", "true");
props.setProperty("mail.smtp.auth.mechanisms", "PQC-SIGN");
props.setProperty("mail.smtp.sasl.enable", "true");
props.setProperty("mail.smtp.sasl.pqc.privateKey", b64(ML-DSA 私钥));
```

### 5.4 实测结果

```
[client] SMTP 发送（PQC-SIGN 认证） 完成 | alice@pqc.local -> bob@pqc.local
[预期失败] 错误 ML-DSA 私钥被服务器拒绝 -> 535 Authentication credentials invalid
```

---

## 6. 迁移点 P3：S/MIME 式混合端到端加密

### 6.1 混合信封设计（crypto-agility hybrid）

```
内容加密:   AES-256-GCM（12B IV + 密文+Tag）
会话密钥:   CEK = SHA-256( ML-KEM-768 共享密钥 || RSA-OAEP 共享密钥 )
封装1:      ML-KEM-768 封装 CEK（密文 1088B）      ← 后量子
封装2:      RSA-OAEP-2048 加密 CEK（密文 256B）    ← 经典兜底
安全性 = max(经典, 后量子)：仅破解其一无法解密
```

```
混合签名:   ML-DSA-65 签名 + Ed25519 签名，双签名均验证通过才有效
格式:       "PQCSIGN1" || 公钥s || 签名s
```

### 6.2 实现要点（JDK 原生 PQC，零第三方依赖）

```java
// PqcMailCrypto.encrypt —— 混合封装
KEM kem = KEM.getInstance("ML-KEM");
KEM.Encapsulator enc = kem.newEncapsulator(recipient.mlkemPub);   // [PQC-MOD] 公钥封装
KEM.Encapsulated cap = enc.encapsulate();
byte[] mlkemSs = cap.key().getEncoded();                          // ML-KEM 共享密钥
byte[] rsaCt = rsaCipher.doFinal(randomCek);                      // RSA-OAEP 封装
byte[] cek = sha256(concat(mlkemSs, sha256(randomCek)));          // [PQC-MOD] 联合派生
Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"));
byte[] ct = aes.doFinal(data);                                    // AES-256-GCM
```

### 6.3 与 Angus Mail 的承载集成

加密后的密文作为 `application/octet-stream` 载荷附着到 `MimeMessage`，经 Angus `writeTo` 序列化 / 重新解析 / 解密还原：

```java
MimeMessage carried = new MimeMessage(session);
carried.setFrom(...); carried.setRecipient(...); carried.setSubject("PQC 加密邮件载体");
carried.setDataHandler(new DataHandler(
        new jakarta.mail.util.ByteArrayDataSource(encrypted, "application/octet-stream")));
carried.saveChanges();
// 传输序列化 → 解析 → carriedEnc = received.getInputStream().readAllBytes();
// PqcMailCrypto.decrypt(km, carriedEnc) → 还原原文
```

### 6.4 实测结果

```
明文=87B | 密文=1470B | 解密还原=true        ← 混合封装解封装闭环
混合签名(ML-DSA-65 + Ed25519): 签名=5407B | 验签=true
Angus Mail MimeMessage 承载密文往返: 解密还原=true | 主题=PQC 加密邮件载体
```

> 说明：RFC 9629 / LAMPS 完成 PQC 证书与 CMS 混合格式标准化后，将同一套原语嵌入 BC `CMSSignedData`/`CMSEnvelopedDataGenerator` 即可升级为标准 S/MIME，本实现为该方向的原型验证。

---

## 7. 迁移点 P4：本地凭证量子抗性存储

### 7.1 设计

`PqcVault` 持有 ML-KEM-768 密钥对：

- `seal()`：用自身公钥封装随机 DEK → AES-256-GCM 加密明文 → 产出可落盘 blob；
- `open()`：用私钥解封装 DEK → 解密。

```
"PQCVAULT1" || ML-KEM 密文(1088B) || IV(12B) || AES-GCM 密文
```

### 7.2 实现要点

```java
KEM.Encapsulator enc = kem.newEncapsulator(vaultPub);      // [PQC-MOD] 封装随机 DEK
byte[] dek = sha256(cap.key().getEncoded());
Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");      // AES-256-GCM
aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"));
// open(): Decapsulator.decapsulate(ct) → 还原 DEK → 解密
```

### 7.3 实测结果

```
Vault(ML-KEM-768 封装 DEK + AES-256-GCM): 明文=23B | blob=1150B | 恢复=smtp-password-@XyZ2026! | 匹配=true
```

---

## 8. 迁移点 P5：混合 DKIM 签名

### 8.1 设计

经典 DKIM（`a=ed25519-sha256`）与 PQC DKIM（`a=mldsa65`）**双头并存**，收件端需同时通过两个验签：

```
DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=pqc.local; s=pqc; bh=<sha256(body)>; h=from:subject; pk=<公钥>; b=<Ed25519 签名>
X-PQC-DKIM-Signature: v=1; a=mldsa65; c=relaxed/relaxed; d=pqc.local; s=pqc; bh=<sha256(body)>; h=from:subject; pk=<公钥>; b=<ML-DSA-65 签名>  <!-- [PQC-MOD] PQC 双签名头 -->
```

签名输入 = `from + "\n" + subject + "\n" + base64(bh)`（DKIM 式 header 规范化 + 正文哈希）。

### 8.2 实测结果

```
经典 DKIM a=ed25519-sha256 验证=true
PQC DKIM  a=mldsa65        验证=true
头部样例: v=1; a=mldsa65; c=relaxed/relaxed; d=pqc.local; s=pqc; bh=AapU8obaNC/geRhdo1fKkOlnPNe18nDHXfRuvO ...
```

---

## 9. 迁移断点与解决方案

> 「断点」指组件**无法直接提供**、需要变通或自定义才能完成 PQC 迁移的环节。实测共发现 **6 个断点**，全部有解决方案。

### 断点 1：Angus 自定义 SocketFactory 需要静态 `getDefault()`

| 项 | 内容 |
|---|---|
| **现象** | 只提供无参构造时报 `NoSuchMethodException`，Angus 回退默认 SSL 工厂 → 自签名证书不受信（`PKIX path building failed`） |
| **根因** | `SocketFetcher.getSocketFactory(String)` 用反射调用 `Class.getMethod("getDefault")`，**这是 Jakarta Mail 的自定义工厂约定** |
| **解决方案** | 在 `PqcSocketFactory` 加 `public static SSLSocketFactory getDefault()`（✅ 已实现） |

### 断点 2：SocketFetcher 强制主机名校验

| 项 | 内容 |
|---|---|
| **现象** | 信任链配置正确仍报 `CERTIFICATE_UNKNOWN: No name matching localhost found`（异常外层错误 `PKIX path building failed` 具误导性） |
| **根因** | `SocketFetcher.configureSSLSocket()` 无条件设置 endpoint identification（HTTPS），触发 `X509TrustManagerImpl.checkIdentity` |
| **解决方案** | 服务器证书必须 **CN/SAN 包含实际主机名**。本项目用 `keytool -ext san=dns:localhost,ip:127.0.0.1` 重新生成证书（✅ 已实现）；生产应使用匹配主机名的受信 CA 证书 |

### 断点 3：JDK `Sasl` 不扫描 classpath 的 `META-INF/services`

| 项 | 内容 |
|---|---|
| **现象** | `Sasl.createSaslClient` 返回 null，报 `No authentication mechanisms supported by both server and client`；探针显示只枚举到 `com.sun.security.sasl.*` 内置工厂 |
| **根因** | JDK 27 `Sasl` 的工厂发现机制不使用应用 classpath 的 ServiceLoader |
| **解决方案** | **切换注册方式**：用 `Security.addProvider(new PqcSaslProvider())` 注册 `SaslClientFactory.PQC-SIGN` JCA Provider 服务（✅ 已实现） |

### 断点 4：JDK 版本决定 JSSE 层 PQC 能力

| 项 | 内容 |
|---|---|
| **现象** | `x25519` / ECDSA 一切正常，但 ML-DSA 证书在 JDK JSSE 握手报 `handshake_failure: found no selectable cipher suite`（方案B场景6 实测） |
| **根因** | JDK 27 `SunJSSE` 的 `signature_algorithms` 协商列表硬编码，不含 `mldsa*`；JDK 24-26 连 `X25519MLKEM768` 组也没有 |
| **解决方案** | ① JDK < 27 → **切换依赖** BC BCTLS（方案B）；② 需要 PQC 证书签名 → 必须 BC 栈；③ 等待 IETF LAMPS 标准后 JDK 原生支持（2033 CNSA 2.0 目标） |

### 断点 5：`mail.smtp.writetimeout` 引入 WriteTimeoutSocket 包装层

| 项 | 内容 |
|---|---|
| **现象** | 设置 `writetimeout` 时 SocketFetcher 会把原始 Socket 包成 `WriteTimeoutSocket` 再交给自定义工厂 layered `createSocket`，调试链路变复杂 |
| **解决方案** | 演示工程不设置 writetimeout，聚焦 TLS 迁移；生产可按需保留（不破坏 PQC 注入，仅增加包装层） |

### 断点 6：单 Part `application/octet-stream` 的 DCH 缺失

| 项 | 内容 |
|---|---|
| **现象** | `MimeBodyPart.setContent(base64字符串, "application/octet-stream")` 后 `writeTo` 报 `UnsupportedDataTypeException: no object DCH` |
| **根因** | 内容对象（String/byte[]）没有对应 `DataContentHandler`，ObjectDataContentHandler 无法序列化 |
| **解决方案** | 改用 `DataHandler(new ByteArrayDataSource(bytes, "application/octet-stream"))`（✅ 已实现） |

---

## 10. 工程结构

```
angus-mail/
├── lib/                        # 全部依赖 jar（版本见 §3）
├── certs/                      # 测试证书（CN=localhost + SAN，keytool 生成）
│   ├── server-ecdsa.p12        # ECDSA 证书（方案A/B/C 通用）
│   ├── server-legacy.p12       # 传统 EC 证书（回退测试）
│   └── server-bc-mldsa.p12     # ML-DSA-65 证书（方案B）
├── logs/                       # 运行日志（含 TLS 握手调试）
│   ├── runA.log / runB.log / runC.log
├── reports/                    # 本报告（.md + .html 可视化版）
├── src/pqc/
│   ├── common/
│   │   ├── PqcSsl.java         # 双栈 SSLContext/Provider 工厂
│   │   ├── PqcSocketFactory.java # P1 自定义套接字工厂（getDefault 约定）
│   │   ├── MailPqcConfig.java  # P1/P2 会话属性装配
│   │   ├── PqcMailServer.java  # 本地 PQC SMTP/IMAP/POP3 服务器
│   │   ├── PqcMailCrypto.java  # P3 混合加密/签名
│   │   ├── PqcVault.java       # P4 本地凭证 Vault
│   │   └── PqcDkim.java        # P5 混合 DKIM
│   ├── sasl/
│   │   ├── PqcSaslClient.java  # P2 SASL 客户端（ML-DSA 签名）
│   │   ├── PqcSaslClientFactory.java
│   │   └── PqcSaslProvider.java # P2 JCA Provider 注册（断点3 对策）
│   ├── approachA/MainA.java    # 方案A：JDK 原生
│   ├── approachB/MainB.java    # 方案B：BouncyCastle
│   └── approachC/MainC.java    # 方案C：混合双栈 + P2/P3/P4/P5 全迁移点
├── build.ps1                   # 编译（纯 javac，无需 Maven）
├── run-all.ps1                 # 一键运行三方案并生成日志
├── pom.xml                     # Maven 依赖参考（CI 环境）
└── README.md                   # 环境要求/依赖安装/运行/预期输出/严格性说明/版本记录/断点链接
```

**运行方式**：

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1     # 编译 -> out/
powershell -ExecutionPolicy Bypass -File run-all.ps1    # 运行三方案 -> logs/
```

---

## 11. 结论与实施路线

### 11.1 结论

1. **Angus Mail PQC 迁移可行且低成本**：纯应用层库 + 密码学委托设计，P1–P5 全部可在**业务代码零侵入**下完成。
2. **TLS 层是迁移主线**：`X25519MLKEM768` 混合组（JDK 27 原生或 BC）即可立即保护会话密钥；PQC 证书签名（ML-DSA）目前**仅 BC 栈可用**。
3. **三个关键断点已实测并解决**：`getDefault()` 静态约定、SocketFetcher 主机名校验、`Sasl` Provider 注册。
4. **内容机密性**（P3/P4）与**认证/签名**（P2/P5）可通过 JDK 原生 PQC 原语（JEP 496/497）以混合方式先行落地，待 LAMPS/RFC 9629 标准化后平滑升级为标准 S/MIME/DKIM。

### 11.2 实施路线

| 阶段 | 时间 | 动作 |
|---|---|---|
| **当前** | 2026 | 升 JDK 27+，方案A/C 注入 `PqcSocketFactory`，TLS 走 `X25519MLKEM768`；本地凭证换 PqcVault（P4） |
| **近期** | 2027 | 方案B 引入 BC 栈 + ML-DSA 证书；OAuth2 令牌/口令认证换 PQC-SIGN（P2）；邮件签名换混合 DKIM（P5） |
| **中期** | 2029-2030 | LAMPS 标准成熟后，P3 混合信封嵌入标准 CMS/OpenPGP；服务端证书过渡到双证书（经典+PQC） |
| **远期** | 2033+ | CNSA 2.0：全链路纯 ML-KEM/ML-DSA，移除经典回退 |

### 版本记录

| 版本 | 日期 | 变更 |
|---|---|---|
| 1.0.0 | 2026-09-29 | 初始版本：P1–P5 全迁移点、三方案实测、6 断点对策、可视化报告 |
| 1.0.1 | 2026-09-29 | 刷新：新增「代码修改点一览」，代码示例中修改点行以 `// [PQC-MOD]` 标注（HTML 版黄色高亮），工程结构补充 README.md |

---

*报告生成：2026-09-29（v1.0.1）· 全部验证数据取自 `logs/runA.log` / `logs/runB.log` / `logs/runC.log`*
