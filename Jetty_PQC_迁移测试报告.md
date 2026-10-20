# Jetty 12 PQC 后量子迁移测试报告

## 1. 测试概述

**被测软件**: Eclipse Jetty 12.1.13 (HTTP 服务器 / Servlet 容器 / HTTP 客户端)
**迁移目标**: 后量子密码 (PQC, Post-Quantum Cryptography) 全链路迁移
**测试环境**: Windows x86-64, **JDK 27** (SunJSSE 原生支持 PQC), Bouncy Castle 1.86

**关键结论速览**:

| 迁移点 | 现状算法 | PQC 目标 | 状态 |
|--------|---------|---------|------|
| 1. TLS 密钥交换 | ECDHE(X25519) | **X25519MLKEM768** (混合组) | ✅ 可迁移(已实证) |
| 2. 证书签名 | ECDSA/RSA | ML-DSA | ⚠️ **阻断点**(已实证) |
| 3. HTTP 摘要认证 | MD5 | **SHA-384** (384 位) | ✅ 可迁移(已实证) |
| 4. 口令哈希/Realm | MD5/SHA-1 | **SHA3-384** (384 位)/Argon2 | ✅ 可迁移(已实证) |
| 5. 会话安全 | SecureRandom | 增强熵+配置 | ✅ 可迁移(已实证) |
| 6. OIDC/JWT | RS256/ES256 | ML-DSA(JOSE) | ⚠️ 依赖 IETF |
| 7. HttpClient 出站 TLS | ECDHE | X25519MLKEM768 | ✅ 可迁移(已实证) |
| 8. HTTP/3 (QUIC) | TLS 1.3 | 同迁移点1 | ⚠️ 依赖 Quiche 原生库 |

---

## 2. 测试环境

| 项目 | 值 |
|------|----|
| 操作系统 | Windows x86-64 |
| JDK | **JDK 27** (build 27+35-2325) |
| Jetty | 12.1.13 (jetty-server/util/http/io/security/client/session/openid/http3) |
| 额外依赖 | slf4j 2.0.17, nimbus-jose-jwt 10.0.1, caffeine, BC 1.86 |
| 项目目录 | `D:\PQC-test\jetty\` |
| 运行脚本 | `run_jetty_pqc.bat` |

---

## 3. 迁移点实现与验证

### 3.1 迁移点1: TLS 握手密钥交换 → X25519MLKEM768 ✅

**实现**: `src/JettyPqcServer.java`
内嵌 Jetty HTTPS 服务器, 覆写 `SslContextFactory.customize(SSLParameters)` 显式指定 named groups:

```java
class PqcSslContextFactory extends SslContextFactory.Server {
    @Override
    public SSLParameters customize(SSLParameters sslParams) {
        sslParams.setNamedGroups(new String[]{"X25519MLKEM768", "X25519", "secp256r1"});
        return super.customize(sslParams);
    }
}
```

**代码改造点** (改造前 → 改造后, `+` 新增 / `-` 删除):
```java
// 改造前: 默认 ECDHE, 未指定 PQC 组
class ServerSslCtxFactory extends SslContextFactory.Server {
    @Override
    public SSLParameters customize(SSLParameters p) { return super.customize(p); }
}
// 改造后: 覆写 customize() 强制 PQC 混合组
class PqcSslContextFactory extends SslContextFactory.Server {
+   @Override
+   public SSLParameters customize(SSLParameters p) {
+       p.setNamedGroups(new String[]{"X25519MLKEM768", "x25519", "secp256r1"});
+       return super.customize(p);
+   }
}
```
- 改造类: `SslContextFactory.Server` / `SslContextFactory.Client` (jetty-util)
- 关键 API: `SSLParameters.setNamedGroups(String[])` (JDK 27 公开; JDK 24-26 用反射/BC BCTLS)
- 服务器装配: `new ServerConnector(server, new SslConnectionFactory(ssl, "http/1.1"), new HttpConnectionFactory(https))`
- 客户端装配: `httpClient.setSslContextFactory(ssl)` (Jetty 12 独立 setter)
- 生产等价方案: `-Djdk.tls.namedGroups=X25519MLKEM768,x25519` 或 Jetty XML 配置

**验证**: 客户端仅通告 `X25519MLKEM768` 单组, 握手仍成功 → **证明服务器协商了 PQC 混合组**。

```
[CLIENT] Named groups configured (PQC only): [X25519MLKEM768, ...]
[CLIENT] GET https://localhost:18443/hello -> 200 (OK)
Server TLS : TLSv1.3 + X25519MLKEM768 (hybrid)
```

> 注: JDK 27 SunJSSE 的默认 named groups 列表首位即 `X25519MLKEM768`, 即使不显式配置, 生产环境直接运行 JDK 27+ 即可获得混合 PQC 密钥交换。

### 3.2 迁移点2: TLS 证书签名 → ML-DSA ⚠️ 阻断点(已实证)

**实现**: `src/MldsaCertBlockTest.java`
用 keytool 生成 ML-DSA-65 自签名证书, 加载到 Jetty `SslContextFactory`, 再进行真实 TLS 握手。

**实证结论**:
```
证书    : subject=CN=Jetty ML-DSA Server, sigAlg=ML-DSA-65, pubKeyLen=1974B
[ OK ] Jetty SslContextFactory 加载 ML-DSA 证书: 成功
[ OK ] SSLContext 初始化: 成功
TLS signature schemes: [ecdsa_*, ed25519, rsa_pss_*, ...]   // 共18个, 无任何 PQC
含 PQC 签名算法: false
[TLS] 握手失败 (预期, 阻断实证): SSLHandshakeException -> (handshake_failure) No available authentication scheme
```

**根因**: JSSE 的 `signature_algorithms` 扩展硬编码 18 种经典签名方案, 不含 ML-DSA。与 JSSE-java 项目 4.5/6.8 结论一致。

**代码改造点**:
- 证书生成: `keytool -genkeypair -keyalg ML-DSA -groupname ML-DSA-65 ...` (JDK 27)
- 加载 (改造点, 可行):
```java
SslContextFactory.Server ssl = new SslContextFactory.Server();
+ ssl.setKeyStorePath("etc/mldsa.p12");   // ★ 改造点: 证书换成 ML-DSA
ssl.setKeyStorePassword("changeit");
ssl.start();   // ✅ 加载成功, 但真实握手在此之后失败
```
- **阻断定位**: `SSLParameters.getSignatureSchemes()` 仅 18 种经典方案; `sun.security.ssl` 硬编码, 不经 Provider 扩展
  - 目标改造点 (待 JSSE 支持): `signature_algorithms` 期望出现 `ML-DSA-44 / ML-DSA-65 / ML-DSA-87`
- 跟踪: JDK-8332706 (ML-DSA TLS), IETF LAMPS draft-ietf-lamps-dilithium-certificates

**过渡期方案**: 保持 EC/RSA 证书签名 + X25519MLKEM768 混合密钥交换(已达 CNSA 2.0 第一阶段); 证书签名迁移等待 JSSE 支持 ML-DSA 或采用混合证书。

### 3.3 迁移点3: HTTP 摘要认证 → SHA-384 (384 位) ✅

**实现**: `src/DigestAuthPqcTest.java`
ee10 ServletContextHandler + ConstraintSecurityHandler + DigestAuthenticator, 完整 HTTP Digest challenge-response:

```
未认证请求 -> 401 (挑战) OK
WWW-Authenticate: Digest realm="pqc-realm", ..., algorithm=SHA-384, qop="auth"
HA1(SHA-384)=...
Digest 认证请求 -> 200 (OK)
响应: Protected resource OK - authenticated as alice
=> Digest 认证 + SHA-384 (384位) 挑战-应答全链路验证通过
```

**结论**: Jetty 12 `DigestAuthenticator` 默认算法为 **SHA-256 (RFC 7616)**, 通过 `setAlgorithm("SHA-384")` 显式切换至 **384 位**; 摘要长度 96 hex (48 字节), 认证链路完整可用。

**代码改造点** (改造前 → 改造后):
```java
// 改造前: 算法未显式指定 (旧版默认 MD5 / Jetty 12 默认 SHA-256) + 凭证存 MD5 哈希
DigestAuthenticator digest = new DigestAuthenticator();
- // 旧: 未显式指定算法, 挑战头 algorithm=MD5 (Jetty 12 默认 SHA-256)
UserStore us = new UserStore();
- us.addUser("alice", Credential.getCredential("MD5:" + md5Hex), roles);

// 改造后: 显式 SHA-384 (384 位) + 明文凭证由 Jetty 计算 HA1
DigestAuthenticator digest = new DigestAuthenticator();
+ digest.setAlgorithm("SHA-384");                        // ★ 关键: 384 位迁移目标 (覆盖默认 SHA-256)
UserStore us = new UserStore();
+ us.addUser("alice", Credential.getCredential("password"), roles);   // ★ 关键: 存明文, 由 Digest.check() 计算 HA1
```
- 改造类: `ConstraintSecurityHandler` + `DigestAuthenticator` (jetty-ee10-servlet)
- API 差异: Jetty 12 的 `Constraint` 为接口, 用 `new Constraint.Builder().name("digest").roles("user").build()`

> **⚠️ 算法兼容性边界**：HTTP Digest 是"无状态挑战-应答"协议，服务器发起 `algorithm=SHA-384` 挑战时**无法预先探测客户端是否支持该算法**——response 由客户端按挑战算法计算、服务器同算法复核（RFC 7616 §3.9 通过重复 `algorithm` 参数提供多算法列表让客户端选择）。
> 本测试的客户端为自研 Java 客户端（按挑战头动态选算法），**只证明 Jetty `setAlgorithm()` 能驱动 SHA-384 走完整挑战-应答链路，不能证明真实第三方客户端（浏览器/curl 等）支持**。且 SHA-384 并非 RFC 7616 注册算法（仅 MD5 / SHA-256 / SHA-512-256）。
> **生产落地建议**：改用多算法挑战（`algorithm=SHA-384, algorithm=SHA-256`）或跟随 RFC 7616 注册算法，避免客户端兼容性风险。

### 3.4 迁移点4: 口令哈希/Realm → SHA3-384 (384 位) ✅

**实现**: `src/PasswordHashPqcTest.java`

- JCE 层面 MD5/SHA-1/SHA2/SHA3 全部可用
- Jetty `Credential.getCredential()` 支持 `CRYPT:`, `MD5:`, `MD:<算法>:` 前缀, 可无缝切换 SHA3-384 (384 位):
```
MD:SHA3-384:9c1565e99afa... -> MD [OK]   校验正确密码: true, 校验错误密码: false
```
- 摘要长度增长 (基准=SHA3-384): SHA3-384 96 hex (384 位); SHA3-256 64 hex (-33%), SHA3-512 128 hex (+33%), 需评估存储字段。

**代码改造点** (改造前 → 改造后):
```java
// 改造前 (弱哈希, 量子不安全):
- Credential md5  = Credential.getCredential("MD5:" + md5Hex);    // 128-bit
- Credential sha1 = Credential.getCredential("SHA-1:" + sha1Hex); // 160-bit
// 改造后 (384 位, CNSA 2.0 推荐):
+ Credential c1 = Credential.getCredential("MD:SHA-384:" + sha384Hex);   // 384-bit
+ Credential c2 = Credential.getCredential("MD:SHA3-384:" + sha3_384Hex); // 384-bit SHA3 ★ 迁移目标
+ Credential c3 = Credential.getCredential("MD:SHA3-512:" + sha3_512Hex);
// 校验链路完全不变:
boolean ok = c2.check("password");   // → true (实测通过)
boolean bad = c2.check("wrong");     // → false (实测通过)
```
- 改造类: `org.eclipse.jetty.util.security.Credential` / `Password`
- Realm 文件格式: `alice: MD:SHA3-384:<96hex>, user`
- 需评估: 摘要长度增长对 DB 字段影响 (基准 SHA3-384, SHA3-256 -33%, SHA3-512 +33%)

### 3.5 迁移点5: 会话安全 ✅

**实现**: `src/SessionSecurityPqcTest.java`

- `SecureRandom` 默认算法 **DRBG** (CSPRNG), SHA1PRNG/Windows-PRNG 均可用
- Jetty 会话 ID: 31 hex 字符 ≈ **124 bits 熵**, 10000 次生成 0 重复
- **建议**: 会话 ID 熵略低于 128 bits, 建议提高随机字节数至 16+; 开启 HttpOnly/Secure/SameSite

**代码改造点** (改造前 → 改造后):
```java
// 改造前: 默认随机源 + 会话 ID ~124 bits
DefaultSessionIdManager idMgr = new DefaultSessionIdManager(server);
- // 旧: 未指定随机源 / workerName
// 改造后: 显式 DRBG + 分实例标识
+ idMgr.setRandom(new SecureRandom());    // ★ 关键: JDK 27 默认 DRBG (CSPRNG)
+ idMgr.setWorkerName("node1");           // 分布式多实例需区分
server.addBean(idMgr);

// 会话 Cookie (jetty.xml): 改造前 false → 改造后全开
- <Set name="httpOnly">false</Set>
- <Set name="secure">false</Set>
+ <Set name="httpOnly">true</Set>
+ <Set name="secure">true</Set>
+ <Set name="sameSite">Strict</Set>
```
- 熵增强: `DefaultSessionIdManager.setRandom(new SecureRandom())` (JDK 27 默认 DRBG)
- 生产建议: 会话 ID ≥ 32 hex 字符 (≥128 bits 熵)
- 无算法阻断, 仅配置级改造

### 3.6 迁移点6: OIDC/JWT ⚠️ 依赖 IETF

**实现**: `src/OidcJwtPqcTest.java` (nimbus-jose-jwt)

- 当前 RS256/384/512 (RSA-2048~4096), ES256/384/512 (P-256/384/521) 签名验签全部可用
- **PQC JOSE 算法全部不可用** (ML-DSA-44/65/87, SLH-DSA, Falcon 均未定义):
```
ML-DSA-44 -> 不可用   ML-DSA-65 -> 不可用   ... => JOSE PQC 算法标准未定 (IETF jose-pqc WG)
```
- 近期方案: 提升经典强度 (RSA-3072+/P-384+, HS-384+), 待 JOSE PQC 标准落地后切换。

**代码改造点** (改造前 → 改造后):
```java
// 改造前: RSA-2048 / P-256 (量子 Grover/Shor 可破)
- RSAKey rsa = new RSAKeyGenerator(2048).generate();
- ECKey  ec  = new ECKeyGenerator(Curve.P_256).generate();
// 改造后: 提升至 RSA-3072+ / P-384+ / HS-384+
+ RSAKey rsa2 = new RSAKeyGenerator(3072).generate();    // 或 4096
+ ECKey  ec2  = new ECKeyGenerator(Curve.P_384).generate();
+ JWSHeader(JWSAlgorithm.parse("RS384"))                // ★ 关键: RS384 + RSA-3072

// 待 JOSE PQC 标准落地后 (目标改造点):
+ JWSAlgorithm alg = JWSAlgorithm.parse("ML-DSA-65");   // ★ 当前实测抛 ParseException: Unsupported JWS algorithm
```
- 提升强度: `new RSAKeyGenerator(3072)`, `new ECKeyGenerator(Curve.P_384)`, 算法 RS384/ES384
- 待 JOSE PQC 落地: `JWSAlgorithm.parse("ML-DSA-65")` — 当前实测抛 `ParseException: Unsupported JWS algorithm`

### 3.7 迁移点7: HttpClient 出站 TLS ✅

**实现**: `src/JettyPqcClient.java`
Jetty HttpClient + 自定义 `SslContextFactory.Client`, 与迁移点1 相同的 named groups 覆写方式。出站 HTTPS 成功协商 PQC 混合组 (见 3.1 输出)。

### 3.8 迁移点8: HTTP/3 (QUIC) ⚠️ 环境依赖

**实现**: `src/Http3PqcTest.java`

- HTTP/3 模块类全部在 classpath (HTTP3ServerConnectionFactory, RawHTTP3ServerConnectionFactory, ServerQuicConfiguration)
- **Quiche 原生库缺失** (jetty-quiche-native 需自行构建, 不在 Maven Central) → 当前环境无法启动 HTTP/3 服务器
- HTTP/3 的 TLS 层与 HTTP/1.1/2 完全一致 (TLS 1.3), **PQC 迁移与迁移点1 相同**, 无额外算法迁移点:
```
JDK TLS named groups 首位: X25519MLKEM768, PQC 混合组可用: true
```

**代码改造点** (改造前 → 改造后):
```java
// 改造前: 仅 HTTP/1.1 连接器
SslContextFactory.Server ssl = new SslContextFactory.Server();
ssl.setKeyStorePath("etc/keystore.p12");
- // 旧: ServerConnector(HTTP/1.1 over TCP) 即可, 无 QUIC 装配

// 改造后: 新增 QUIC 配置 + HTTP/3 连接工厂 + QuicServerConnector
+ ServerQuicConfiguration quicConfig =
+     new ServerQuicConfiguration(ssl, Path.of("etc/quic-pems"));
+ quicConfig.setMaxBidirectionalRemoteStreams(1024);   // ★ 关键: QUIC 流配额
+ RawHTTP3ServerConnectionFactory http3 =
+     new RawHTTP3ServerConnectionFactory(quicConfig, sessionListener);
+ QuicServerConnector connector =
+     new QuicServerConnector(server, quicConfig, http3);
server.addConnector(connector);
```
- 装配: `ServerQuicConfiguration(ssl, Path.of("etc/quic-pems"))` + `RawHTTP3ServerConnectionFactory` + `QuicServerConnector`
- PQC named groups 复用迁移点1 的 `customize()` 覆写, 自动生效
- 环境前置: 构建 `jetty-quiche-native` (Quiche 原生库, 不在 Maven Central) — 当前 Windows 阻断

---

## 4. 迁移断点总结

| 断点 | 表现 | 影响 |
|------|------|------|
| **JSSE signature_algorithms 硬编码** | ML-DSA 证书加载 OK、握手失败 (`No available authentication scheme`) | 证书签名无法直接迁移到 ML-DSA |
| **JOSE 无 PQC 算法** | nimbus-jose-jwt 不认 ML-DSA 等 | OIDC/JWT 签名无法迁移 |
| **HTTP/3 依赖 Quiche 原生库** | jetty-quiche-native 不在 Maven Central | Windows 环境需自行编译原生库 |

---

## 5. 迁移阶段路线

| 阶段 | 时间 | 行动 |
|------|------|------|
| **当前** | 2026 | 升级 JDK 27+, HTTPS/HttpClient/HTTP3 自动获得 X25519MLKEM768 混合密钥交换; 证书保持 ECDSA; Digest 认证用 SHA-384; 口令哈希切 SHA3-384 (384 位) |
| **中期** | 2027-2028 | 待 JSSE 支持 PQC 签名算法后, 引入混合证书 (经典+PQC 双签名); OIDC 提升经典强度 |
| **远期** | 2029+ | JOSE PQC 标准落地后迁移 JWT; 证书全面 ML-DSA/SLH-DSA; CNSA 2.0 达标 |

---

## 6. 交付物清单

```
D:\PQC-test\jetty\
├── src/
│   ├── JettyPqcServer.java        迁移点1: HTTPS 服务器 + X25519MLKEM768
│   ├── JettyPqcClient.java        迁移点7: HttpClient 出站 TLS
│   ├── MldsaCertBlockTest.java    迁移点2: ML-DSA 证书阻断验证
│   ├── DigestAuthPqcTest.java     迁移点3: Digest 认证 SHA-384
│   ├── PasswordHashPqcTest.java   迁移点4: 口令哈希迁移
│   ├── SessionSecurityPqcTest.java 迁移点5: 会话安全审计
│   ├── OidcJwtPqcTest.java        迁移点6: JWT 算法评估
│   └── Http3PqcTest.java          迁移点8: HTTP/3 评估
├── lib/                           Jetty 12.1.13 + 依赖 jars
├── etc/                           keystore.p12 (EC), mldsa.p12 (ML-DSA-65)
├── results/                       运行输出归档 + 可视化报告 (report.html)
├── out/                           编译产物
└── run_jetty_pqc.bat              一键运行全部迁移点
```

**复现**: 双击运行 `run_jetty_pqc.bat`, 依次输出 8 个迁移点的实现与验证结果。
**可视化报告**: 浏览器打开 `results/report.html`, 含各迁移点代码改造点。
