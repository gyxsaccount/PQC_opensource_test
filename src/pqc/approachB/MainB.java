package pqc.approachB;

import java.security.KeyStore;

import javax.net.ssl.SSLContext;

import pqc.common.HttpClientFactory;
import pqc.common.PqcClient;
import pqc.common.PqcHttpServer;
import pqc.common.PqcSsl;
import pqc.common.TestUtils;

/**
 * 方案B：BouncyCastle bcjsse（bctls-jdk18on）PQC。
 * 依赖：bcprov-jdk18on + bcutil-jdk18on + bctls-jdk18on (BCJSSE provider)
 * 能力：相比 JDK 额外支持
 *   - 纯 ML-KEM 群组（MLKEM768/MLKEM512/MLKEM1024）
 *   - PQC 证书签名（ML-DSA-65，FIPS 204；SLH-DSA / Falcon 可选）
 *   - 需显式注入 BCSSLParameters.setSignatureSchemes(["mldsa65",...])
 */
public final class MainB {

    private static final String BC_MLDSA_KS = "certs/server-bc-mldsa.p12";
    private static final String ECDSA_KS = "certs/server-ecdsa.p12";
    private static final String KS_PASS = "changeit";

    public static void main(String[] args) throws Exception {
        PqcSsl.enableMlDsaSignatureSchemes();
        PqcSsl.installBouncyCastle();

        System.out.println("================================================================");
        System.out.println(" 方案B 迁移测试：BouncyCastle BCJSSE PQC（bcprov+bcutil+bctls 1.86）");
        System.out.println("================================================================");

        KeyStore bcKs = PqcSsl.loadKeyStore(BC_MLDSA_KS, KS_PASS);
        KeyStore ecdsaKs = PqcSsl.loadKeyStore(ECDSA_KS, KS_PASS);

        // 服务端：BC + ML-DSA-65 证书，混合群组 —— 9543
        PqcHttpServer bcMldsaHybrid = new PqcHttpServer(PqcSsl.bcServerContext(bcKs, KS_PASS),
                PqcSsl.hybridGroups(), 9543);
        bcMldsaHybrid.start();

        // 服务端：BC + ML-DSA-65 证书，纯 MLKEM768 —— 9544
        PqcHttpServer bcMldsaPure = new PqcHttpServer(PqcSsl.bcServerContext(bcKs, KS_PASS),
                PqcSsl.pureMlkem768(), 9544);
        bcMldsaPure.start();

        // 服务端：BC + ECDSA 证书，混合群组 —— 9546（JDK客户端互操作）
        PqcHttpServer bcEcdsaHybrid = new PqcHttpServer(PqcSsl.bcServerContext(ecdsaKs, KS_PASS),
                PqcSsl.hybridGroups(), 9546);
        bcEcdsaHybrid.start();

        // 服务端：JDK + ECDSA 证书，混合群组 —— 9545（BC客户端互操作）
        PqcHttpServer jdkEcdsaHybrid = new PqcHttpServer(PqcSsl.jdkServerContext(ecdsaKs, KS_PASS),
                PqcSsl.hybridGroups(), 9545);
        jdkEcdsaHybrid.start();

        SSLContext bcClientCtx = PqcSsl.bcClientContext(bcKs);
        SSLContext bcClientEcdsaCtx = PqcSsl.bcClientContext(ecdsaKs);
        SSLContext jdkClientCtx = PqcSsl.jdkClientContext(bcKs);
        SSLContext jdkClientEcdsaCtx = PqcSsl.jdkClientContext(ecdsaKs);

        System.out.println("\n--- 场景1 正向：BC客户端 ↔ BC服务器（ML-DSA证书 + 混合 X25519MLKEM768） ---");
        try (PqcClient client = HttpClientFactory.build("方案B-客户端", bcClientCtx, PqcSsl.hybridGroups(),
                new String[]{"TLSv1.3"}, PqcSsl.PQC_SIGNATURE_SCHEMES)) {
            TestUtils.run(client, "https://localhost:9543/data", "正向-ML-DSA证书+混合密钥交换");
        }

        System.out.println("\n--- 场景2 正向：BC客户端 ↔ BC服务器（ML-DSA证书 + 纯 ML-KEM-768） ---");
        try (PqcClient client = HttpClientFactory.build("方案B-纯MLKEM客户端", bcClientCtx, PqcSsl.pureMlkem768(),
                new String[]{"TLSv1.3"}, PqcSsl.PQC_SIGNATURE_SCHEMES)) {
            TestUtils.run(client, "https://localhost:9544/data", "正向-纯MLKEM768密钥交换(BC特有)");
        }

        System.out.println("\n--- 场景3 互操作：JDK客户端 ↔ BC服务器(ECDSA证书, 混合X25519MLKEM768) ---");
        try (PqcClient client = HttpClientFactory.build("方案B-JDK客户端", jdkClientEcdsaCtx,
                PqcSsl.hybridGroups())) {
            TestUtils.run(client, "https://localhost:9546/data", "互操作-JDK客户端+BC服务器");
        }

        System.out.println("\n--- 场景4 互操作：BC客户端(默认签名方案) ↔ JDK服务器(ECDSA证书, 混合X25519MLKEM768) ---");
        try (PqcClient client = HttpClientFactory.build("方案B-BC客户端", bcClientEcdsaCtx,
                PqcSsl.hybridGroups())) {
            TestUtils.run(client, "https://localhost:9545/data", "互操作-BC客户端+JDK服务器");
        }

        System.out.println("\n--- 场景5 断点：JDK客户端(仅X25519MLKEM768) ↔ BC服务器(仅纯MLKEM768) ---");
        try (PqcClient client = HttpClientFactory.build("方案B-JDK客户端", jdkClientCtx,
                new String[]{"X25519MLKEM768"})) {
            TestUtils.run(client, "https://localhost:9544/data", "断点-无共同TLS群组(JKD无纯MLKEM)");
        }

        System.out.println("\n--- 场景6 断点：在 JDK 客户端上强制配置纯 MLKEM768 群组字符串 ---");
        try (PqcClient client = HttpClientFactory.build("方案B-JDK错误群组", jdkClientCtx,
                new String[]{"MLKEM768"})) {
            TestUtils.run(client, "https://localhost:9543/data", "断点-纯MLKEM768在JDK不可配置");
        } catch (Exception e) {
            System.out.println("  [FAIL] 断点-纯MLKEM768在JDK不可配置");
            System.out.println("         " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.out.println("         (预期失败：JDK 的 SSLParameters.setNamedGroups 不识别 MLKEM768)");
        }

        System.out.println("\n--- 场景7 断点：JDK客户端(信任ML-DSA证书) ↔ BC的ML-DSA证书服务器 ---");
        System.out.println("    （JDK JSSE 的 signature_algorithms 不含 mldsa，服务端无法签名 CertificateVerify）");
        try (PqcClient client = HttpClientFactory.build("方案B-JDK客户端", jdkClientCtx,
                PqcSsl.hybridGroups())) {
            TestUtils.run(client, "https://localhost:9543/data", "断点-JDK JSSE无法认证ML-DSA证书");
        }

        System.out.println("\n[服务端最后协商] bcMldsaHybrid=" + bcMldsaHybrid.getLastNegotiated()
                + " | bcMldsaPure=" + bcMldsaPure.getLastNegotiated()
                + " | bcEcdsaHybrid=" + bcEcdsaHybrid.getLastNegotiated()
                + " | jdkEcdsaHybrid=" + jdkEcdsaHybrid.getLastNegotiated());
        bcMldsaHybrid.close();
        bcMldsaPure.close();
        bcEcdsaHybrid.close();
        jdkEcdsaHybrid.close();
        System.out.println("\n方案B 测试结束。");
    }
}
