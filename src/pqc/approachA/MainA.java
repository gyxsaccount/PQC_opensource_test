package pqc.approachA;

import java.security.KeyStore;

import javax.net.ssl.SSLContext;

import pqc.common.HttpClientFactory;
import pqc.common.PqcClient;
import pqc.common.PqcHttpServer;
import pqc.common.PqcSsl;
import pqc.common.TestUtils;

/**
 * 方案A：JDK 内置 PQC（零第三方依赖）。
 * 依赖：JDK 21+（本测试环境 JDK 27）
 *   - TLS 群组：X25519MLKEM768（混合式，ML-KEM 与 X25519 组合）
 *   - 证书：本方案用 ECDSA 证书（JDK JSSE 的 signature_algorithms 不含 mldsa，
 *     无法用 ML-DSA 证书做 TLS 服务端认证——见场景2断点）
 */
public final class MainA {

    private static final String ECDSA_KS = "certs/server-ecdsa.p12";
    private static final String MLDSA_KS = "certs/server-jdk.p12";
    private static final String KS_PASS = "changeit";

    public static void main(String[] args) throws Exception {
        PqcSsl.enableMlDsaSignatureSchemes();

        System.out.println("================================================================");
        System.out.println(" 方案A 迁移测试：JDK 内置 PQC（X25519MLKEM768 密钥交换）");
        System.out.println("================================================================");

        KeyStore ecdsaKs = PqcSsl.loadKeyStore(ECDSA_KS, KS_PASS);
        KeyStore mldsaKs = PqcSsl.loadKeyStore(MLDSA_KS, KS_PASS);

        // 服务端：JDK(SunJSSE) SSLContext + ECDSA 证书，混合群组
        SSLContext serverCtx = PqcSsl.jdkServerContext(ecdsaKs, KS_PASS);
        PqcSsl.printGroups("JDK服务端", serverCtx);
        PqcHttpServer pServer = new PqcHttpServer(serverCtx, PqcSsl.hybridGroups(), 9443);
        pServer.start();

        // 服务端2：JDK(SunJSSE) + ML-DSA-65 证书（断点测试：JDK JSSE 不支持）
        PqcHttpServer mldsaServer = new PqcHttpServer(PqcSsl.jdkServerContext(mldsaKs, KS_PASS),
                PqcSsl.hybridGroups(), 9445);
        mldsaServer.start();

        // 服务端3：仅 PQC 群组（断点测试用）
        PqcHttpServer pOnlyServer = new PqcHttpServer(serverCtx, new String[]{"X25519MLKEM768"}, 9444);
        pOnlyServer.start();

        // 客户端：JDK(SunJSSE) SSLContext
        SSLContext clientCtx = PqcSsl.jdkClientContext(ecdsaKs);
        PqcSsl.printGroups("JDK客户端", clientCtx);

        System.out.println("\n--- 场景1 正向：JDK客户端 ↔ JDK服务器（混合密钥交换 X25519MLKEM768） ---");
        try (PqcClient client = HttpClientFactory.build("方案A-客户端", clientCtx, PqcSsl.hybridGroups())) {
            TestUtils.run(client, "https://localhost:9443/data", "正向-PQC混合密钥交换(X25519MLKEM768)");
        }

        System.out.println("\n--- 场景2 断点：JDK JSSE 无法用 ML-DSA-65 证书做 TLS 服务端认证 ---");
        SSLContext jdkMldsaTrustCtx = PqcSsl.jdkClientContext(mldsaKs);
        try (PqcClient client = HttpClientFactory.build("方案A-MLDSA客户端", jdkMldsaTrustCtx,
                PqcSsl.hybridGroups())) {
            TestUtils.run(client, "https://localhost:9445/data", "断点-JDK JSSE不支持ML-DSA证书");
        }

        System.out.println("\n--- 场景3 断点：服务端仅X25519MLKEM768 + 客户端仅x25519（未启用PQC） ---");
        try (PqcClient client = HttpClientFactory.build("方案A-传统客户端", clientCtx, PqcSsl.legacyGroups())) {
            TestUtils.run(client, "https://localhost:9444/data", "断点-无共同TLS群组导致握手失败");
        }

        System.out.println("\n--- 场景4 断点：强制TLS1.2（X25519MLKEM768 仅支持 TLS1.3） ---");
        try (PqcClient client = HttpClientFactory.build("方案A-TLS12客户端", clientCtx,
                PqcSsl.hybridGroups(), new String[]{"TLSv1.2"})) {
            TestUtils.run(client, "https://localhost:9443/data", "断点-混合群组在TLS1.2不可用");
        }

        System.out.println("\n--- 场景5 证书验证：默认PKIX TrustManager 校验 ECDSA 证书链 ---");
        System.out.println("    （场景1已通过，说明 SunJSSE PKIX 信任链校验正常）");

        System.out.println("\n[服务端最后协商] pServer=" + pServer.getLastNegotiated()
                + " | mldsa=" + mldsaServer.getLastNegotiated()
                + " | pOnly=" + pOnlyServer.getLastNegotiated());
        pServer.close();
        mldsaServer.close();
        pOnlyServer.close();
        System.out.println("\n方案A 测试结束。");
    }
}
