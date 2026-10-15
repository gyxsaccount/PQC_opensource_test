package pqc.approachC;

import java.security.KeyStore;

import javax.net.ssl.SSLContext;

import pqc.common.HttpClientFactory;
import pqc.common.PqcClient;
import pqc.common.PqcHttpServer;
import pqc.common.PqcSsl;
import pqc.common.TestUtils;

/**
 * 方案C：混合式（JDK 内置 + BouncyCastle 双栈，推荐生产方案）。
 * 策略：客户端群组优先 PQC(X25519MLKEM768)，回退 x25519 保证向后兼容；
 *       服务端可先部署 BC 栈以获得更广的 PQC 群组覆盖，再逐步收敛为纯 PQC。
 * 说明：互操作场景服务端使用 ECDSA 证书（PQC 密钥交换 + 传统证书签名），
 *       ML-DSA 证书仅 BCJSSE 服务端可用（见方案B 场景1/2/7）。
 */
public final class MainC {

    private static final String ECDSA_KS = "certs/server-ecdsa.p12";
    private static final String LEGACY_KS = "certs/server-legacy.p12";
    private static final String KS_PASS = "changeit";

    public static void main(String[] args) throws Exception {
        PqcSsl.enableMlDsaSignatureSchemes();
        PqcSsl.installBouncyCastle();

        System.out.println("================================================================");
        System.out.println(" 方案C 迁移测试：混合式（JDK 内置 + BouncyCastle 双栈）");
        System.out.println("================================================================");

        KeyStore ecdsaKs = PqcSsl.loadKeyStore(ECDSA_KS, KS_PASS);
        KeyStore legacyKs = PqcSsl.loadKeyStore(LEGACY_KS, KS_PASS);

        // 服务端：BC 栈（混合群组 + ECDSA 证书）  —— 9643
        PqcHttpServer bcServer = new PqcHttpServer(PqcSsl.bcServerContext(ecdsaKs, KS_PASS),
                PqcSsl.hybridGroups(), 9643);
        bcServer.start();

        // 服务端：JDK 栈（混合群组 + ECDSA 证书）  —— 9644
        PqcHttpServer jdkServer = new PqcHttpServer(PqcSsl.jdkServerContext(ecdsaKs, KS_PASS),
                PqcSsl.hybridGroups(), 9644);
        jdkServer.start();

        // 服务端：传统（EC 证书 + 仅 x25519） —— 9645（回退测试）
        PqcHttpServer legacyServer = new PqcHttpServer(PqcSsl.jdkServerContext(legacyKs, KS_PASS),
                PqcSsl.legacyGroups(), 9645);
        legacyServer.start();

        // 服务端：仅 PQC 群组 —— 9646（断点测试）
        PqcHttpServer pqcOnlyServer = new PqcHttpServer(PqcSsl.jdkServerContext(ecdsaKs, KS_PASS),
                new String[]{"X25519MLKEM768"}, 9646);
        pqcOnlyServer.start();

        SSLContext jdkClientCtx = PqcSsl.jdkClientContext(ecdsaKs);
        SSLContext bcClientCtx = PqcSsl.bcClientContext(ecdsaKs);
        SSLContext jdkClientLegacyCtx = PqcSsl.jdkClientContext(legacyKs);

        System.out.println("\n--- 场景1 互操作：JDK客户端 ↔ BC服务器（X25519MLKEM768） ---");
        try (PqcClient client = HttpClientFactory.build("方案C-JDK客户端", jdkClientCtx,
                PqcSsl.hybridGroups())) {
            TestUtils.run(client, "https://localhost:9643/data", "互操作-JDK客户端+BC服务器");
        }

        System.out.println("\n--- 场景2 互操作：BC客户端(默认签名方案) ↔ JDK服务器（X25519MLKEM768） ---");
        try (PqcClient client = HttpClientFactory.build("方案C-BC客户端", bcClientCtx,
                PqcSsl.hybridGroups())) {
            TestUtils.run(client, "https://localhost:9644/data", "互操作-BC客户端+JDK服务器");
        }

        System.out.println("\n--- 场景3 回退：PQC优先JDK客户端 ↔ 传统服务器(仅x25519)，自动回退 ---");
        try (PqcClient client = HttpClientFactory.build("方案C-回退JDK客户端", jdkClientLegacyCtx,
                PqcSsl.hybridGroups())) {
            TestUtils.run(client, "https://localhost:9645/data", "回退-传统服务器x25519仍可连接");
        }

        System.out.println("\n--- 场景4 回退：PQC优先BC客户端 ↔ 传统服务器(仅x25519) ---");
        try (PqcClient client = HttpClientFactory.build("方案C-回退BC客户端", jdkClientLegacyCtx,
                PqcSsl.hybridGroups())) {
            TestUtils.run(client, "https://localhost:9645/data", "回退-BC客户端+传统服务器");
        }

        System.out.println("\n--- 场景5 断点：客户端仅x25519 ↔ PQC-only服务器（未迁移彻底） ---");
        try (PqcClient client = HttpClientFactory.build("方案C-未迁移客户端", jdkClientCtx,
                PqcSsl.legacyGroups())) {
            TestUtils.run(client, "https://localhost:9646/data", "断点-未启用PQC群组导致失败");
        }

        System.out.println("\n--- 场景6 正向：JDK客户端 ↔ JDK服务器（生产默认配置） ---");
        try (PqcClient client = HttpClientFactory.build("方案C-生产客户端", jdkClientCtx,
                PqcSsl.hybridGroups())) {
            TestUtils.run(client, "https://localhost:9644/data", "正向-混合密钥交换(X25519MLKEM768)");
        }

        System.out.println("\n[服务端最后协商] bc=" + bcServer.getLastNegotiated()
                + " | jdk=" + jdkServer.getLastNegotiated()
                + " | legacy=" + legacyServer.getLastNegotiated()
                + " | pqcOnly=" + pqcOnlyServer.getLastNegotiated());
        bcServer.close();
        jdkServer.close();
        legacyServer.close();
        pqcOnlyServer.close();
        System.out.println("\n方案C 测试结束。");
    }
}
