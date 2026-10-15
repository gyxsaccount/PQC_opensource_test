import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * 迁移点2: ML-DSA 证书 + JSSE TLS 握手 -> 阻断验证
 *
 * 实证 JSSE 的 signature_algorithms 扩展硬编码不含 ML-DSA，
 * 即使 keytool 能生成 ML-DSA 证书、Jetty SslContextFactory 能加载，
 * 真实 TLS 握手也会失败 (handshake_failure / No available authentication scheme)。
 *
 * 依赖: etc/mldsa.p12 (keytool -genkeypair -keyalg ML-DSA -groupname ML-DSA-65 ...)
 * 运行: java -cp lib/*;out MldsaCertBlockTest etc/mldsa.p12 18445
 */
public class MldsaCertBlockTest {

    static final char[] PASSWORD = "changeit".toCharArray();

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: MldsaCertBlockTest <mldsa-keystore-path> <port>");
            System.exit(1);
        }
        String ksPath = args[0];
        int port = Integer.parseInt(args[1]);

        System.out.println("=== 迁移点2: ML-DSA 证书阻断验证 (Jetty SslContextFactory) ===");
        System.out.println("JDK    : " + System.getProperty("java.version"));
        System.out.println("SSLEngine based provider : " + SSLContext.getDefault().getProvider().getName());

        // 1) 加载 ML-DSA keystore
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(ksPath)) {
            ks.load(fis, PASSWORD);
        }
        String alias = ks.aliases().nextElement();
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        System.out.println("证书    : subject=" + cert.getSubjectX500Principal()
                + ", sigAlg=" + cert.getSigAlgName()
                + ", pubKeyAlg=" + cert.getPublicKey().getAlgorithm()
                + ", pubKeyLen=" + cert.getPublicKey().getEncoded().length + "B");

        // 2) 用 Jetty SslContextFactory 加载 (与 Jetty 生产一致)
        SslContextFactory.Server ssl = new SslContextFactory.Server();
        ssl.setKeyStorePath(ksPath);
        ssl.setKeyStorePassword(new String(PASSWORD));
        try {
            ssl.start();
            System.out.println("[ OK ] Jetty SslContextFactory 加载 ML-DSA 证书: 成功");
        } catch (Exception e) {
            System.out.println("[FAIL] Jetty SslContextFactory 加载失败: " + e.getMessage());
        }

        // 3) 直接加载到 SSLContext (绕过 Jetty, 单独验证 JSSE)
        PrivateKey privKey = (PrivateKey) ks.getKey(alias, PASSWORD);
        KeyStore inMem = KeyStore.getInstance("PKCS12");
        inMem.load(null, null);
        inMem.setKeyEntry("mldsa", privKey, PASSWORD, new X509Certificate[]{cert});
        javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance("SunX509");
        kmf.init(inMem, PASSWORD);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, new java.security.SecureRandom());
        System.out.println("[ OK ] SSLContext 初始化: 成功 (KeyManager 加载 ML-DSA 证书)");

        // 4) 查询 TLS signature schemes 是否含 PQC
        SSLParameters params = SSLContext.getDefault().getDefaultSSLParameters();
        System.out.println("TLS signature schemes: " + Arrays.toString(params.getSignatureSchemes()));
        boolean hasPqc = false;
        for (String s : params.getSignatureSchemes()) {
            if (s.toLowerCase().contains("mldsa") || s.toLowerCase().contains("dilithium")
                    || s.toLowerCase().contains("slh") || s.toLowerCase().contains("falcon")) {
                hasPqc = true;
            }
        }
        System.out.println("含 PQC 签名算法: " + hasPqc);

        // 5) 真实 TLS 握手验证 -> 预期失败
        SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
        SSLServerSocket srv = (SSLServerSocket) ssf.createServerSocket(port);
        srv.setSoTimeout(8000);
        System.out.println("\n[TLS] 服务监听端口 " + port + ", 等待握手 (8s 超时)...");

        // 启动客户端线程主动发起握手
        Thread clientThread = new Thread(() -> {
            try {
                Thread.sleep(500);
                javax.net.ssl.SSLSocket cs = (javax.net.ssl.SSLSocket) javax.net.ssl.SSLSocketFactory.getDefault()
                        .createSocket("localhost", port);
                cs.startHandshake();
                System.out.println("[CLIENT] 握手成功 (意外!): " + cs.getSession().getCipherSuite());
                cs.close();
            } catch (Exception ex) {
                System.out.println("[CLIENT] 握手异常: " + ex.getClass().getSimpleName() + " -> " + ex.getMessage());
            }
        });
        clientThread.start();

        try {
            javax.net.ssl.SSLSocket sock = (javax.net.ssl.SSLSocket) srv.accept();
            sock.startHandshake();
            System.out.println("[TLS] 握手成功 (意外!): " + sock.getSession().getCipherSuite());
            sock.close();
        } catch (javax.net.ssl.SSLHandshakeException e) {
            System.out.println("[TLS] 握手失败 (预期, 阻断实证): " + e.getClass().getSimpleName()
                    + " -> " + e.getMessage());
            System.out.println("  => ML-DSA 证书无法用于 JSSE TLS 握手 (signature_algorithms 硬编码缺位)");
            System.out.println("  => 过渡期方案: 保持 EC/RSA 证书签名 + X25519MLKEM768 混合密钥交换");
        } finally {
            clientThread.join(1000);
            srv.close();
        }
        System.out.println("\n=== 迁移点2 结论: ML-DSA 证书签名不可直迁移, 阻断于 JSSE signature_algorithms ===");
    }
}
