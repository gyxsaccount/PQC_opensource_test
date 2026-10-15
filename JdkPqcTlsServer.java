import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import javax.net.ssl.*;

/**
 * JDK 27 原生 TLS 1.3 PQC 混合组 (X25519MLKEM768) 握手 demo - Server
 *
 * JDK 24+ (JEP 496/497): ML-KEM / ML-DSA 原语 API
 * JDK 27: SunJSSE 原生支持 X25519MLKEM768 混合密钥交换组
 *         (X25519 + ML-KEM-768, draft-ietf-tls-hybrid-design)
 *
 * 依赖 keytool 预生成 keystore，通过 run_jdk_demo.bat 执行。
 */
public class JdkPqcTlsServer {

    static final int PORT = 18444;
    static final char[] PASSWORD = "changeit".toCharArray();

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: JdkPqcTlsServer <keystore-path>");
            System.exit(1);
        }
        String ksPath = args[0];

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(ksPath)) {
            ks.load(fis, PASSWORD);
        }
        String alias = ks.aliases().nextElement();
        PrivateKey privKey = (PrivateKey) ks.getKey(alias, PASSWORD);
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

        SSLContext ctx = createSSLContext(privKey, cert);

        SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
        SSLServerSocket srv = (SSLServerSocket) ssf.createServerSocket(PORT);

        SSLParameters params = srv.getSSLParameters();
        params.setProtocols(new String[]{"TLSv1.3"});
        params.setNamedGroups(new String[]{"X25519MLKEM768", "X25519"});
        srv.setSSLParameters(params);

        System.out.println("[SERVER] Listening on port " + PORT);
        System.out.println("[SERVER] Configured named groups: " + Arrays.toString(params.getNamedGroups()));

        while (true) {
            try (SSLSocket sock = (SSLSocket) srv.accept()) {
                sock.setSoTimeout(15000);
                sock.startHandshake();

                SSLSession session = sock.getSession();
                System.out.println("\n=== New client connected ===");
                System.out.println("  Peer: " + sock.getInetAddress().getHostAddress() + ":" + sock.getPort());
                System.out.println("  Protocol: " + session.getProtocol());
                System.out.println("  Cipher suite: " + session.getCipherSuite());
                System.out.println("  Session ID: " + hex(session.getId()));

                BufferedReader reader = new BufferedReader(new InputStreamReader(sock.getInputStream()));
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(sock.getOutputStream()));

                String msg = reader.readLine();
                System.out.println("  Received: \"" + msg + "\"");

                String response = "OK from JDK PQC server, got: " + msg;
                writer.write(response);
                writer.newLine();
                writer.flush();
                System.out.println("  Replied: \"" + response + "\"");
                System.out.println("=== Connection complete ===\n");
            } catch (Exception e) {
                System.err.println("[SERVER] Error: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    static SSLContext createSSLContext(PrivateKey privKey, X509Certificate cert) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("server", privKey, PASSWORD, new X509Certificate[]{cert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, PASSWORD);

        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), null, new SecureRandom());
        System.out.println("[SERVER] SSLContext ready (JDK SunJSSE with PQC group " + "X25519MLKEM768" + ")");
        return ctx;
    }

    static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}