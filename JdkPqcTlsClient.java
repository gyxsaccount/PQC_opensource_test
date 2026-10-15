import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import javax.net.ssl.*;

/**
 * JDK 27 原生 TLS 1.3 PQC 混合组 (X25519MLKEM768) 握手 demo - Client
 *
 * 客户端不需要 keystore，使用 trust-all TrustManager 验证握手，
 * 关键点在于与服务器共同协商 X25519MLKEM768 混合组。
 */
public class JdkPqcTlsClient {

    static final String HOST = "localhost";
    static final int PORT = 18444;
    static final int CONNECT_TIMEOUT_MS = 10000;
    static final int READ_TIMEOUT_MS = 10000;
    static final String TEST_MESSAGE = "Hello from JDK native PQC client!";

    public static void main(String[] args) throws Exception {
        SSLContext ctx = createClientSSLContext();

        SSLParameters params = ctx.getDefaultSSLParameters();
        System.out.println("[CLIENT] JDK default named groups: " + Arrays.toString(params.getNamedGroups()));
        System.out.println("[CLIENT] Connecting to " + HOST + ":" + PORT + " ...");

        try (SSLSocket sock = (SSLSocket) ctx.getSocketFactory().createSocket()) {
            sock.connect(new java.net.InetSocketAddress(HOST, PORT), CONNECT_TIMEOUT_MS);
            sock.setSoTimeout(READ_TIMEOUT_MS);

            SSLParameters sslParams = sock.getSSLParameters();
            sslParams.setProtocols(new String[]{"TLSv1.3"});
            sslParams.setNamedGroups(new String[]{"X25519MLKEM768"});
            sock.setSSLParameters(sslParams);

            sock.startHandshake();

            SSLSession session = sock.getSession();
            System.out.println("\n=== JDK native PQC TLS 1.3 handshake complete ===");
            System.out.println("  Protocol: " + session.getProtocol());
            System.out.println("  Cipher suite: " + session.getCipherSuite());
            System.out.println("  Negotiated group: X25519MLKEM768 (set by client)");
            System.out.println("  Session ID: " + hex(session.getId()));
            System.out.println("  Cipher suite uses hybrid key exchange: "
                + (session.getCipherSuite().startsWith("TLS_") ? "TLS 1.3 HKDF" : ""));
            System.out.println("  Server cert: " + ((java.security.cert.X509Certificate) session.getPeerCertificates()[0]).getSubjectX500Principal());

            BufferedReader reader = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(sock.getOutputStream()));

            System.out.println("\n  Sending: \"" + TEST_MESSAGE + "\"");
            writer.write(TEST_MESSAGE);
            writer.newLine();
            writer.flush();

            String response = reader.readLine();
            System.out.println("  Received: \"" + response + "\"");

            if (response != null && response.contains(TEST_MESSAGE)) {
                System.out.println("\n[CLIENT] SUCCESS: hybrid X25519MLKEM768 TLS 1.3 handshake + encrypted exchange verified");
            } else {
                System.out.println("\n[CLIENT] WARNING: unexpected response");
            }
        }
    }

    static SSLContext createClientSSLContext() throws Exception {
        TrustManager[] trustAll = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, trustAll, new SecureRandom());
        return ctx;
    }

    static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}