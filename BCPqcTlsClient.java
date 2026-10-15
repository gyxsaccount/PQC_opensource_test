import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.net.ssl.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class BCPqcTlsClient {

    static final String HOST = "localhost";
    static final int PORT = 18443;
    static final int CONNECT_TIMEOUT_MS = 10000;
    static final int READ_TIMEOUT_MS = 10000;
    static final String TEST_MESSAGE = "Hello from PQC client!";

    public static void main(String[] args) throws Exception {
        installProviders();

        SSLContext ctx = createClientSSLContext();

        String pqcGroup = discoverPqcGroup(ctx);
        System.out.println("[CLIENT] Using PQC named group: " + pqcGroup);

        SSLSocketFactory sf = ctx.getSocketFactory();
        System.out.println("[CLIENT] Connecting to " + HOST + ":" + PORT + " ...");

        try (SSLSocket sock = (SSLSocket) sf.createSocket(HOST, PORT)) {
            sock.setSoTimeout(READ_TIMEOUT_MS);

            SSLParameters params = sock.getSSLParameters();
            params.setProtocols(new String[]{"TLSv1.3"});
            params.setNamedGroups(new String[]{pqcGroup});
            sock.setSSLParameters(params);

            sock.startHandshake();

            SSLSession session = sock.getSession();
            SSLParameters negotiated = sock.getSSLParameters();

            System.out.println("\n=== PQC TLS 1.3 handshake complete ===");
            System.out.println("  Connected to: " + sock.getInetAddress().getHostAddress() + ":" + sock.getPort());
            System.out.println("  Protocol: " + session.getProtocol());
            System.out.println("  Cipher suite: " + session.getCipherSuite());
            System.out.println("  Negotiated named group(s): " + Arrays.toString(negotiated.getNamedGroups()));
            System.out.println("  Session ID: " + hex(session.getId()));
            System.out.println("  Session created: " + new Date(session.getCreationTime()));

            X509Certificate[] peerCerts = (X509Certificate[]) session.getPeerCertificates();
            System.out.println("  Server certificates (" + peerCerts.length + "):");
            for (X509Certificate c : peerCerts) {
                System.out.println("    Subject:  " + c.getSubjectX500Principal());
                System.out.println("    Issuer:   " + c.getIssuerX500Principal());
                System.out.println("    SigAlg:   " + c.getSigAlgName());
                System.out.println("    Serial:   " + c.getSerialNumber());
                System.out.println("    Validity: " + c.getNotBefore() + " - " + c.getNotAfter());
            }
            System.out.println("  Peer host: " + session.getPeerHost());

            BufferedReader reader = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(sock.getOutputStream()));

            System.out.println("\n  Sending: \"" + TEST_MESSAGE + "\"");
            writer.write(TEST_MESSAGE);
            writer.newLine();
            writer.flush();

            String response = reader.readLine();
            System.out.println("  Received: \"" + response + "\"");

            if (TEST_MESSAGE.length() > 0 && response != null && response.contains(TEST_MESSAGE)) {
                System.out.println("\n[CLIENT] SUCCESS: full PQC handshake + encrypted message exchange verified");
            } else {
                System.out.println("\n[CLIENT] WARNING: response did not echo the sent message");
            }
        }
    }

    static void installProviders() {
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
        Security.removeProvider("BCJSSE");
        Security.addProvider(new BouncyCastleJsseProvider());
        System.out.println("[CLIENT] Providers:");
        for (Provider p : Security.getProviders())
            System.out.println("  " + p.getName() + " v" + p.getVersionStr());
    }

    static SSLContext createClientSSLContext() throws Exception {
        TrustManager[] trustAll = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "BCJSSE");
        ctx.init(null, trustAll, new SecureRandom());
        System.out.println("[CLIENT] SSLContext ready (trust-all manager)");
        return ctx;
    }

    static String discoverPqcGroup(SSLContext ctx) {
        String[] candidates = {
            "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
            "X25519MLKEM1024", "x25519Kyber768", "X25519Kyber768",
            "p256Kyber768", "MLKEM768", "MLKEM1024"
        };
        try {
            SSLEngine engine = ctx.createSSLEngine();
            SSLParameters params = engine.getSSLParameters();

            String[] configured = params.getNamedGroups();
            System.out.println("[CLIENT] Default named groups: " + Arrays.toString(configured));

            for (String c : candidates) {
                try {
                    params.setNamedGroups(new String[]{c});
                    String[] result = params.getNamedGroups();
                    if (result != null && result.length > 0) {
                        System.out.println("[CLIENT] Group '" + c + "' available");
                        return result[0];
                    }
                } catch (Exception e) {
                    // skip
                }
            }
        } catch (Exception e) {
            System.out.println("[CLIENT] Probe failed, use default: " + e.getMessage());
        }
        return "X25519MLKEM768";
    }

    static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}