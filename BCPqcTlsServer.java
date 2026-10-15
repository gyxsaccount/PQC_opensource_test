import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.net.ssl.*;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class BCPqcTlsServer {

    static final int PORT = 18443;
    static final char[] PASSWORD = "changeit".toCharArray();

    public static void main(String[] args) throws Exception {
        installProviders();

        KeyPair serverKeyPair = generateKeyPair();
        X509Certificate serverCert = generateCertificate(serverKeyPair);

        SSLContext ctx = createServerSSLContext(serverKeyPair, serverCert);

        String pqcGroup = discoverPqcGroup(ctx);
        System.out.println("[SERVER] Using PQC named group: " + pqcGroup);

        SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
        SSLServerSocket srv = (SSLServerSocket) ssf.createServerSocket(PORT);

        SSLParameters params = srv.getSSLParameters();
        params.setProtocols(new String[]{"TLSv1.3"});
        params.setNamedGroups(new String[]{pqcGroup, "X25519", "secp256r1"});
        srv.setSSLParameters(params);

        System.out.println("[SERVER] Listening on port " + PORT);
        System.out.println("[SERVER] Configured named groups: " + Arrays.toString(params.getNamedGroups()));

        while (true) {
            try (SSLSocket sock = (SSLSocket) srv.accept()) {
                sock.setSoTimeout(15000);
                sock.startHandshake();

                SSLSession session = sock.getSession();
                SSLParameters negotiated = sock.getSSLParameters();

                System.out.println("\n=== New client connected ===");
                System.out.println("  Peer: " + sock.getInetAddress().getHostAddress() + ":" + sock.getPort());
                System.out.println("  Protocol: " + session.getProtocol());
                System.out.println("  Cipher suite: " + session.getCipherSuite());
                System.out.println("  Negotiated named group(s): " + Arrays.toString(negotiated.getNamedGroups()));
                System.out.println("  Session ID: " + hex(session.getId()));
                System.out.println("  Session created: " + new Date(session.getCreationTime()));

                if (session.getLocalCertificates() != null) {
                    System.out.println("  Server cert subject: "
                        + ((X509Certificate) session.getLocalCertificates()[0]).getSubjectX500Principal());
                }
                try {
                    X509Certificate[] peerCerts = (X509Certificate[]) session.getPeerCertificates();
                    System.out.println("  Client certs (" + peerCerts.length + "):");
                    for (X509Certificate c : peerCerts) {
                        System.out.println("    Subject: " + c.getSubjectX500Principal());
                    }
                } catch (SSLPeerUnverifiedException e) {
                    System.out.println("  Client cert: (not requested / none provided)");
                }

                BufferedReader reader = new BufferedReader(new InputStreamReader(sock.getInputStream()));
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(sock.getOutputStream()));

                String msg = reader.readLine();
                System.out.println("  Received: \"" + msg + "\"");

                String response = "OK from PQC server, got: " + msg;
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

    static void installProviders() {
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
        Security.removeProvider("BCJSSE");
        Security.addProvider(new BouncyCastleJsseProvider());
        System.out.println("[SERVER] Providers:");
        for (Provider p : Security.getProviders())
            System.out.println("  " + p.getName() + " v" + p.getVersionStr());
    }

    static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        System.out.println("[SERVER] Generated EC secp256r1 keypair");
        return kp;
    }

    static X509Certificate generateCertificate(KeyPair kp) throws Exception {
        X500Name subject = new X500Name("CN=PQC TLS 1.3 Server, O=BouncyCastle, C=DE");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        long now = System.currentTimeMillis();

        JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
            subject, serial,
            new Date(now - 60000),
            new Date(now + 365L * 24 * 60 * 60 * 1000),
            subject, kp.getPublic());
        cb.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        cb.addExtension(Extension.keyUsage, true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign));

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(cb.build(new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC").build(kp.getPrivate())));

        System.out.println("[SERVER] Generated cert: subject=" + cert.getSubjectX500Principal()
            + ", sigAlg=" + cert.getSigAlgName());
        return cert;
    }

    static SSLContext createServerSSLContext(KeyPair kp, X509Certificate cert) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        ks.setKeyEntry("server", kp.getPrivate(), PASSWORD, new X509Certificate[]{cert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", "BCJSSE");
        kmf.init(ks, PASSWORD);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "BCJSSE");
        KeyStore ts = KeyStore.getInstance("PKCS12", "BC");
        ts.load(null, null);
        ts.setCertificateEntry("server", cert);
        tmf.init(ts);

        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "BCJSSE");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        System.out.println("[SERVER] SSLContext ready");
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
            System.out.println("[SERVER] Default named groups: " + Arrays.toString(configured));

            for (String c : candidates) {
                try {
                    params.setNamedGroups(new String[]{c});
                    String[] result = params.getNamedGroups();
                    if (result != null && result.length > 0) {
                        System.out.println("[SERVER] Group '" + c + "' available");
                        return result[0];
                    }
                } catch (Exception e) {
                    // skip
                }
            }
        } catch (Exception e) {
            System.out.println("[SERVER] Probe failed, use default: " + e.getMessage());
        }
        return "X25519MLKEM768";
    }

    static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}