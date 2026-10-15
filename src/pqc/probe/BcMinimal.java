import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Security;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class BcMinimal {

    public static void main(String[] args) throws Exception {
        java.security.Security.setProperty("jdk.tls.signatureSchemes",
            "mldsa87,mldsa65,mldsa44,ecdsa_secp256r1_sha256,ecdsa_secp384r1_sha384,"
          + "ecdsa_secp521r1_sha512,ed25519,ed448,rsa_pss_rsae_sha256,rsa_pss_rsae_sha384,"
          + "rsa_pss_rsae_sha512,rsa_pss_pss_sha256,rsa_pss_pss_sha384,rsa_pss_pss_sha512");
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (var in = new java.io.FileInputStream("certs/server-bc-mldsa.p12")) {
            ks.load(in, "changeit".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("X.509", "BCJSSE");
        kmf.init(ks, "changeit".toCharArray());
        SSLContext sctx = SSLContext.getInstance("TLS", "BCJSSE");
        sctx.init(kmf.getKeyManagers(), null, new java.security.SecureRandom());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "BCJSSE");
        tmf.init(ks);
        SSLContext cctx = SSLContext.getInstance("TLS", "BCJSSE");
        cctx.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());

        SSLServerSocket ss = (SSLServerSocket) sctx.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        ss.setEnabledProtocols(new String[]{"TLSv1.3"});
        int port = ss.getLocalPort();
        System.out.println("server enabled protocols: " + java.util.Arrays.toString(ss.getEnabledProtocols()));
        System.out.println("server enabled ciphers: " + java.util.Arrays.toString(ss.getEnabledCipherSuites()));

        Thread server = new Thread(() -> {
            try (Socket s = ss.accept()) {
                SSLSocket tls = (SSLSocket) s;
                tls.setUseClientMode(false);
                tls.startHandshake();
                SSLSession ses = tls.getSession();
                System.out.println("[server] session=" + ses.getProtocol() + " / " + ses.getCipherSuite());
                InputStream in = tls.getInputStream();
                while (in.read() != -1 && in.available() > 0) { /* drain */ }
                OutputStream out = tls.getOutputStream();
                out.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".getBytes());
                out.flush();
            } catch (Exception e) {
                System.out.println("[server] ERR " + e);
            }
        });
        server.start();

        SSLSocket c = (SSLSocket) cctx.getSocketFactory().createSocket("localhost", port);
        c.setEnabledProtocols(new String[]{"TLSv1.3"});
        c.startHandshake();
        SSLSession cses = c.getSession();
        System.out.println("[client] session=" + cses.getProtocol() + " / " + cses.getCipherSuite());
        c.close();
        server.join();
    }
}
