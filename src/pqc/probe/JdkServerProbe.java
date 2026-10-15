import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class JdkServerProbe {

    public static void main(String[] args) throws Exception {
        // Security.insertProviderAt(new BouncyCastleProvider(), 1);
        // Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (var in = new java.io.FileInputStream("certs/server-ecdsa.p12")) {
            ks.load(in, "changeit".toCharArray());
        }
        System.out.println("aliases: " + Collections(ks.aliases()));

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
        kmf.init(ks, "changeit".toCharArray());
        for (var km : kmf.getKeyManagers()) {
            if (km instanceof X509KeyManager xkm) {
                for (var en = ks.aliases(); en.hasMoreElements(); ) {
                    String alias = en.nextElement();
                    System.out.println("chooseServerAlias(ec) " + alias + " chainLen="
                            + (xkm.getCertificateChain(alias) == null ? "null" : xkm.getCertificateChain(alias).length));
                }
                System.out.println("chooseServerAlias(ec,null,null) = "
                        + xkm.chooseServerAlias("ec", null, null));
                System.out.println("chooseServerAlias(EC,null,null) = "
                        + xkm.chooseServerAlias("EC", null, null));
                System.out.println("chooseServerAlias(rsa,null,null) = "
                        + xkm.chooseServerAlias("rsa", null, null));
            }
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
        tmf.init(ks);

        SSLContext sctx = SSLContext.getInstance("TLS", "SunJSSE");
        sctx.init(kmf.getKeyManagers(), null, new java.security.SecureRandom());

        SSLServerSocket ss = (SSLServerSocket) sctx.getServerSocketFactory()
                .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        ss.setEnabledProtocols(new String[]{"TLSv1.3"});
        int port = ss.getLocalPort();

        Thread server = new Thread(() -> {
            try (Socket s = ss.accept()) {
                SSLSocket tls = (SSLSocket) s;
                tls.setUseClientMode(false);
                tls.startHandshake();
                System.out.println("[jdk-server] OK session=" + tls.getSession().getProtocol()
                        + " / " + tls.getSession().getCipherSuite());
            } catch (Exception e) {
                System.out.println("[jdk-server] ERR " + e.getMessage());
            }
        });
        server.start();

        SSLContext cctx = SSLContext.getInstance("TLS", "BCJSSE");
        cctx.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());
        SSLSocket c = (SSLSocket) cctx.getSocketFactory().createSocket("localhost", port);
        BCSSLParameters cp = ((BCSSLSocket) c).getParameters();
        cp.setProtocols(new String[]{"TLSv1.3"});
        cp.setNamedGroups(new String[]{"X25519MLKEM768", "x25519"});
        ((BCSSLSocket) c).setParameters(cp);
        c.startHandshake();
        System.out.println("[bc-client-defaultsig] OK session=" + c.getSession().getProtocol()
                + " / " + c.getSession().getCipherSuite());
        c.close();
        server.join();
    }

    static String Collections(java.util.Enumeration<String> e) {
        java.util.List<String> l = new java.util.ArrayList<>();
        while (e.hasMoreElements()) l.add(e.nextElement());
        return String.join(",", l);
    }
}
