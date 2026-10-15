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

import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** BCJSSE 默认签名方案下，ML-DSA 证书握手是否可行。 */
public class BcMldsaDefaultSig {

    public static void main(String[] args) throws Exception {
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

        SSLServerSocket ss = (SSLServerSocket) sctx.getServerSocketFactory()
                .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        int port = ss.getLocalPort();

        Thread server = new Thread(() -> {
            try (Socket s = ss.accept()) {
                SSLSocket tls = (SSLSocket) s;
                tls.setUseClientMode(false);
                tls.startHandshake();
                System.out.println("[bc-server] session=" + tls.getSession().getProtocol()
                        + " / " + tls.getSession().getCipherSuite());
                OutputStream out = tls.getOutputStream();
                out.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".getBytes());
                out.flush();
            } catch (Exception e) {
                System.out.println("[bc-server] ERR " + e.getMessage());
            }
        });
        server.start();

        SSLSocket c = (SSLSocket) cctx.getSocketFactory().createSocket("localhost", port);
        BCSSLParameters cp = ((BCSSLSocket) c).getParameters();
        cp.setProtocols(new String[]{"TLSv1.3"});
        ((BCSSLSocket) c).setParameters(cp);
        c.startHandshake();
        System.out.println("[bc-client] session=" + c.getSession().getProtocol()
                + " / " + c.getSession().getCipherSuite());
        c.close();
        server.join();
    }
}
