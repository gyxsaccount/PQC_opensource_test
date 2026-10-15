import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class BcServerCipherProbe {

    public static void main(String[] args) throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (var in = new java.io.FileInputStream("certs/server-jdk.p12")) {
            ks.load(in, "changeit".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("X.509", "BCJSSE");
        kmf.init(ks, "changeit".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS", "BCJSSE");
        ctx.init(kmf.getKeyManagers(), null, new java.security.SecureRandom());

        SSLServerSocket ss = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0);
        System.out.println("supported: " + Arrays.toString(ss.getSupportedCipherSuites()));
        System.out.println("enabled (before): " + Arrays.toString(ss.getEnabledCipherSuites()));
        SSLParameters p = ss.getSSLParameters();
        System.out.println("params ciphers: " + Arrays.toString(p.getCipherSuites()));
        p.setProtocols(new String[]{"TLSv1.3"});
        p.setNamedGroups(new String[]{"X25519MLKEM768", "x25519"});
        p.setCipherSuites(ss.getEnabledCipherSuites());
        ss.setSSLParameters(p);
        System.out.println("enabled (after): " + Arrays.toString(ss.getEnabledCipherSuites()));
    }
}
