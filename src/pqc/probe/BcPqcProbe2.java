import java.security.SecureRandom;
import java.security.Security;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class BcPqcProbe2 {

    public static void main(String[] args) throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);

        System.out.println("=== BouncyCastle BCJSSE TLS 群组探测(v2) ===");

        String[] algos = new String[]{"TLS", "BCTLS", "BCJSSE"};
        for (String alg : algos) {
            try {
                SSLContext sc = SSLContext.getInstance(alg, "BCJSSE");
                TrustManager[] dummy = new TrustManager[]{ new DummyTrustManager() };
                sc.init(null, dummy, new SecureRandom());
                System.out.println("[" + alg + "] OK, supported groups:");
                for (String g : sc.getSupportedSSLParameters().getNamedGroups()) {
                    System.out.println("    " + g);
                }
                System.out.println("    ciphers(TLS13):");
                for (String c : sc.getSupportedSSLParameters().getCipherSuites()) {
                    if (c.contains("_AES_")) System.out.println("    " + c);
                }
            } catch (Exception e) {
                System.out.println("[" + alg + "] ERROR: " + e);
            }
        }
    }

    static class DummyTrustManager implements TrustManager {
    }
}
