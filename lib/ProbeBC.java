import java.security.*;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import javax.net.ssl.*;

public class ProbeBC {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleJsseProvider());
        SSLContext ctx = SSLContext.getInstance("TLS", "BCJSSE");
        ctx.init(null, null, new SecureRandom());
        System.out.println("=== BC (BCJSSE) supported cipher suites: " + ctx.getSupportedSSLParameters().getCipherSuites().length + " total ===");
        for (String s : ctx.getSupportedSSLParameters().getCipherSuites()) {
            System.out.println("  " + s);
        }
        System.out.println("\n=== PQC-only ===");
        for (String s : ctx.getSupportedSSLParameters().getCipherSuites()) {
            if (s.contains("KYBER") || s.contains("MLKEM") || s.contains("DILITHIUM") || s.contains("SPHINCS") || s.contains("ML_DSA")) {
                System.out.println("  " + s);
            }
        }
    }
}
