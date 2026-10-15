import java.security.*;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import javax.net.ssl.*;
import java.lang.reflect.*;

public class ProbeBC2 {
    public static void main(String[] args) throws Exception {
        // Check what named groups BC supports
        Provider p = new BouncyCastleJsseProvider();
        Security.addProvider(p);
        
        System.out.println("=== BC Provider services ===");
        for (Provider.Service s : p.getServices()) {
            if (s.getType().contains("SSL") || s.getAlgorithm().contains("TLS") || s.getType().contains("KeyManager")) {
                System.out.println("  " + s.getType() + "." + s.getAlgorithm() + " -> " + s.getClassName());
            }
        }
        
        System.out.println("\n=== SSLContext from BCJSSE ===");
        SSLContext ctx = SSLContext.getInstance("TLS", "BCJSSE");
        ctx.init(null, null, new SecureRandom());

        System.out.println("\n=== Looking for named groups ===");
        try {
            Method m = SSLParameters.class.getMethod("getNamedGroups");
            SSLParameters params = ctx.getSupportedSSLParameters();
            String[] groups = (String[]) m.invoke(params);
            System.out.println("  Named groups: " + (groups != null ? String.join(", ", groups) : "null"));
        } catch (Exception e) {
            System.out.println("  getNamedGroups() not available: " + e.getMessage());
        }
        
        // Check enabled cipher suites
        System.out.println("\n=== Enabled cipher suites (first 10) ===");
        String[] enabled = ctx.getDefaultSSLParameters().getCipherSuites();
        for (int i = 0; i < Math.min(10, enabled.length); i++) {
            System.out.println("  " + enabled[i]);
        }
        
        // Also check supported - maybe PQC suites need to be explicitly enabled
        System.out.println("\n=== All supported cipher suites (filtered by KYBER/ML-KEM/ML-DSA/DILITHIUM) ===");
        for (String s : ctx.getSupportedSSLParameters().getCipherSuites()) {
            String upper = s.toUpperCase();
            if (upper.contains("KYBER") || upper.contains("MLKEM") || upper.contains("ML-KEM") || upper.contains("DILITHIUM") || upper.contains("ML-DSA") || upper.contains("SPHINCS") || upper.contains("PQC")) {
                System.out.println("  " + s);
            }
        }
        
        System.out.println("\n=== Checking through Provider service ===");
        // Check if there are any registered SSL/TLS services with PQC
        for (Provider.Service s : p.getServices()) {
            String alg = s.getAlgorithm();
            if (alg.toUpperCase().contains("ML") || alg.toUpperCase().contains("KYBER") || alg.toUpperCase().contains("DILITHIUM") || alg.toUpperCase().contains("SPHINCS")) {
                System.out.println("  " + s.getType() + "." + s.getAlgorithm());
            }
        }
        
        // Try BCFIPS provider approach
        System.out.println("\n=== Trying to create SSLContext with specific protocol ===");
        String[] protocols = {"TLSv1.3", "TLSv1.2"};
        for (String proto : protocols) {
            try {
                SSLContext ctx2 = SSLContext.getInstance(proto, "BCJSSE");
                ctx2.init(null, null, new SecureRandom());
                System.out.println("  " + proto + " OK, suites: " + ctx2.getSupportedSSLParameters().getCipherSuites().length);
            } catch (Exception e) {
                System.out.println("  " + proto + " FAIL: " + e.getMessage());
            }
        }
    }
}
