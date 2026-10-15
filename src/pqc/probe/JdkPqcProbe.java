import java.security.AlgorithmParameterGenerator;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.SecureRandom;
import java.util.TreeSet;
import javax.net.ssl.SSLContext;

public class JdkPqcProbe {

    public static void main(String[] args) throws Exception {
        System.out.println("=== JDK PQC 能力探测 ===");
        System.out.println("Java: " + System.getProperty("java.version"));
        System.out.println("Vendor: " + System.getProperty("java.vendor"));
        System.out.println("Providers:");
        for (var p : Security.getProviders()) {
            System.out.println("  " + p.getName() + " : " + p.getVersion());
        }

        System.out.println("\n--- KeyPairGenerator (PQC 候选) ---");
        for (String alg : new String[]{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "SLH-DSA", "SLH-DSA-128S", "SLH-DSA-128F", "ML-KEM-512",
                "ML-KEM-768", "ML-KEM-1024", "Falcon", "Ed25519", "X25519",
                "RSA", "EC"}) {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
                System.out.println("  [OK] " + alg + " (provider=" + kpg.getProvider().getName() + ")");
            } catch (Exception e) {
                System.out.println("  [NO] " + alg + " -> " + e.getClass().getSimpleName());
            }
        }

        System.out.println("\n--- SecureRandom ---");
        System.out.println("  default: " + new SecureRandom().getAlgorithm());

        System.out.println("\n--- SSLContext 支持的 TLS 版本与群组 ---");
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, null, null);
        for (String g : sc.getSupportedSSLParameters().getNamedGroups()) {
            System.out.println("  group: " + g);
        }
        System.out.println("  protocols: " + String.join(",", sc.getSupportedSSLParameters().getProtocols()));
    }
}
