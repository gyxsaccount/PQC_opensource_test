import java.security.KeyPairGenerator;
import java.security.Security;
import javax.net.ssl.SSLContext;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class BcPqcProbe {

    public static void main(String[] args) throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);

        System.out.println("=== BouncyCastle PQC 能力探测 ===");
        System.out.println("Providers:");
        for (var p : Security.getProviders()) {
            System.out.println("  " + p.getName() + " : " + p.getVersion());
        }

        System.out.println("\n--- KeyPairGenerator (PQC) ---");
        for (String alg : new String[]{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "SLH-DSA", "SLH-DSA-128S", "SLH-DSA-128F", "SLH-DSA-192S",
                "Falcon", "Falcon-512", "Falcon-1024", "Kyber", "ML-KEM-768"}) {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
                System.out.println("  [OK] " + alg + " (provider=" + kpg.getProvider().getName() + ")");
            } catch (Exception e) {
                System.out.println("  [NO] " + alg + " -> " + e.getClass().getSimpleName());
            }
        }

        System.out.println("\n--- BCJSSE SSLContext 支持的 TLS 群组 ---");
        for (String prov : new String[]{"BCJSSE", "BCTLS"}) {
            try {
                SSLContext sc = SSLContext.getInstance("TLS", prov);
                sc.init(null, null, null);
                System.out.println("[" + prov + "] groups:");
                for (String g : sc.getSupportedSSLParameters().getNamedGroups()) {
                    System.out.println("    " + g);
                }
            } catch (Exception e) {
                System.out.println("[" + prov + "] ERROR: " + e);
            }
        }
    }
}
