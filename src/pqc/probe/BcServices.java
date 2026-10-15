import java.security.Provider;
import java.security.Security;
import java.util.Set;
import java.util.TreeSet;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class BcServices {

    public static void main(String[] args) {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
        Provider p = Security.getProvider("BCJSSE");
        System.out.println("=== BCJSSE services ===");
        for (Provider.Service s : p.getServices()) {
            String type = s.getType();
            if (type.contains("Manager") || type.contains("SSLContext") || type.contains("KeyFactory")) {
                System.out.println(type + " : " + s.getAlgorithm());
            }
        }
    }
}
