package pqc.common;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * 迁移点 P1 公共工厂：SSLContext / Provider 构建（JDK 内置 SunJSSE 与 BouncyCastle BCJSSE 双栈）。
 */
public final class PqcSsl {

    public static final String BC_JSSE = BouncyCastleJsseProvider.PROVIDER_NAME;
    public static final String BC_JCE = BouncyCastleProvider.PROVIDER_NAME;
    public static final String SUN_JSSE = "SunJSSE";

    public static void installBouncyCastle() {
        Security.removeProvider(BC_JCE);
        Security.removeProvider(BC_JSSE);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
    }

    public static void enableMlDsaSignatureSchemes() {
        String base = Security.getProperty("jdk.tls.signatureSchemes");
        if (base == null || base.isBlank()) {
            base = "ecdsa_secp256r1_sha256,ecdsa_secp384r1_sha384,ecdsa_secp521r1_sha512,"
                    + "ed25519,ed448,"
                    + "rsa_pss_rsae_sha256,rsa_pss_rsae_sha384,rsa_pss_rsae_sha512,"
                    + "rsa_pss_pss_sha256,rsa_pss_pss_sha384,rsa_pss_pss_sha512";
        }
        Security.setProperty("jdk.tls.signatureSchemes", "mldsa87,mldsa65,mldsa44," + base);
    }

    public static final String[] PQC_SIGNATURE_SCHEMES = {
            "mldsa87", "mldsa65", "mldsa44",
            "ecdsa_secp256r1_sha256", "ed25519", "rsa_pss_rsae_sha256"
    };

    public static final String[] STANDARD_SIGNATURE_SCHEMES = {
            "ecdsa_secp256r1_sha256", "ed25519", "rsa_pss_rsae_sha256"
    };

    public static KeyStore loadKeyStore(String path, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(path)) {
            ks.load(in, password.toCharArray());
        }
        return ks;
    }

    public static SSLContext jdkClientContext(KeyStore trustStore) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", SUN_JSSE);
        tmf.init(trustStore);
        SSLContext ctx = SSLContext.getInstance("TLS", SUN_JSSE);
        ctx.init(null, tmf.getTrustManagers(), new SecureRandom());
        return ctx;
    }

    public static SSLContext jdkServerContext(KeyStore ks, String password) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509", SUN_JSSE);
        kmf.init(ks, password.toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS", SUN_JSSE);
        ctx.init(kmf.getKeyManagers(), null, new SecureRandom());
        return ctx;
    }

    public static SSLContext bcClientContext(KeyStore trustStore) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", BC_JSSE);
        tmf.init(trustStore);
        SSLContext ctx = SSLContext.getInstance("TLS", BC_JSSE);
        ctx.init(null, tmf.getTrustManagers(), new SecureRandom());
        return ctx;
    }

    public static SSLContext bcServerContext(KeyStore ks, String password) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("X.509", BC_JSSE);
        kmf.init(ks, password.toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS", BC_JSSE);
        ctx.init(kmf.getKeyManagers(), null, new SecureRandom());
        return ctx;
    }

    public static String[] hybridGroups() {
        return new String[]{"X25519MLKEM768", "x25519"};
    }

    public static String[] legacyGroups() {
        return new String[]{"x25519"};
    }

    public static String[] pureMlkem768() {
        return new String[]{"MLKEM768"};
    }

    public static void printGroups(String label, SSLContext ctx) {
        String[] groups = ctx.getSupportedSSLParameters().getNamedGroups();
        StringBuilder sb = new StringBuilder("  [" + label + "] supported named groups: ");
        if (groups == null) {
            sb.append("(BCJSSE 不通过 SSLParameters 暴露，群组经 BCSSLParameters 注入)");
        } else {
            for (String g : groups) {
                sb.append(g).append(' ');
            }
        }
        System.out.println(sb);
    }

    private PqcSsl() {
    }
}
