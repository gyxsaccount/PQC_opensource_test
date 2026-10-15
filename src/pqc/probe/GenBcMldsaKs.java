import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** 用 BouncyCastle 生成 ML-DSA-65 自签名证书并存入 PKCS12。 */
public class GenBcMldsaKs {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "BC");
        KeyPair kp = kpg.generateKeyPair();

        X500Name subject = new X500Name("CN=pqc-bc-mldsa-server");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() - 1000L),
                new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                subject,
                kp.getPublic());

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("ML-DSA-65")
                .setProvider(new BouncyCastleProvider());
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(builder.build(signerBuilder.build(kp.getPrivate())));

        System.out.println("BC ML-DSA-65 cert sig alg: " + cert.getSigAlgName());
        System.out.println("BC ML-DSA-65 cert pub alg: " + cert.getPublicKey().getAlgorithm());

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("server", kp.getPrivate(), "changeit".toCharArray(), new X509Certificate[]{cert});
        try (var out = new java.io.FileOutputStream("certs/server-bc-mldsa.p12")) {
            ks.store(out, "changeit".toCharArray());
        }
        System.out.println("written certs/server-bc-mldsa.p12");
    }
}
