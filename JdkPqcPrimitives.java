import java.security.*;
import java.security.spec.NamedParameterSpec;
import java.util.*;
import javax.crypto.*;

/**
 * JDK 24+ 原生 PQC 原语 demo (JEP 496 ML-KEM, JEP 497 ML-DSA)
 *
 * 注意: 原语 API 与 TLS 集成是分开的。此 demo 演示:
 *   1. ML-KEM (FIPS 203): KeyPairGenerator + KEM 封装/解封装
 *   2. ML-DSA (FIPS 204): KeyPairGenerator + Signature 签名/验签
 *   3. TLS 1.3 中的 X25519MLKEM768 混合组(在 JdkPqcTlsServer/Client 中演示)
 *
 * 运行于 JDK 24+。
 */
public class JdkPqcPrimitives {

    public static void main(String[] args) throws Exception {
        System.out.println("=== JDK 原生 PQC 原语 (JEP 496 / JEP 497) ===");
        System.out.println("Java: " + System.getProperty("java.version"));

        mlKemDemo();
        System.out.println();
        mlDsaDemo();
    }

    static void mlKemDemo() throws Exception {
        System.out.println("\n---- ML-KEM (FIPS 203) Key Encapsulation ----");
        Map<String, NamedParameterSpec> mlkem = new LinkedHashMap<>();
        mlkem.put("ML-KEM-512", NamedParameterSpec.ML_KEM_512);
        mlkem.put("ML-KEM-768", NamedParameterSpec.ML_KEM_768);
        mlkem.put("ML-KEM-1024", NamedParameterSpec.ML_KEM_1024);
        for (Map.Entry<String, NamedParameterSpec> e : mlkem.entrySet()) {
            String paramSet = e.getKey();
            long t0 = System.nanoTime();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM");
            kpg.initialize(e.getValue());
            KeyPair kp = kpg.generateKeyPair();
            long t1 = System.nanoTime();

            // 发送方(Client): 用接收方公钥封装
            KEM kemSender = KEM.getInstance("ML-KEM");
            KEM.Encapsulator enc = kemSender.newEncapsulator(kp.getPublic());
            KEM.Encapsulated encap = enc.encapsulate();
            byte[] ct = encap.encapsulation();      // 密文 (encapsulation)
            SecretKey sharedSecretSender = encap.key();
            long t2 = System.nanoTime();

            // 接收方(Server): 用私钥解封装
            KEM kemReceiver = KEM.getInstance("ML-KEM");
            KEM.Decapsulator dec = kemReceiver.newDecapsulator(kp.getPrivate());
            SecretKey sharedSecretReceiver = dec.decapsulate(ct);
            long t3 = System.nanoTime();

            boolean match = Arrays.equals(sharedSecretSender.getEncoded(), sharedSecretReceiver.getEncoded());

            System.out.printf("  %-12s | pub=%-4d priv=%-4d ct=%-4d | keygen=%-6.2fms encaps=%-6.2fms decaps=%-6.2fms | shared-secret match=%s%n",
                paramSet,
                kp.getPublic().getEncoded().length, kp.getPrivate().getEncoded().length, ct.length,
                (t1 - t0) / 1e6, (t2 - t1) / 1e6, (t3 - t2) / 1e6,
                match);
        }
    }

    static void mlDsaDemo() throws Exception {
        System.out.println("\n---- ML-DSA (FIPS 204) Digital Signature ----");
        byte[] message = "JDK native PQC ML-DSA message".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Map<String, NamedParameterSpec> mldsa = new LinkedHashMap<>();
        mldsa.put("ML-DSA-44", NamedParameterSpec.ML_DSA_44);
        mldsa.put("ML-DSA-65", NamedParameterSpec.ML_DSA_65);
        mldsa.put("ML-DSA-87", NamedParameterSpec.ML_DSA_87);
        for (Map.Entry<String, NamedParameterSpec> e : mldsa.entrySet()) {
            String paramSet = e.getKey();
            long t0 = System.nanoTime();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA");
            kpg.initialize(e.getValue());
            KeyPair kp = kpg.generateKeyPair();
            long t1 = System.nanoTime();

            Signature signer = Signature.getInstance("ML-DSA");
            signer.initSign(kp.getPrivate());
            signer.update(message);
            byte[] sig = signer.sign();
            long t2 = System.nanoTime();

            Signature verifier = Signature.getInstance("ML-DSA");
            verifier.initVerify(kp.getPublic());
            verifier.update(message);
            boolean valid = verifier.verify(sig);
            long t3 = System.nanoTime();

            System.out.printf("  %-12s | pub=%-4d priv=%-4d sig=%-4d | keygen=%-6.2fms sign=%-6.2fms verify=%-6.2fms | valid=%s%n",
                paramSet,
                kp.getPublic().getEncoded().length, kp.getPrivate().getEncoded().length, sig.length,
                (t1 - t0) / 1e6, (t2 - t1) / 1e6, (t3 - t2) / 1e6,
                valid);
        }
    }
}