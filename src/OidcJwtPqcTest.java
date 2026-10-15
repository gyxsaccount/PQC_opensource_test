import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 迁移点6: OIDC / JWT 签名算法评估
 *
 * Jetty 12 jetty-openid 依赖 JWT (ID Token), 其签名算法:
 *   当前: RS256/RS384/RS512 (RSA), ES256/ES384/ES512 (EC), HS256/384/512 (HMAC)
 *   迁移目标: JOSE 后量子算法 (draft-ietf-jose-pqc 相关), 或先提升经典强度
 *
 * 验证:
 *   1. 当前 JWT 算法签名/验签可用性
 *   2. 算法强度对比 (RSA-2048 vs 3072/4096, P-256 vs P-384/P-521)
 *   3. PQC JOSE 算法可用性检查 (应为空, 依赖 IETF 标准)
 *
 * 运行: java -cp lib/*;out OidcJwtPqcTest
 */
public class OidcJwtPqcTest {

    public static void main(String[] args) throws Exception {
        System.out.println("=== 迁移点6: OIDC / JWT 签名算法评估 (jetty-openid) ===");
        System.out.println("JDK: " + System.getProperty("java.version"));

        // 1) 当前 JWT 算法签名/验签
        System.out.println("\n[1] 当前 JWT 算法签名/验签链路:");
        String payload = "{\"sub\":\"alice\",\"iss\":\"https://idp.example\",\"exp\":9999999999}";

        // RSA 系列
        for (int bits : new int[]{2048, 3072, 4096}) {
            RSAKey rsaJwk = new RSAKeyGenerator(bits).generate();
            for (String alg : new String[]{"RS256", "RS384", "RS512"}) {
                try {
                    JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.parse(alg)), new Payload(payload));
                    jws.sign(new RSASSASigner(rsaJwk));
                    boolean v = jws.verify(new RSASSAVerifier(rsaJwk.toRSAPublicKey()));
                    System.out.printf("    %s (RSA-%d): sign=%dB verify=%s%n", alg, bits, jws.serialize().length(), v);
                } catch (Exception e) {
                    System.out.printf("    %s (RSA-%d): FAIL %s%n", alg, bits, e.getMessage());
                }
            }
        }

        // EC 系列
        for (Curve curve : new Curve[]{Curve.P_256, Curve.P_384, Curve.P_521}) {
            ECKey ecJwk = new ECKeyGenerator(curve).generate();
            String alg = curve.equals(Curve.P_256) ? "ES256" : curve.equals(Curve.P_384) ? "ES384" : "ES512";
            try {
                JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.parse(alg)), new Payload(payload));
                jws.sign(new ECDSASigner(ecJwk));
                boolean v = jws.verify(new ECDSAVerifier(ecJwk.toECPublicKey()));
                System.out.printf("    %s (%s): sign=%dB verify=%s%n", alg, curve, jws.serialize().length(), v);
            } catch (Exception e) {
                System.out.printf("    %s (%s): FAIL %s%n", alg, curve, e.getMessage());
            }
        }

        // 2) 算法强度对比
        System.out.println("\n[2] 经典算法强度与后量子对比:");
        System.out.println("    RSA-2048  ~ 112-bit 安全强度 (量子 Shor 可破)");
        System.out.println("    RSA-3072  ~ 128-bit");
        System.out.println("    P-256     ~ 128-bit (量子 Grover 减半为 64-bit)");
        System.out.println("    P-384     ~ 192-bit (量子 96-bit)");
        System.out.println("    ML-DSA-65 ~ 128-bit 后量子 (CNSA 2.0 要求)");

        // 3) PQC JOSE 算法可用性
        System.out.println("\n[3] PQC JOSE 算法可用性 (draft-ietf-jose-pqc):");
        String[] pqcAlgs = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA", "Falcon-512"};
        for (String a : pqcAlgs) {
            try {
                JWSAlgorithm.parse(a);
                System.out.println("    " + a + " -> 可用 (意外)");
            } catch (Exception e) {
                System.out.println("    " + a + " -> 不可用: " + e.getMessage().split(":")[0]);
            }
        }
        System.out.println("    => JOSE PQC 算法标准未定 (IETF jose-pqc WG), 当前 OIDC 迁移只能:");
        System.out.println("       a) 提升经典强度 (RSA-3072+/P-384+, HS-384+)");
        System.out.println("       b) 将 ID Token 校验与 TLS 分离, 待 JOSE PQC 标准落地后切换");

        System.out.println("\n=== 迁移点6 结论: JWT 当前无 PQC 标准算法可用, 依赖 IETF jose-pqc; 近期仅可提升经典强度 ===");
    }
}
