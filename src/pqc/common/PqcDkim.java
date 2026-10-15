package pqc.common;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;

/**
 * 迁移点 P5：混合 DKIM 签名原型。
 * 经典 DKIM(a=ed25519-sha256) 与 PQC DKIM(a=mldsa65) 双签名并存，
 * 收件端需同时通过两个签名验证，防量子伪造。
 */
public final class PqcDkim {

    public static String[] sign(String from, String subject, byte[] body, PqcMailCrypto.KeyMaterial signer)
            throws Exception {
        byte[] bh = bodyHash(body);
        String classic = signOne(from, subject, bh, "ed25519-sha256", "Ed25519",
                signer.edPub.getEncoded(), signer.edPriv);
        String pqc = signOne(from, subject, bh, "mldsa65", "ML-DSA",
                signer.mldsaPub.getEncoded(), signer.mldsaPriv);
        return new String[]{classic, pqc};
    }

    private static String signOne(String from, String subject, byte[] bh, String algName, String jcaAlg,
            byte[] pub, java.security.PrivateKey priv) throws Exception {
        byte[] input = signInput(from, subject, bh);
        Signature sig = Signature.getInstance(jcaAlg);
        sig.initSign(priv);
        sig.update(input);
        return "v=1; a=" + algName + "; c=relaxed/relaxed; d=pqc.local; s=pqc;"
                + " bh=" + b64(bh) + "; h=from:subject; pk=" + b64(pub) + "; b=" + b64(sig.sign());
    }

    public static boolean verify(String from, String subject, byte[] body, String dkimHeader, String jcaAlg)
            throws Exception {
        String[] kv = splitHeader(dkimHeader);
        String bhB64 = kv[1];
        String pkB64 = kv[2];
        String sigB64 = kv[3];
        byte[] bh = bodyHash(body);
        if (!MessageDigest.isEqual(bh, Base64.getDecoder().decode(bhB64))) {
            return false;
        }
        byte[] input = signInput(from, subject, bh);
        Signature sig = Signature.getInstance(jcaAlg);
        sig.initVerify(java.security.KeyFactory.getInstance(jcaAlg.equals("ML-DSA") ? "ML-DSA" : "Ed25519")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(
                        Base64.getDecoder().decode(pkB64))));
        sig.update(input);
        return sig.verify(Base64.getDecoder().decode(sigB64));
    }

    private static byte[] signInput(String from, String subject, byte[] bh) {
        return (from + "\n" + subject + "\n" + b64(bh)).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] bodyHash(byte[] body) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(body);
    }

    private static String[] splitHeader(String header) {
        String[] tokens = header.split(";");
        String bh = null;
        String pk = null;
        String b = null;
        for (String t : tokens) {
            String s = t.trim();
            if (s.startsWith("bh=")) {
                bh = s.substring(3);
            } else if (s.startsWith("pk=")) {
                pk = s.substring(3);
            } else if (s.startsWith("b=")) {
                b = s.substring(2);
            }
        }
        return new String[]{header, bh, pk, b};
    }

    private static String b64(byte[] in) {
        return Base64.getEncoder().encodeToString(in);
    }

    private PqcDkim() {
    }
}
