package pqc.common;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 迁移点 P3：端到端邮件内容混合加密（crypto-agility hybrid）。
 *  - 混合密钥封装：ML-KEM-768 + RSA-OAEP-2048 共同封装 AES-256-GCM 会话密钥
 *    （安全性 = max(经典, 后量子)，仅破解其一无法解密）
 *  - 混合签名：ML-DSA-65 + Ed25519 双签名，验证需同时通过
 * 基于 JDK 24+ 原生 PQC 原语（JEP 496 ML-KEM / JEP 497 ML-DSA），零第三方依赖。
 */
public final class PqcMailCrypto {

    public static final class KeyMaterial {
        public final PublicKey mlkemPub;
        public final PrivateKey mlkemPriv;
        public final PublicKey rsaPub;
        public final PrivateKey rsaPriv;
        public final PublicKey mldsaPub;
        public final PrivateKey mldsaPriv;
        public final PublicKey edPub;
        public final PrivateKey edPriv;

        public KeyMaterial(PublicKey mlkemPub, PrivateKey mlkemPriv, PublicKey rsaPub, PrivateKey rsaPriv,
                PublicKey mldsaPub, PrivateKey mldsaPriv, PublicKey edPub, PrivateKey edPriv) {
            this.mlkemPub = mlkemPub;
            this.mlkemPriv = mlkemPriv;
            this.rsaPub = rsaPub;
            this.rsaPriv = rsaPriv;
            this.mldsaPub = mldsaPub;
            this.mldsaPriv = mldsaPriv;
            this.edPub = edPub;
            this.edPriv = edPriv;
        }
    }

    public static KeyMaterial generateKeyMaterial() throws Exception {
        KeyPairGenerator mlkemKpg = KeyPairGenerator.getInstance("ML-KEM");
        mlkemKpg.initialize(NamedParameterSpec.ML_KEM_768);
        KeyPair mlkem = mlkemKpg.generateKeyPair();

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        KeyPair rsa = rsaKpg.generateKeyPair();

        KeyPairGenerator mldsaKpg = KeyPairGenerator.getInstance("ML-DSA");
        mldsaKpg.initialize(NamedParameterSpec.ML_DSA_65);
        KeyPair mldsa = mldsaKpg.generateKeyPair();

        KeyPairGenerator edKpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair ed = edKpg.generateKeyPair();

        return new KeyMaterial(mlkem.getPublic(), mlkem.getPrivate(),
                rsa.getPublic(), rsa.getPrivate(),
                mldsa.getPublic(), mldsa.getPrivate(),
                ed.getPublic(), ed.getPrivate());
    }

    /**
     * 混合加密：用接收方 ML-KEM-768 公钥 + RSA-OAEP 公钥共同封装随机 CEK，AES-256-GCM 加密数据。
     * CEK = SHA-256(ML-KEM 共享密钥 || RSA 共享密钥)。
     */
    public static byte[] encrypt(KeyMaterial recipient, byte[] data) throws Exception {
        byte[] randomCek = new byte[32];
        new java.security.SecureRandom().nextBytes(randomCek);

        KEM kem = KEM.getInstance("ML-KEM");
        KEM.Encapsulator enc = kem.newEncapsulator(recipient.mlkemPub);
        KEM.Encapsulated cap = enc.encapsulate();
        byte[] mlkemCt = cap.encapsulation();
        byte[] mlkemSs = cap.key().getEncoded();

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, recipient.rsaPub);
        byte[] rsaCt = rsa.doFinal(randomCek);
        byte[] rsaSs = sha256(randomCek);

        byte[] cek = sha256(concat(mlkemSs, rsaSs));

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"));
        byte[] ct = aes.doFinal(data);
        byte[] iv = aes.getIV();

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        buf.write("PQCENC1".getBytes(StandardCharsets.US_ASCII));
        writeLen(buf, mlkemCt.length);
        buf.writeBytes(mlkemCt);
        writeLen(buf, rsaCt.length);
        buf.writeBytes(rsaCt);
        buf.writeBytes(iv);
        buf.writeBytes(ct);
        return buf.toByteArray();
    }

    /**
     * 混合解密：必须同时解封装 ML-KEM 与 RSA 才能还原 CEK（任一被破解仍有另一层保护）。
     */
    public static byte[] decrypt(KeyMaterial recipient, byte[] envelope) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(envelope);
        byte[] magic = new byte[7];
        buf.get(magic);
        if (!"PQCENC1".equals(new String(magic, StandardCharsets.US_ASCII))) {
            throw new IllegalArgumentException("非 PQC 混合加密格式");
        }
        byte[] mlkemCt = new byte[buf.getShort() & 0xFFFF];
        buf.get(mlkemCt);
        byte[] rsaCt = new byte[buf.getShort() & 0xFFFF];
        buf.get(rsaCt);
        byte[] iv = new byte[12];
        buf.get(iv);
        byte[] ct = new byte[buf.remaining()];
        buf.get(ct);

        KEM kem = KEM.getInstance("ML-KEM");
        KEM.Decapsulator dec = kem.newDecapsulator(recipient.mlkemPriv);
        byte[] mlkemSs = dec.decapsulate(mlkemCt).getEncoded();

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.DECRYPT_MODE, recipient.rsaPriv);
        byte[] randomCek = rsa.doFinal(rsaCt);
        byte[] rsaSs = sha256(randomCek);

        byte[] cek = sha256(concat(mlkemSs, rsaSs));

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
        return aes.doFinal(ct);
    }

    /**
     * 混合签名：ML-DSA-65 与 Ed25519 同时对消息签名，两份签名都验证通过才算有效。
     */
    public static byte[] sign(KeyMaterial signer, byte[] data) throws Exception {
        Signature mldsa = Signature.getInstance("ML-DSA");
        mldsa.initSign(signer.mldsaPriv);
        mldsa.update(data);
        byte[] mldsaSig = mldsa.sign();

        Signature ed = Signature.getInstance("Ed25519");
        ed.initSign(signer.edPriv);
        ed.update(data);
        byte[] edSig = ed.sign();

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        buf.write("PQCSIGN1".getBytes(StandardCharsets.US_ASCII));
        writeKey(buf, signer.mldsaPub.getEncoded());
        writeKey(buf, signer.edPub.getEncoded());
        writeKey(buf, mldsaSig);
        writeKey(buf, edSig);
        return buf.toByteArray();
    }

    public static boolean verify(byte[] signed, byte[] data) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(signed);
        byte[] magic = new byte[8];
        buf.get(magic);
        if (!"PQCSIGN1".equals(new String(magic, StandardCharsets.US_ASCII))) {
            throw new IllegalArgumentException("非 PQC 混合签名格式");
        }
        byte[] mldsaPub = readKey(buf);
        byte[] edPub = readKey(buf);
        byte[] mldsaSig = readKey(buf);
        byte[] edSig = readKey(buf);

        KeyFactory kf = KeyFactory.getInstance("ML-DSA");
        Signature mldsa = Signature.getInstance("ML-DSA");
        mldsa.initVerify(kf.generatePublic(new X509EncodedKeySpec(mldsaPub)));
        mldsa.update(data);
        boolean okMldsa = mldsa.verify(mldsaSig);

        KeyFactory edkf = KeyFactory.getInstance("Ed25519");
        Signature ed = Signature.getInstance("Ed25519");
        ed.initVerify(edkf.generatePublic(new X509EncodedKeySpec(edPub)));
        ed.update(data);
        boolean okEd = ed.verify(edSig);

        return okMldsa && okEd;
    }

    private static void writeKey(ByteArrayOutputStream buf, byte[] key) {
        writeLen(buf, key.length);
        buf.writeBytes(key);
    }

    private static byte[] readKey(ByteBuffer buf) {
        byte[] key = new byte[buf.getShort() & 0xFFFF];
        buf.get(key);
        return key;
    }

    private static void writeLen(ByteArrayOutputStream buf, int len) {
        buf.write((len >>> 8) & 0xFF);
        buf.write(len & 0xFF);
    }

    private static byte[] sha256(byte[] in) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(in);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private PqcMailCrypto() {
    }
}
