package pqc.common;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.NamedParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 迁移点 P4：本地敏感数据（邮箱口令/OAuth2 令牌）量子抗性存储。
 * 每个 Vault 持有 ML-KEM-768 密钥对；seal() 用自身公钥封装随机 DEK，
 * 以 AES-256-GCM 加密明文，产出可持久化的 blob；open() 用私钥解封装还原。
 */
public final class PqcVault {

    private final byte[] pub;
    private final byte[] priv;

    private PqcVault(byte[] pub, byte[] priv) {
        this.pub = pub;
        this.priv = priv;
    }

    public static PqcVault create() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM");
        kpg.initialize(NamedParameterSpec.ML_KEM_768);
        KeyPair kp = kpg.generateKeyPair();
        return new PqcVault(kp.getPublic().getEncoded(), kp.getPrivate().getEncoded());
    }

    public byte[] seal(byte[] plaintext) throws Exception {
        KeyPair kp = new KeyPair(
                KeyFactoryHolder.x509("ML-KEM", pub),
                KeyFactoryHolder.pkcs8("ML-KEM", priv));
        KEM kem = KEM.getInstance("ML-KEM");
        KEM.Encapsulator enc = kem.newEncapsulator(kp.getPublic());
        KEM.Encapsulated cap = enc.encapsulate();
        byte[] kemCt = cap.encapsulation();
        byte[] dek = sha256(cap.key().getEncoded());

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"));
        byte[] ct = aes.doFinal(plaintext);
        byte[] iv = aes.getIV();

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        buf.write("PQCVAULT1".getBytes(StandardCharsets.US_ASCII));
        writeLen(buf, kemCt.length);
        buf.writeBytes(kemCt);
        buf.writeBytes(iv);
        buf.writeBytes(ct);
        return buf.toByteArray();
    }

    public byte[] open(byte[] blob) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(blob);
        byte[] magic = new byte[9];
        buf.get(magic);
        if (!"PQCVAULT1".equals(new String(magic, StandardCharsets.US_ASCII))) {
            throw new IllegalArgumentException("非 PQC Vault 格式");
        }
        byte[] kemCt = new byte[buf.getShort() & 0xFFFF];
        buf.get(kemCt);
        byte[] iv = new byte[12];
        buf.get(iv);
        byte[] ct = new byte[buf.remaining()];
        buf.get(ct);

        KeyPair kp = new KeyPair(
                KeyFactoryHolder.x509("ML-KEM", pub),
                KeyFactoryHolder.pkcs8("ML-KEM", priv));
        KEM kem = KEM.getInstance("ML-KEM");
        KEM.Decapsulator dec = kem.newDecapsulator(kp.getPrivate());
        byte[] dek = sha256(dec.decapsulate(kemCt).getEncoded());

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(128, iv));
        return aes.doFinal(ct);
    }

    private static byte[] sha256(byte[] in) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(in);
    }

    private static void writeLen(ByteArrayOutputStream buf, int len) {
        buf.write((len >>> 8) & 0xFF);
        buf.write(len & 0xFF);
    }

    private static final class KeyFactoryHolder {
        static java.security.PublicKey x509(String alg, byte[] enc) throws Exception {
            return java.security.KeyFactory.getInstance(alg)
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(enc));
        }

        static java.security.PrivateKey pkcs8(String alg, byte[] enc) throws Exception {
            return java.security.KeyFactory.getInstance(alg)
                    .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(enc));
        }
    }
}
