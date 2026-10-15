package pqc.approachC;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import jakarta.mail.Authenticator;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import pqc.common.MailPqcConfig;
import pqc.common.PqcDkim;
import pqc.common.PqcMailCrypto;
import pqc.common.PqcMailServer;
import pqc.common.PqcSocketFactory;
import pqc.common.PqcSsl;
import pqc.common.PqcVault;

/**
 * 方案C：混合式（JDK + BC 双栈）全迁移点验证。
 * P1 TLS 传输 / P2 PQC-SIGN SASL 认证 / P3 混合端到端加密 / P4 本地凭证 Vault / P5 混合 DKIM。
 */
public final class MainC {

    private static final String ECDSA_KS = "certs/server-ecdsa.p12";
    private static final String LEGACY_KS = "certs/server-legacy.p12";
    private static final String KS_PASS = "changeit";

    public static void main(String[] args) throws Exception {
        PqcSsl.enableMlDsaSignatureSchemes();
        PqcSsl.installBouncyCastle();

        System.out.println("================================================================");
        System.out.println(" 方案C 迁移测试：混合式双栈 + 全迁移点（P1-P5）");
        System.out.println("================================================================");

        KeyStore ecdsaKs = PqcSsl.loadKeyStore(ECDSA_KS, KS_PASS);
        KeyStore legacyKs = PqcSsl.loadKeyStore(LEGACY_KS, KS_PASS);

        Map<String, byte[]> authUsers = new LinkedHashMap<>();
        KeyPairGenerator mldsaKpg = KeyPairGenerator.getInstance("ML-DSA");
        mldsaKpg.initialize(NamedParameterSpec.ML_DSA_65);
        KeyPair mldsaClient = mldsaKpg.generateKeyPair();
        authUsers.put("alice", mldsaClient.getPublic().getEncoded());

        PqcMailServer bcEcdsa = new PqcMailServer(
                PqcSsl.bcServerContext(ecdsaKs, KS_PASS), PqcSsl.hybridGroups(), 2743, "smtp", null);
        PqcMailServer jdkEcdsa = new PqcMailServer(
                PqcSsl.jdkServerContext(ecdsaKs, KS_PASS), PqcSsl.hybridGroups(), 2744, "smtp", null);
        PqcMailServer legacy = new PqcMailServer(
                PqcSsl.jdkServerContext(legacyKs, KS_PASS), PqcSsl.legacyGroups(), 2745, "smtp", null);
        PqcMailServer smtpAuth = new PqcMailServer(
                PqcSsl.jdkServerContext(ecdsaKs, KS_PASS), PqcSsl.hybridGroups(), 2746, "smtp", authUsers);
        bcEcdsa.start();
        jdkEcdsa.start();
        legacy.start();
        smtpAuth.start();

        p1(bcEcdsa, jdkEcdsa, legacy, ecdsaKs, legacyKs);
        p2(smtpAuth, mldsaClient, ecdsaKs);
        p3();
        p4();
        p5();

        bcEcdsa.close();
        jdkEcdsa.close();
        legacy.close();
        smtpAuth.close();
        System.out.println("\n方案C 测试结束。");
    }

    private static void p1(PqcMailServer bcEcdsa, PqcMailServer jdkEcdsa, PqcMailServer legacy,
            KeyStore ecdsaKs, KeyStore legacyKs) throws Exception {
        System.out.println("\n================ 迁移点 P1：TLS 传输（混合双栈） ================");

        System.out.println("\n--- 场景1 互操作：JDK客户端 ↔ BC服务器（混合 X25519MLKEM768）---");
        PqcSocketFactory.configure(PqcSsl.jdkClientContext(ecdsaKs), PqcSsl.hybridGroups());
        Session s1 = Session.getInstance(MailPqcConfig.smtp("localhost", 2743));
        Transport.send(buildMessage(s1, "方案C 场景1", "JDK client -> BC server"));
        report("SMTP 互操作", "alice@pqc.local -> bob@pqc.local");

        System.out.println("\n--- 场景2 互操作：BC客户端 ↔ JDK服务器（混合 X25519MLKEM768）---");
        PqcSocketFactory.configure(PqcSsl.bcClientContext(ecdsaKs), PqcSsl.hybridGroups());
        Session s2 = Session.getInstance(MailPqcConfig.smtp("localhost", 2744));
        Transport.send(buildMessage(s2, "方案C 场景2", "BC client -> JDK server"));
        report("SMTP 互操作", "alice@pqc.local -> bob@pqc.local");

        System.out.println("\n--- 场景3 回退：PQC 优先 → 传统服务器(仅 x25519) ---");
        PqcSocketFactory.configure(PqcSsl.jdkClientContext(legacyKs), PqcSsl.hybridGroups());
        Session s3 = Session.getInstance(MailPqcConfig.smtp("localhost", 2745));
        Transport.send(buildMessage(s3, "方案C 场景3", "fallback to x25519"));
        report("SMTP 回退", "alice@pqc.local -> bob@pqc.local");

        System.out.println("  [服务端] bcEcdsa=" + bcEcdsa.getLastNegotiated() + "/" + bcEcdsa.getLastCipher()
                + " 证书=" + bcEcdsa.getLastCertSigAlg()
                + " | jdkEcdsa=" + jdkEcdsa.getLastNegotiated() + "/" + jdkEcdsa.getLastCipher()
                + " 证书=" + jdkEcdsa.getLastCertSigAlg()
                + " | legacy=" + legacy.getLastNegotiated() + "/" + legacy.getLastCipher());
    }

    private static void p2(PqcMailServer smtpAuth, KeyPair mldsaClient, KeyStore ecdsaKs) throws Exception {
        System.out.println("\n================ 迁移点 P2：PQC-SIGN SASL 认证（ML-DSA 挑战-响应） ================");
        byte[] privB64 = Base64.getEncoder().encode(mldsaClient.getPrivate().getEncoded());
        Security.setProperty("pqc.sasl.mldsa.privateKey", new String(privB64, StandardCharsets.US_ASCII));
        Security.addProvider(new pqc.sasl.PqcSaslProvider());
        System.out.println("  注册 PqcSaslProvider: SaslClientFactory.PQC-SIGN");

        PqcSocketFactory.configure(PqcSsl.jdkClientContext(ecdsaKs), PqcSsl.hybridGroups());
        Properties props = MailPqcConfig.smtp("localhost", 2746);
        MailPqcConfig.smtpAuth(props, "PQC-SIGN", new String(privB64, StandardCharsets.US_ASCII));
        Session s = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication("alice", "x");
            }
        });
        Transport.send(buildMessage(s, "方案C P2 认证", "ML-DSA challenge-response auth over PQC TLS"));
        report("SMTP 发送（PQC-SIGN 认证）", "alice@pqc.local -> bob@pqc.local");

        PqcSocketFactory.configure(PqcSsl.jdkClientContext(ecdsaKs), PqcSsl.hybridGroups());
        Properties bad = MailPqcConfig.smtp("localhost", 2746);
        MailPqcConfig.smtpAuth(bad, "PQC-SIGN",
                Base64.getEncoder().encodeToString(KeyPairGenerator.getInstance("ML-DSA")
                        .generateKeyPair().getPrivate().getEncoded()));
        Session sBad = Session.getInstance(bad, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication("eve", "x");
            }
        });
        try {
            Transport.send(buildMessage(sBad, "方案C P2 反例", "wrong key"));
            System.out.println("  [FAIL] 错误私钥/用户未被拒绝");
        } catch (Exception e) {
            System.out.println("  [预期失败] 错误 ML-DSA 私钥被服务器拒绝 -> 535 Authentication credentials invalid");
        }
    }

    private static void p3() throws Exception {
        System.out.println("\n================ 迁移点 P3：S/MIME 式混合端到端加密 ================");
        PqcMailCrypto.KeyMaterial km = PqcMailCrypto.generateKeyMaterial();
        byte[] body = "To Bob: PQC migration plan v2.0 [机密内容：切换到 ML-KEM/ML-DSA].  -----END----"
                .getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = PqcMailCrypto.encrypt(km, body);
        byte[] decrypted = PqcMailCrypto.decrypt(km, encrypted);
        System.out.println("  混合加密(ML-KEM-768 + RSA-OAEP-2048 -> AES-256-GCM):");
        System.out.println("    明文=" + body.length + "B | 密文=" + encrypted.length
                + "B | 解密还原=" + Arrays.equals(body, decrypted));

        byte[] signed = PqcMailCrypto.sign(km, body);
        boolean verified = PqcMailCrypto.verify(signed, body);
        System.out.println("  混合签名(ML-DSA-65 + Ed25519): 签名=" + signed.length + "B | 验签=" + verified);

        Session sp = Session.getInstance(new Properties());
        MimeMessage carried = new MimeMessage(sp);
        carried.setFrom(new InternetAddress("alice@pqc.local"));
        carried.setRecipient(MimeMessage.RecipientType.TO, new InternetAddress("bob@pqc.local"));
        carried.setSubject("PQC 加密邮件载体");
        carried.setDataHandler(new jakarta.activation.DataHandler(
                new jakarta.mail.util.ByteArrayDataSource(encrypted, "application/octet-stream")));
        carried.saveChanges();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        carried.writeTo(bos);
        MimeMessage received = new MimeMessage(sp, new ByteArrayInputStream(bos.toByteArray()));
        byte[] carriedEnc = received.getInputStream().readAllBytes();
        byte[] reopened = PqcMailCrypto.decrypt(km, carriedEnc);
        System.out.println("  Angus Mail MimeMessage 承载密文往返: 解密还原="
                + Arrays.equals(body, reopened) + " | 主题=" + received.getSubject());
    }

    private static void p4() throws Exception {
        System.out.println("\n================ 迁移点 P4：本地凭证量子抗性 Vault ================");
        PqcVault vault = PqcVault.create();
        byte[] secret = "smtp-password-@XyZ2026!".getBytes(StandardCharsets.UTF_8);
        byte[] blob = vault.seal(secret);
        byte[] opened = vault.open(blob);
        System.out.println("  Vault(ML-KEM-768 封装 DEK + AES-256-GCM): 明文=" + secret.length
                + "B | blob=" + blob.length + "B | 恢复="
                + new String(opened, StandardCharsets.UTF_8)
                + " | 匹配=" + Arrays.equals(secret, opened));
    }

    private static void p5() throws Exception {
        System.out.println("\n================ 迁移点 P5：混合 DKIM 签名 ================");
        PqcMailCrypto.KeyMaterial km = PqcMailCrypto.generateKeyMaterial();
        byte[] body = "This is the canonicalized DKIM body for PQC signing demo."
                .getBytes(StandardCharsets.UTF_8);
        String[] dkim = PqcDkim.sign("alice@pqc.local", "PQC DKIM 迁移", body, km);
        boolean classic = PqcDkim.verify("alice@pqc.local", "PQC DKIM 迁移", body, dkim[0], "Ed25519");
        boolean pqc = PqcDkim.verify("alice@pqc.local", "PQC DKIM 迁移", body, dkim[1], "ML-DSA");
        System.out.println("  经典 DKIM a=ed25519-sha256 验证=" + classic);
        System.out.println("  PQC DKIM  a=mldsa65        验证=" + pqc);
        System.out.println("  头部样例: " + dkim[1].substring(0, Math.min(96, dkim[1].length())) + " ...");
    }

    private static MimeMessage buildMessage(Session session, String subject, String body) throws Exception {
        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress("alice@pqc.local"));
        msg.setRecipient(MimeMessage.RecipientType.TO, new InternetAddress("bob@pqc.local"));
        msg.setSubject(subject);
        msg.setText(body);
        return msg;
    }

    private static void report(String label, String detail) {
        var session = PqcSocketFactory.getLastSession();
        if (session == null) {
            System.out.println("  [client] " + label + " 完成（无握手记录）");
            return;
        }
        System.out.println("  [client] " + label + " 完成 | " + detail);
        System.out.println("          协议=" + session.getProtocol()
                + " | 密码套件=" + session.getCipherSuite());
    }
}
