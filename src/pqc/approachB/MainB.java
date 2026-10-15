package pqc.approachB;

import java.security.KeyStore;

import jakarta.mail.Folder;
import jakarta.mail.Session;
import jakarta.mail.Store;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import pqc.common.MailPqcConfig;
import pqc.common.PqcMailServer;
import pqc.common.PqcSocketFactory;
import pqc.common.PqcSsl;

/**
 * 方案B：BouncyCastle BCJSSE 迁移测试。
 * 相比 JDK 额外支持纯 ML-KEM 群组与 ML-DSA PQC 证书签名（需显式注入签名方案）。
 */
public final class MainB {

    private static final String BC_MLDSA_KS = "certs/server-bc-mldsa.p12";
    private static final String ECDSA_KS = "certs/server-ecdsa.p12";
    private static final String KS_PASS = "changeit";

    public static void main(String[] args) throws Exception {
        PqcSsl.enableMlDsaSignatureSchemes();
        PqcSsl.installBouncyCastle();

        System.out.println("================================================================");
        System.out.println(" 方案B 迁移测试：BouncyCastle BCJSSE（ML-DSA 证书 + 混合密钥交换）");
        System.out.println("================================================================");

        KeyStore bcKs = PqcSsl.loadKeyStore(BC_MLDSA_KS, KS_PASS);
        KeyStore ecdsaKs = PqcSsl.loadKeyStore(ECDSA_KS, KS_PASS);

        PqcMailServer smtpMldsa = new PqcMailServer(
                PqcSsl.bcServerContext(bcKs, KS_PASS), PqcSsl.hybridGroups(), 2643, "smtp", null);
        PqcMailServer imapMldsa = new PqcMailServer(
                PqcSsl.bcServerContext(bcKs, KS_PASS), PqcSsl.hybridGroups(), 2644, "imap", null);
        PqcMailServer pop3Mldsa = new PqcMailServer(
                PqcSsl.bcServerContext(bcKs, KS_PASS), PqcSsl.hybridGroups(), 2645, "pop3", null);
        PqcMailServer bcEcdsa = new PqcMailServer(
                PqcSsl.bcServerContext(ecdsaKs, KS_PASS), PqcSsl.hybridGroups(), 2646, "smtp", null);
        PqcMailServer jdkEcdsa = new PqcMailServer(
                PqcSsl.jdkServerContext(ecdsaKs, KS_PASS), PqcSsl.hybridGroups(), 2647, "smtp", null);
        smtpMldsa.start();
        imapMldsa.start();
        pop3Mldsa.start();
        bcEcdsa.start();
        jdkEcdsa.start();

        System.out.println("\n--- 场景1 正向：BC客户端 ↔ BC服务器（ML-DSA证书 + 混合X25519MLKEM768）---");
        PqcSocketFactory.configure(PqcSsl.bcClientContext(bcKs), PqcSsl.hybridGroups(),
                new String[]{"TLSv1.3"}, PqcSsl.PQC_SIGNATURE_SCHEMES);
        Session s1 = Session.getInstance(MailPqcConfig.smtp("localhost", 2643));
        Transport.send(buildMessage(s1, "PQC 方案B", "Hello via BCJSSE ML-DSA certificate."));
        report("SMTP 发送", "ML-DSA证书", "alice@pqc.local -> bob@pqc.local");

        System.out.println("\n--- 场景2 正向：BC客户端 ↔ BC IMAP服务器（ML-DSA证书）---");
        PqcSocketFactory.configure(PqcSsl.bcClientContext(bcKs), PqcSsl.hybridGroups(),
                new String[]{"TLSv1.3"}, PqcSsl.PQC_SIGNATURE_SCHEMES);
        Session s2 = Session.getInstance(MailPqcConfig.imap("localhost", 2644));
        try (Store store = s2.getStore("imap")) {
            store.connect("localhost", 2644, "alice", "secret");
            Folder inbox = store.getDefaultFolder();
            System.out.println("  [client] IMAP default folder = " + inbox.getName());
            report("IMAP 连接", "ML-DSA证书", "alice@pqc.local");
        }

        System.out.println("\n--- 场景3 正向：BC客户端 ↔ BC POP3服务器（ML-DSA证书）---");
        PqcSocketFactory.configure(PqcSsl.bcClientContext(bcKs), PqcSsl.hybridGroups(),
                new String[]{"TLSv1.3"}, PqcSsl.PQC_SIGNATURE_SCHEMES);
        Session s3 = Session.getInstance(MailPqcConfig.pop3("localhost", 2645));
        try (Store store = s3.getStore("pop3")) {
            store.connect("localhost", 2645, "alice", "secret");
            System.out.println("  [client] POP3 连接成功");
            report("POP3 连接", "ML-DSA证书", "alice@pqc.local");
        }

        System.out.println("\n--- 场景4 互操作：JDK客户端 ↔ BC服务器（ECDSA证书, 混合群组）---");
        PqcSocketFactory.configure(PqcSsl.jdkClientContext(ecdsaKs), PqcSsl.hybridGroups());
        Session s4 = Session.getInstance(MailPqcConfig.smtp("localhost", 2646));
        Transport.send(buildMessage(s4, "PQC 方案B 互操作", "JDK client to BC server."));
        report("SMTP 互操作", "ECDSA证书", "alice@pqc.local -> bob@pqc.local");

        System.out.println("\n--- 场景5 互操作：BC客户端 ↔ JDK服务器（ECDSA证书, 混合群组）---");
        PqcSocketFactory.configure(PqcSsl.bcClientContext(ecdsaKs), PqcSsl.hybridGroups());
        Session s5 = Session.getInstance(MailPqcConfig.smtp("localhost", 2647));
        Transport.send(buildMessage(s5, "PQC 方案B 互操作2", "BC client to JDK server."));
        report("SMTP 互操作", "ECDSA证书", "alice@pqc.local -> bob@pqc.local");

        System.out.println("\n--- 场景6 断点：JDK客户端 → BC ML-DSA证书服务器（预期握手失败）---");
        try {
            PqcSocketFactory.configure(PqcSsl.jdkClientContext(bcKs), PqcSsl.hybridGroups());
            Session s6 = Session.getInstance(MailPqcConfig.smtp("localhost", 2643));
            Transport.send(buildMessage(s6, "PQC 方案B 断点", "should fail"));
            System.out.println("  [FAIL] 未按预期失败（JDK 应无法认证 ML-DSA 证书）");
        } catch (Exception e) {
            System.out.println("  [预期失败] JDK JSSE signature_algorithms 不含 mldsa -> "
                    + root(e).getClass().getSimpleName() + ": " + root(e).getMessage());
            System.out.println("  （解决方案：升级 JDK 27+ 等待 LAMPS 标准，或切换方案B BC 客户端/方案C 双栈）");
        }

        System.out.println("\n[服务端最后协商] smtpMldsa=" + smtpMldsa.getLastNegotiated() + "/"
                + smtpMldsa.getLastCipher() + " 证书=" + smtpMldsa.getLastCertSigAlg()
                + " | bcEcdsa=" + bcEcdsa.getLastNegotiated() + " 证书=" + bcEcdsa.getLastCertSigAlg()
                + " | jdkEcdsa=" + jdkEcdsa.getLastNegotiated() + " 证书=" + jdkEcdsa.getLastCertSigAlg());
        smtpMldsa.close();
        imapMldsa.close();
        pop3Mldsa.close();
        bcEcdsa.close();
        jdkEcdsa.close();
        System.out.println("\n方案B 测试结束。");
    }

    private static MimeMessage buildMessage(Session session, String subject, String body) throws Exception {
        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress("alice@pqc.local"));
        msg.setRecipient(MimeMessage.RecipientType.TO, new InternetAddress("bob@pqc.local"));
        msg.setSubject(subject);
        msg.setText(body);
        return msg;
    }

    private static void report(String label, String cert, String detail) {
        var session = PqcSocketFactory.getLastSession();
        if (session == null) {
            System.out.println("  [client] " + label + " 完成（无握手记录）");
            return;
        }
        System.out.println("  [client] " + label + " 完成 | " + detail);
        System.out.println("          协议=" + session.getProtocol()
                + " | 密码套件=" + session.getCipherSuite()
                + " | 配置群组=[X25519MLKEM768, x25519]（握手调试日志可见协商值）");
    }

    private static Throwable root(Throwable t) {
        while (t.getCause() != null) {
            t = t.getCause();
        }
        return t;
    }
}
