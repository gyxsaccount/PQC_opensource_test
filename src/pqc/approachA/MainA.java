package pqc.approachA;

import java.security.KeyStore;
import java.util.Properties;

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
 * 方案A：JDK 27 原生（SunJSSE + X25519MLKEM768 混合组）迁移测试。
 * Angus Mail 零代码改造，仅通过会话属性注入自定义 SSLSocketFactory。
 */
public final class MainA {

    private static final String ECDSA_KS = "certs/server-ecdsa.p12";
    private static final String LEGACY_KS = "certs/server-legacy.p12";
    private static final String KS_PASS = "changeit";

    public static void main(String[] args) throws Exception {
        System.out.println("================================================================");
        System.out.println(" 方案A 迁移测试：JDK 27 原生 PQC（SunJSSE + X25519MLKEM768）");
        System.out.println("================================================================");

        KeyStore ecdsaKs = PqcSsl.loadKeyStore(ECDSA_KS, KS_PASS);
        KeyStore legacyKs = PqcSsl.loadKeyStore(LEGACY_KS, KS_PASS);

        PqcMailServer smtp = new PqcMailServer(
                PqcSsl.jdkServerContext(ecdsaKs, KS_PASS), PqcSsl.hybridGroups(), 2543, "smtp", null);
        PqcMailServer imap = new PqcMailServer(
                PqcSsl.jdkServerContext(ecdsaKs, KS_PASS), PqcSsl.hybridGroups(), 2544, "imap", null);
        PqcMailServer pop3 = new PqcMailServer(
                PqcSsl.jdkServerContext(ecdsaKs, KS_PASS), PqcSsl.hybridGroups(), 2545, "pop3", null);
        PqcMailServer legacy = new PqcMailServer(
                PqcSsl.jdkServerContext(legacyKs, KS_PASS), PqcSsl.legacyGroups(), 2546, "smtp", null);
        smtp.start();
        imap.start();
        pop3.start();
        legacy.start();

        System.out.println("\n--- 场景1 SMTP 发送（PQC 混合密钥交换 X25519MLKEM768）---");
        PqcSocketFactory.configure(PqcSsl.jdkClientContext(ecdsaKs), PqcSsl.hybridGroups());
        Session s1 = Session.getInstance(MailPqcConfig.smtp("localhost", 2543));
        MimeMessage msg = buildMessage(s1, "PQC 方案A", "Hello from PQC Angus Mail (JDK native).");
        Transport.send(msg);
        report("SMTP 发送", "alice@pqc.local -> bob@pqc.local");

        System.out.println("\n--- 场景2 IMAP 收信连接（PQC 混合密钥交换）---");
        PqcSocketFactory.configure(PqcSsl.jdkClientContext(ecdsaKs), PqcSsl.hybridGroups());
        Session s2 = Session.getInstance(MailPqcConfig.imap("localhost", 2544));
        try (Store store = s2.getStore("imap")) {
            store.connect("localhost", 2544, "alice", "secret");
            Folder inbox = store.getDefaultFolder();
            System.out.println("  [client] IMAP default folder = " + inbox.getName());
            report("IMAP 连接", "alice@pqc.local");
        }

        System.out.println("\n--- 场景3 POP3 收信连接（PQC 混合密钥交换）---");
        PqcSocketFactory.configure(PqcSsl.jdkClientContext(ecdsaKs), PqcSsl.hybridGroups());
        Session s3 = Session.getInstance(MailPqcConfig.pop3("localhost", 2545));
        try (Store store = s3.getStore("pop3")) {
            store.connect("localhost", 2545, "alice", "secret");
            System.out.println("  [client] POP3 连接成功");
            report("POP3 连接", "alice@pqc.local");
        }

        System.out.println("\n--- 场景4 回退：PQC 优先客户端 → 传统服务器(仅 x25519) ---");
        PqcSocketFactory.configure(PqcSsl.jdkClientContext(legacyKs), PqcSsl.hybridGroups());
        Session s4 = Session.getInstance(MailPqcConfig.smtp("localhost", 2546));
        MimeMessage msg2 = buildMessage(s4, "PQC 方案A 回退", "Fallback over classic x25519.");
        Transport.send(msg2);
        report("SMTP 回退", "alice@pqc.local -> bob@pqc.local");

        System.out.println("\n[服务端最后协商] smtp=" + smtp.getLastNegotiated() + "/" + smtp.getLastCipher()
                + " | imap=" + imap.getLastNegotiated() + "/" + imap.getLastCipher()
                + " | pop3=" + pop3.getLastNegotiated() + "/" + pop3.getLastCipher()
                + " | legacy=" + legacy.getLastNegotiated() + "/" + legacy.getLastCipher());
        smtp.close();
        imap.close();
        pop3.close();
        legacy.close();
        System.out.println("\n方案A 测试结束。");
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
                + " | 密码套件=" + session.getCipherSuite()
                + " | 配置群组=[X25519MLKEM768, x25519]（握手调试日志可见协商值）");
    }
}
