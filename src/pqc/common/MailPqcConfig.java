package pqc.common;

import java.util.Properties;

import javax.net.ssl.SSLSocketFactory;

/**
 * 迁移点 P1 接入层：Angus Mail 会话属性装配。
 * 把 PqcSocketFactory + TLSv1.3 注入 SMTP/IMAP/POP3 三个协议（隐式 TLS + STARTTLS 双通道）。
 * 通过 mail.{proto}.ssl.socketFactory（实例）属性注入，SocketFetcher 直接使用该工厂创建 SSL 套接字。
 */
public final class MailPqcConfig {

    public static Properties smtp(String host, int port) {
        return base("smtp", host, port);
    }

    public static Properties imap(String host, int port) {
        return base("imap", host, port);
    }

    public static Properties pop3(String host, int port) {
        return base("pop3", host, port);
    }

    /** 在 SMTP 配置上启用 PQC-SIGN SASL 认证（迁移点 P2）。 */
    public static Properties smtpAuth(Properties p, String mech, String mlDsaPrivateKeyB64) {
        p.setProperty("mail.smtp.auth", "true");
        p.setProperty("mail.smtp.auth.mechanisms", mech);
        p.setProperty("mail.smtp.sasl.enable", "true");
        p.setProperty("mail.smtp.sasl.pqc.privateKey", mlDsaPrivateKeyB64);
        return p;
    }

    private static Properties base(String proto, String host, int port) {
        Properties p = new Properties();
        p.setProperty("mail." + proto + ".host", host);
        p.setProperty("mail." + proto + ".port", String.valueOf(port));
        p.setProperty("mail." + proto + ".connectiontimeout", "15000");
        p.setProperty("mail." + proto + ".timeout", "15000");
        p.setProperty("mail." + proto + ".ssl.enable", "true");
        p.setProperty("mail." + proto + ".starttls.enable", "true");
        p.setProperty("mail." + proto + ".ssl.protocols", "TLSv1.3");
        p.put("mail." + proto + ".ssl.socketFactory", new PqcSocketFactory());
        p.setProperty("mail." + proto + ".ssl.socketFactory.fallback", "false");
        return p;
    }

    private MailPqcConfig() {
    }
}
