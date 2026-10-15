package pqc.common;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

/**
 * 迁移点 P1 验证端：极简 PQC 邮件服务器（SMTP / IMAP / POP3）。
 * 基于 SSLSocket 实现隐式 TLS，支持 JDK SunJSSE 与 BC BCJSSE 双栈，
 * 可选支持 PQC-SIGN（ML-DSA 挑战-响应）SASL 认证（迁移点 P2）。
 */
public final class PqcMailServer implements AutoCloseable {

    private final SSLContext sslContext;
    private final String[] namedGroups;
    private final int port;
    private final String protocol;
    private final Map<String, byte[]> authUsers;

    private ServerSocket serverSocket;
    private volatile boolean running;
    private Thread acceptThread;

    private volatile String lastNegotiated = "none";
    private volatile String lastCipher = "none";
    private volatile String lastCertSigAlg = "none";

    public PqcMailServer(SSLContext sslContext, String[] namedGroups, int port, String protocol,
            Map<String, byte[]> authUsers) {
        this.sslContext = sslContext;
        this.namedGroups = namedGroups;
        this.port = port;
        this.protocol = protocol.toLowerCase();
        this.authUsers = authUsers;
    }

    public void start() throws IOException {
        SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
        serverSocket = factory.createServerSocket(port, 50, InetAddress.getLoopbackAddress());
        if (serverSocket instanceof SSLServerSocket sslServer) {
            sslServer.setNeedClientAuth(false);
            SSLParameters params = sslServer.getSSLParameters();
            params.setProtocols(new String[]{"TLSv1.3"});
            params.setNamedGroups(namedGroups);
            params.setCipherSuites(sslServer.getEnabledCipherSuites());
            sslServer.setSSLParameters(params);
            System.out.println("  [server] " + protocol.toUpperCase() + " TLS1.3 named groups = "
                    + String.join(",", namedGroups)
                    + " (provider=" + sslContext.getProvider().getName() + ")");
        }
        running = true;
        acceptThread = new Thread(this::acceptLoop, "pqc-" + protocol + "-server");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket raw = serverSocket.accept();
                Thread t = new Thread(() -> handle(raw), "pqc-" + protocol + "-conn");
                t.setDaemon(true);
                t.start();
            } catch (IOException e) {
                if (running) {
                    System.err.println("  [server] accept error: " + e.getMessage());
                }
            }
        }
    }

    private void handle(Socket socket) {
        try (SSLSocket ssl = (SSLSocket) socket) {
            ssl.setUseClientMode(false);
            if (ssl instanceof BCSSLSocket bcSocket) {
                BCSSLParameters params = bcSocket.getParameters();
                params.setProtocols(new String[]{"TLSv1.3"});
                params.setCipherSuites(ssl.getEnabledCipherSuites());
                params.setNamedGroups(namedGroups);
                params.setSignatureSchemes(PqcSsl.PQC_SIGNATURE_SCHEMES);
                bcSocket.setParameters(params);
            } else {
                SSLParameters params = ssl.getSSLParameters();
                params.setProtocols(new String[]{"TLSv1.3"});
                params.setNamedGroups(namedGroups);
                params.setCipherSuites(ssl.getEnabledCipherSuites());
                ssl.setSSLParameters(params);
            }
            ssl.startHandshake();
            SSLSession session = ssl.getSession();
            lastNegotiated = session.getProtocol();
            lastCipher = session.getCipherSuite();
            X509Certificate[] chain = (X509Certificate[]) session.getLocalCertificates();
            if (chain != null && chain.length > 0) {
                lastCertSigAlg = chain[0].getSigAlgName();
            }

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(ssl.getInputStream(), StandardCharsets.ISO_8859_1));
            OutputStream out = ssl.getOutputStream();
            switch (protocol) {
                case "smtp" -> smtpLoop(reader, out);
                case "imap" -> imapLoop(reader, out);
                case "pop3" -> pop3Loop(reader, out);
                default -> throw new IllegalStateException("unknown protocol: " + protocol);
            }
        } catch (Exception e) {
            if (running) {
                System.err.println("  [server] " + protocol + " connection error: " + e.getMessage());
            }
        }
    }

    private void smtpLoop(BufferedReader in, OutputStream out) throws IOException {
        send(out, "220 pqc-mail ESMTP PQC ready");
        String line;
        boolean inData = false;
        while ((line = in.readLine()) != null) {
            if (inData) {
                if (line.equals(".")) {
                    inData = false;
                    send(out, "250 2.0.0 OK: queued as PQC-001");
                }
                continue;
            }
            String upper = line.toUpperCase();
            if (upper.startsWith("EHLO") || upper.startsWith("HELO")) {
                send(out, "250-pqc-mail");
                if (authUsers != null && !authUsers.isEmpty()) {
                    send(out, "250-AUTH PQC-SIGN");
                }
                send(out, "250 2.0.0 OK");
            } else if (upper.startsWith("AUTH")) {
                String[] parts = line.split(" ");
                String mech = parts.length > 1 ? parts[1].toUpperCase() : "";
                if (!"PQC-SIGN".equals(mech)) {
                    send(out, "504 5.5.4 Unrecognized authentication type");
                    continue;
                }
                byte[] challenge = new byte[16];
                new SecureRandom().nextBytes(challenge);
                send(out, "334 " + Base64.getEncoder().encodeToString(challenge));
                String resp = in.readLine();
                if (resp == null) {
                    break;
                }
                if (verifyPqcSign(challenge, resp)) {
                    send(out, "235 2.7.0 Authentication successful");
                } else {
                    send(out, "535 5.7.8 Authentication credentials invalid");
                }
            } else if (upper.startsWith("MAIL FROM")) {
                send(out, "250 2.1.0 OK");
            } else if (upper.startsWith("RCPT TO")) {
                send(out, "250 2.1.5 OK");
            } else if (upper.startsWith("DATA")) {
                send(out, "354 End data with <CR><LF>.<CR><LF>");
                inData = true;
            } else if (upper.startsWith("QUIT")) {
                send(out, "221 2.0.0 Bye");
                break;
            } else if (upper.startsWith("NOOP")) {
                send(out, "250 2.0.0 OK");
            } else if (upper.startsWith("RSET")) {
                send(out, "250 2.0.0 OK");
            } else {
                send(out, "250 2.0.0 OK");
            }
        }
    }

    private boolean verifyPqcSign(byte[] challenge, String responseB64) {
        try {
            String response = new String(Base64.getDecoder().decode(responseB64), StandardCharsets.UTF_8);
            int idx = response.indexOf(':');
            if (idx < 0) {
                return false;
            }
            String user = response.substring(0, idx);
            byte[] sig = Base64.getDecoder().decode(response.substring(idx + 1));
            byte[] pub = authUsers == null ? null : authUsers.get(user);
            if (pub == null) {
                return false;
            }
            byte[] input = ("PQC-SIGN\0" + new String(challenge, StandardCharsets.ISO_8859_1) + "\0" + user)
                    .getBytes(StandardCharsets.UTF_8);
            KeyFactory kf = KeyFactory.getInstance("ML-DSA");
            Signature verifier = Signature.getInstance("ML-DSA");
            verifier.initVerify(kf.generatePublic(new X509EncodedKeySpec(pub)));
            verifier.update(input);
            return verifier.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    private void imapLoop(BufferedReader in, OutputStream out) throws IOException {
        send(out, "* OK [CAPABILITY IMAP4rev1 LITERAL+ AUTH=PQC-SIGN] pqc-mail IMAP ready");
        String line;
        while ((line = in.readLine()) != null) {
            String upper = line.toUpperCase();
            String tag = line.contains(" ") ? line.substring(0, line.indexOf(' ')) : "*";
            if (upper.contains("CAPABILITY")) {
                send(out, "* CAPABILITY IMAP4rev1 LITERAL+ AUTH=PQC-SIGN");
                send(out, tag + " OK CAPABILITY completed");
            } else if (upper.contains("LOGIN")) {
                send(out, tag + " OK LOGIN completed");
            } else if (upper.contains("LIST")) {
                send(out, "* LIST (\\HasNoChildren) \"/\" INBOX");
                send(out, tag + " OK LIST completed");
            } else if (upper.contains("LSUB")) {
                send(out, tag + " OK LSUB completed");
            } else if (upper.contains("SELECT")) {
                send(out, "* 0 EXISTS");
                send(out, "* OK [UIDVALIDITY 1] UIDs valid");
                send(out, "* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)");
                send(out, tag + " OK [READ-WRITE] SELECT completed");
            } else if (upper.contains("NOOP")) {
                send(out, tag + " OK NOOP completed");
            } else if (upper.contains("LOGOUT")) {
                send(out, "* BYE pqc-mail logging out");
                send(out, tag + " OK LOGOUT completed");
                break;
            } else {
                send(out, tag + " OK completed");
            }
        }
    }

    private void pop3Loop(BufferedReader in, OutputStream out) throws IOException {
        send(out, "+OK pqc-mail POP3 server ready");
        String line;
        while ((line = in.readLine()) != null) {
            String upper = line.toUpperCase();
            if (upper.startsWith("CAPA")) {
                send(out, "+OK Capability list follows");
                send(out, "USER");
                send(out, "PASS");
                send(out, "UIDL");
                send(out, ".");
            } else if (upper.startsWith("USER")) {
                send(out, "+OK User accepted");
            } else if (upper.startsWith("PASS")) {
                send(out, "+OK Logged in");
            } else if (upper.startsWith("STAT")) {
                send(out, "+OK 0 0");
            } else if (upper.startsWith("NOOP")) {
                send(out, "+OK");
            } else if (upper.startsWith("QUIT")) {
                send(out, "+OK Signing off");
                break;
            } else {
                send(out, "+OK");
            }
        }
    }

    private static void send(OutputStream out, String line) throws IOException {
        out.write((line + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
    }

    public String getLastNegotiated() {
        return lastNegotiated;
    }

    public String getLastCipher() {
        return lastCipher;
    }

    public String getLastCertSigAlg() {
        return lastCertSigAlg;
    }

    @Override
    public void close() {
        running = false;
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException ignored) {
            }
        }
    }
}
