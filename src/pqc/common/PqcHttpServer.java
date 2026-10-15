package pqc.common;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

/**
 * 极简 HTTPS 测试服务器（SSLSocket 实现，支持任意 SSLContext 与 TLS 1.3 命名群组）。
 * 改造点 2：服务端 TLS 群组注入（SSLServerSocket.setSSLParameters + setNamedGroups）。
 */
public final class PqcHttpServer implements AutoCloseable {

    private final SSLContext sslContext;
    private final String[] namedGroups;
    private final int port;
    private ServerSocket serverSocket;
    private volatile boolean running;
    private Thread acceptThread;
    private volatile String lastNegotiated = "none";
    private volatile SSLParameters configuredParams;

    public PqcHttpServer(SSLContext sslContext, String[] namedGroups, int port) {
        this.sslContext = sslContext;
        this.namedGroups = namedGroups;
        this.port = port;
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
            configuredParams = params;
            System.out.println("  [server] TLS1.3 named groups = "
                    + String.join(",", namedGroups) + " (provider=" + sslContext.getProvider().getName() + ")");
        }
        running = true;
        acceptThread = new Thread(this::acceptLoop, "pqc-https-server");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket raw = serverSocket.accept();
                Thread t = new Thread(() -> handle(raw));
                t.setDaemon(true);
                t.start();
            } catch (IOException e) {
                if (running) {
                    System.err.println("  [server] accept error: " + e);
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
                SSLParameters params = configuredParams;
                if (params != null) {
                    ssl.setSSLParameters(params);
                }
            }
            ssl.startHandshake();
            SSLSession session = ssl.getSession();
            lastNegotiated = session.getProtocol() + " / " + session.getCipherSuite();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(ssl.getInputStream(), StandardCharsets.ISO_8859_1));
            String line;
            String path = "/";
            int contentLength = 0;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty()) {
                    break;
                }
                if (line.startsWith("GET ")) {
                    path = line.split(" ")[1];
                }
                if (line.toLowerCase().startsWith("content-length:")) {
                    contentLength = Integer.parseInt(line.substring(15).trim());
                }
            }
            if (contentLength > 0) {
                char[] body = new char[contentLength];
                reader.read(body, 0, contentLength);
            }

            String payload = "PQC-" + ("0".repeat(240));
            String bodyText = "{\"path\":\"" + path + "\",\"server\":\"pqc-https\","
                    + "\"negotiated\":\"" + lastNegotiated + "\",\"payload\":\"" + payload + "\"}";
            byte[] bodyBytes = bodyText.getBytes(StandardCharsets.UTF_8);
            String response = "HTTP/1.1 200 OK\r\n"
                    + "Content-Type: application/json\r\n"
                    + "Content-Length: " + bodyBytes.length + "\r\n"
                    + "Connection: close\r\n"
                    + "X-PQC-Server: " + sslContext.getProvider().getName() + "\r\n"
                    + "\r\n";
            OutputStream out = ssl.getOutputStream();
            out.write(response.getBytes(StandardCharsets.ISO_8859_1));
            out.write(bodyBytes);
            out.flush();
        } catch (Exception e) {
            System.err.println("  [server] connection error: " + e.getMessage());
        }
    }

    public String getLastNegotiated() {
        return lastNegotiated;
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
