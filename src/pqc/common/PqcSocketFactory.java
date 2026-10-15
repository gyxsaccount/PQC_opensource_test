package pqc.common;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

/**
 * 改造点 3：自定义 SSLSocketFactory，在握手前把 PQC 命名群组注入 SSLSocket。
 * 同时兼容 JDK(JSSE) 与 BouncyCastle(BCJSSE) 两种实现。
 */
public final class PqcSocketFactory extends SSLSocketFactory {

    private final SSLSocketFactory delegate;
    private final String[] namedGroups;
    private final String[] protocols;
    private final String[] signatureSchemes;
    private final boolean bc;
    private final AtomicReference<SSLSession> lastSession = new AtomicReference<>();

    public PqcSocketFactory(SSLContext sslContext, String[] namedGroups) {
        this(sslContext, namedGroups, new String[]{"TLSv1.3"}, null);
    }

    public PqcSocketFactory(SSLContext sslContext, String[] namedGroups, String[] protocols) {
        this(sslContext, namedGroups, protocols, null);
    }

    public PqcSocketFactory(SSLContext sslContext, String[] namedGroups, String[] protocols,
            String[] signatureSchemes) {
        this.delegate = sslContext.getSocketFactory();
        this.namedGroups = namedGroups;
        this.protocols = protocols;
        this.signatureSchemes = signatureSchemes;
        this.bc = PqcSsl.BC_JSSE.equals(sslContext.getProvider().getName());
    }

    /** 最近一次 TLS 握手完成的 SSLSession（用于报告协商结果）。 */
    public SSLSession getLastSession() {
        return lastSession.get();
    }

    private Socket configure(Socket socket) throws IOException {
        if (socket instanceof SSLSocket sslSocket) {
            if (bc && sslSocket instanceof BCSSLSocket bcSocket) {
                BCSSLParameters params = bcSocket.getParameters();
                params.setNamedGroups(namedGroups);
                params.setProtocols(protocols);
                params.setCipherSuites(sslSocket.getEnabledCipherSuites());
                if (signatureSchemes != null) {
                    params.setSignatureSchemes(signatureSchemes);
                }
                bcSocket.setParameters(params);
            } else {
                SSLParameters params = sslSocket.getSSLParameters();
                params.setNamedGroups(namedGroups);
                params.setProtocols(protocols);
                params.setCipherSuites(sslSocket.getEnabledCipherSuites());
                sslSocket.setSSLParameters(params);
            }
            sslSocket.addHandshakeCompletedListener(e -> lastSession.set(e.getSession()));
        }
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return configure(delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddress, int localPort) throws IOException {
        return configure(delegate.createSocket(host, port, localAddress, localPort));
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return configure(delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(InetAddress host, int port, InetAddress localAddress, int localPort) throws IOException {
        return configure(delegate.createSocket(host, port, localAddress, localPort));
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return configure(delegate.createSocket(socket, host, port, autoClose));
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }
}
