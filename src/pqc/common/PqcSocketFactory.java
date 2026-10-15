package pqc.common;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

/**
 * 迁移点 P1 接入层：自定义 SSLSocketFactory。
 * Angus Mail 通过 mail.{proto}.ssl.socketFactory.class 属性用无参构造实例化本类，
 * 在握手前把 PQC 命名群组注入 SSLSocket（兼容 JDK SunJSSE 与 BC BCJSSE 双栈）。
 * 运行前必须调用 PqcSocketFactory.configure(...) 设置静态配置。
 */
public final class PqcSocketFactory extends SSLSocketFactory {

    private static volatile SSLContext context;
    private static volatile String[] namedGroups;
    private static volatile String[] protocols;
    private static volatile String[] signatureSchemes;
    private static volatile SSLSession lastSession;

    public static synchronized void configure(SSLContext ctx, String[] groups, String[] protos,
            String[] sigs) {
        context = ctx;
        namedGroups = groups;
        protocols = protos;
        signatureSchemes = sigs;
        lastSession = null;
    }

    public static synchronized void configure(SSLContext ctx, String[] groups) {
        configure(ctx, groups, new String[]{"TLSv1.3"}, null);
    }

    public static synchronized SSLSession getLastSession() {
        return lastSession;
    }

    /** Jakarta Mail SocketFetcher 约定：自定义 socket 工厂类需提供静态 getDefault()。 */
    public static SSLSocketFactory getDefault() {
        System.out.println("  [PqcSocketFactory] getDefault() invoked");
        return new PqcSocketFactory();
    }

    private final SSLSocketFactory delegate;
    private final boolean bc;

    public PqcSocketFactory() {
        SSLContext ctx = context;
        if (ctx == null) {
            throw new IllegalStateException("PqcSocketFactory.configure(...) 未调用");
        }
        this.delegate = ctx.getSocketFactory();
        this.bc = PqcSsl.BC_JSSE.equals(ctx.getProvider().getName());
        System.out.println("  [PqcSocketFactory] instance: provider=" + ctx.getProvider().getName()
                + " groups=[" + String.join(",", namedGroups) + "]");
    }

    private Socket configure(Socket socket) throws IOException {
        if (socket instanceof SSLSocket ssl) {
            if (bc && ssl instanceof BCSSLSocket bcSocket) {
                BCSSLParameters params = bcSocket.getParameters();
                params.setNamedGroups(namedGroups);
                params.setProtocols(protocols);
                params.setCipherSuites(ssl.getEnabledCipherSuites());
                if (signatureSchemes != null) {
                    params.setSignatureSchemes(signatureSchemes);
                }
                bcSocket.setParameters(params);
            } else {
                SSLParameters params = ssl.getSSLParameters();
                params.setNamedGroups(namedGroups);
                params.setProtocols(protocols);
                params.setCipherSuites(ssl.getEnabledCipherSuites());
                ssl.setSSLParameters(params);
            }
            ssl.addHandshakeCompletedListener(e -> lastSession = e.getSession());
        }
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return configure(delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddress, int localPort)
            throws IOException {
        return configure(delegate.createSocket(host, port, localAddress, localPort));
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return configure(delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(InetAddress host, int port, InetAddress localAddress, int localPort)
            throws IOException {
        return configure(delegate.createSocket(host, port, localAddress, localPort));
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return configure(delegate.createSocket(s, host, port, autoClose));
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
