package pqc.common;

import javax.net.ssl.SSLSession;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;

/** HttpClient5 客户端句柄：客户端 + 其底层的 PqcSocketFactory（用于读取协商会话）。 */
public final class PqcClient implements AutoCloseable {

    private final CloseableHttpClient client;
    private final PqcSocketFactory socketFactory;

    public PqcClient(CloseableHttpClient client, PqcSocketFactory socketFactory) {
        this.client = client;
        this.socketFactory = socketFactory;
    }

    public CloseableHttpClient client() {
        return client;
    }

    public SSLSession lastSession() {
        return socketFactory.getLastSession();
    }

    @Override
    public void close() throws Exception {
        client.close();
    }
}
