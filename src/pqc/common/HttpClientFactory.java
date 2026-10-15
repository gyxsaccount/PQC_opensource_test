package pqc.common;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;

/**
 * 改造点 4：HttpClient5 接入 PQC 的 SSLContext / SSLSocketFactory。
 * 把自定义 PqcSocketFactory 通过 SSLConnectionSocketFactory 注入连接管理器。
 */
public final class HttpClientFactory {

    public static PqcClient build(String label, SSLContext sslContext, String[] namedGroups) {
        return build(label, sslContext, namedGroups, new String[]{"TLSv1.3"}, null);
    }

    public static PqcClient build(String label, SSLContext sslContext, String[] namedGroups,
            String[] protocols) {
        return build(label, sslContext, namedGroups, protocols, null);
    }

    public static PqcClient build(String label, SSLContext sslContext, String[] namedGroups,
            String[] protocols, String[] signatureSchemes) {
        PqcSocketFactory socketFactory = new PqcSocketFactory(sslContext, namedGroups, protocols,
                signatureSchemes);
        SSLConnectionSocketFactory connectionSocketFactory = new SSLConnectionSocketFactory(
                socketFactory,
                protocols,
                null,
                NoopHostnameVerifier.INSTANCE);
        PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(connectionSocketFactory)
                .build();
        System.out.println("  [client] " + label + " | provider=" + sslContext.getProvider().getName()
                + " | namedGroups=[" + String.join(",", namedGroups) + "]"
                + " | protocols=[" + String.join(",", protocols) + "]");
        return new PqcClient(
                HttpClients.custom()
                        .setConnectionManager(connectionManager)
                        .setUserAgent("PQC-Migration-Test/" + label)
                        .build(),
                socketFactory);
    }

    private HttpClientFactory() {
    }
}
