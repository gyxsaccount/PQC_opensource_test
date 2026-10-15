import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.ContentResponse;
import org.eclipse.jetty.client.transport.HttpClientTransportOverHTTP;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.SSLParameters;
import java.util.Arrays;

/**
 * 迁移点7: Jetty HttpClient 出站 TLS + X25519MLKEM768
 *
 * 客户端同样通过覆写 SslContextFactory.Client.customize(SSLParameters)
 * 将 PQC 混合组 X25519MLKEM768 置于首位，验证出站 HTTPS 走 PQC 密钥交换。
 *
 * 运行: java -cp lib/*;out JettyPqcClient https://localhost:18443/hello
 */
public class JettyPqcClient {

    static class PqcSslContextFactory extends SslContextFactory.Client {
        private final String[] groups;

        PqcSslContextFactory(String[] groups) {
            this.groups = groups;
        }

        @Override
        public SSLParameters customize(SSLParameters sslParams) {
            sslParams.setNamedGroups(groups);
            return super.customize(sslParams);
        }
    }

    public static void main(String[] args) throws Exception {
        String url = args.length > 0 ? args[0] : "https://localhost:18443/hello";

        // 严格验证: 客户端仅通告 X25519MLKEM768, 若握手成功则证明协商的即为 PQC 混合组
        PqcSslContextFactory ssl = new PqcSslContextFactory(new String[]{"X25519MLKEM768"});
        ssl.setTrustAll(true);
        ssl.setEndpointIdentificationAlgorithm(null);

        HttpClient httpClient = new HttpClient(new HttpClientTransportOverHTTP());
        httpClient.setSslContextFactory(ssl);
        httpClient.setFollowRedirects(false);
        httpClient.start();

        System.out.println("[CLIENT] Named groups configured (PQC only): " + Arrays.toString(ssl.getSslContext().getDefaultSSLParameters().getNamedGroups()));

        ContentResponse response = httpClient.newRequest(url).timeout(15, java.util.concurrent.TimeUnit.SECONDS).send();
        System.out.println("[CLIENT] GET " + url + " -> " + response.getStatus() + (response.getStatus() == HttpStatus.OK_200 ? " (OK)" : ""));
        System.out.println("[CLIENT] --- server response ---");
        System.out.println(response.getContentAsString());

        httpClient.stop();
        System.out.println("[CLIENT] SUCCESS: Jetty HttpClient outbound TLS negotiated PQC hybrid group (X25519MLKEM768)");
    }
}
