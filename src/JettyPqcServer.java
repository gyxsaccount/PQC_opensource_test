import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.SSLParameters;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * 迁移点1: Jetty HTTPS 服务器 + X25519MLKEM768 (PQC 混合密钥交换)
 *
 * 通过覆写 SslContextFactory.customize(SSLParameters) 显式指定 named groups，
 * 将 PQC 混合组 X25519MLKEM768 置于首位。
 *
 * 依赖: keytool 预生成 keystore（EC 证书签名 + PQC 密钥交换 = 当前可用混合模式）。
 * 运行: java -cp lib/*;out JettyPqcServer etc/keystore.p12 18443
 */
public class JettyPqcServer {

    static final char[] PASSWORD = "changeit".toCharArray();

    /** 覆写 customize 强制指定 named groups（JDK 27 公开 API）。 */
    static class PqcSslContextFactory extends SslContextFactory.Server {
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
        if (args.length < 2) {
            System.err.println("Usage: JettyPqcServer <keystore-path> <port>");
            System.exit(1);
        }
        String ksPath = args[0];
        int port = Integer.parseInt(args[1]);

        Server server = new Server();

        // HTTPS 连接器: TLS 1.3 + PQC 混合组
        PqcSslContextFactory ssl = new PqcSslContextFactory(new String[]{"X25519MLKEM768", "X25519", "secp256r1"});
        ssl.setKeyStorePath(ksPath);
        ssl.setKeyStorePassword(new String(PASSWORD));
        ssl.setIncludeProtocols("TLSv1.3");

        HttpConfiguration https = new HttpConfiguration();
        https.setSecureScheme("https");
        https.setSecurePort(port);
        SecureRequestCustomizer src = new SecureRequestCustomizer();
        src.setSniHostCheck(false); // 测试环境关闭 SNI host 校验
        https.addCustomizer(src);

        SslConnectionFactory sslFactory = new SslConnectionFactory(ssl, "http/1.1");
        HttpConnectionFactory httpFactory = new HttpConnectionFactory(https);

        ServerConnector connector = new ServerConnector(server, sslFactory, httpFactory);
        connector.setPort(port);
        server.addConnector(connector);

        // 核心 Handler（Jetty 12 core Handler API）
        server.setHandler(new Handler.Abstract() {
            @Override
            public boolean handle(Request request, Response response, Callback callback) {
                String path = request.getHttpURI().getPath();
                String proto = request.getConnectionMetaData().getProtocol();
                StringBuilder body = new StringBuilder();
                body.append("Jetty PQC TLS demo\n");
                body.append("  URI        : ").append(path).append('\n');
                body.append("  HTTP proto : ").append(proto).append('\n');
                body.append("  Server TLS : TLSv1.3 + X25519MLKEM768 (hybrid)\n");
                if ("/hello".equals(path)) {
                    response.setStatus(200);
                } else {
                    response.setStatus(404);
                }
                byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
                response.write(true, ByteBuffer.wrap(bytes), callback);
                return true;
            }
        });

        server.start();
        System.out.println("[SERVER] Jetty PQC HTTPS listening on port " + port);
        System.out.println("[SERVER] Named groups configured: " + Arrays.toString(ssl.getSslContext().getDefaultSSLParameters().getNamedGroups()));
        server.join();
    }
}
