/**
 * 迁移点8: HTTP/3 (QUIC) 迁移评估
 *
 * Jetty 12 HTTP/3 服务器依赖:
 *   1. jetty-http3-* 模块 (本目录已下载)
 *   2. Quiche 原生库 (jetty-quiche-native, 需独立构建, 不在 Maven Central)
 *   3. HTTP/3 的 TLS 层与 HTTP/1.1/2 完全一致 (TLS 1.3), 
 *      因此 PQC 迁移点与迁移点1相同 (X25519MLKEM768), 仅传输层为 UDP/QUIC。
 *
 * 本 demo 验证:
 *   1. HTTP/3 相关类是否在 classpath
 *   2. Quiche 原生库是否可用
 *   3. HTTP/3 TLS 配置能否复用 PQC named groups
 *
 * 运行: java -cp lib/*;out Http3PqcTest
 */
public class Http3PqcTest {

    public static void main(String[] args) throws Exception {
        System.out.println("=== 迁移点8: HTTP/3 (QUIC) 迁移评估 ===");
        System.out.println("JDK: " + System.getProperty("java.version"));

        // 1) HTTP/3 类可用性
        System.out.println("\n[1] HTTP/3 类可用性:");
        String[][] classes = {
                {"org.eclipse.jetty.http3.HTTP3Configuration", "HTTP/3 配置"},
                {"org.eclipse.jetty.http3.api.Session$Server$Listener", "HTTP/3 会话接口"},
                {"org.eclipse.jetty.http3.server.HTTP3ServerConnectionFactory", "HTTP/3 连接工厂"},
                {"org.eclipse.jetty.http3.server.RawHTTP3ServerConnectionFactory", "HTTP/3 低级工厂"},
                {"org.eclipse.jetty.quic.server.ServerQuicConfiguration", "QUIC 服务器配置"},
        };
        for (String[] c : classes) {
            try {
                Class.forName(c[0]);
                System.out.println("    [ OK ] " + c[1] + " (" + c[0] + ")");
            } catch (ClassNotFoundException e) {
                System.out.println("    [FAIL] " + c[1] + " 未找到: " + c[0]);
            }
        }

        // 2) Quiche 原生库检查
        System.out.println("\n[2] Quiche 原生库依赖 (HTTP/3 必需):");
        String quicheClass = "org.eclipse.jetty.quiche.Quiche";
        try {
            Class.forName(quicheClass);
            System.out.println("    [ OK ] Quiche Java 绑定存在");
        } catch (ClassNotFoundException e) {
            System.out.println("    [FAIL] Quiche Java 绑定缺失: " + quicheClass);
            System.out.println("    => Jetty 12 HTTP/3 需自行构建 jetty-quiche-native (Windows 需 CMake/MSVC), 该依赖不在 Maven Central");
        }

        // 3) TLS 配置复用性 (与迁移点1 相同的 PQC named groups)
        System.out.println("\n[3] HTTP/3 TLS 复用性 (PQC 迁移与迁移点1 一致):");
        javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLS");
        ctx.init(null, null, null);
        String[] groups = ctx.getDefaultSSLParameters().getNamedGroups();
        System.out.println("    JDK TLS named groups 首位: " + groups[0]);
        boolean pqc = groups[0].toUpperCase().contains("MLKEM");
        System.out.println("    PQC 混合组可用: " + pqc + (pqc ? " (HTTP/3 出站/入站自动生效)" : ""));

        System.out.println("\n=== 迁移点8 结论: HTTP/3 依赖 Quiche 原生库 (环境阻断); 其 TLS 层 PQC 迁移与迁移点1 相同, 无额外算法迁移点 ===");
    }
}
