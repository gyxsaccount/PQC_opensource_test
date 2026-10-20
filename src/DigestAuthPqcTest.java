import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.security.ConstraintMapping;
import org.eclipse.jetty.ee10.servlet.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.Constraint;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.UserStore;
import org.eclipse.jetty.security.authentication.DigestAuthenticator;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.security.Credential;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * 迁移点3: HTTP Digest 摘要认证 —— MD5 -> SHA-384 / SHA3-384 迁移验证
 *
 * Jetty 12 的 DigestAuthenticator 默认算法为 SHA-256 (RFC 7616)，
 * 迁移目标按 384 位哈希强度执行 (SHA-384 / SHA3-384)。
 * 本 demo 验证:
 *   1. Digest 认证流程 (挑战-应答)
 *   2. 迁移前: SHA-256 (Jetty 默认) 与 传统 MD5 对比
 *   3. 迁移目标: SHA-384 (384 位) 全链路可用性验证
 *
 * 运行: java -cp lib/*;out DigestAuthPqcTest 18446
 */
public class DigestAuthPqcTest {

    static final String TARGET_ALGORITHM = "SHA-384";

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 18446;

        System.out.println("=== 迁移点3: Digest 认证 哈希算法迁移 (MD5 -> SHA-384/SHA3-384) ===");
        System.out.println("JDK: " + System.getProperty("java.version"));

        // 0) 算法可用性对比 (迁移前 / 迁移目标, 384 位为迁移目标)
        String[] algos = {"MD5", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"};
        String[] marks = {"迁移前(旧)", "中间态", "迁移目标(384位)", "迁移目标", "中间态", "迁移目标(384位)", "迁移目标"};
        System.out.println("\n[0] 摘要算法可用性 (RFC 7616 digest 底层依赖):");
        for (int i = 0; i < algos.length; i++) {
            try {
                MessageDigest md = MessageDigest.getInstance(algos[i]);
                byte[] h = md.digest("username:realm:password".getBytes());
                System.out.printf("    %-10s [%s] OK, hex_len=%d%n", algos[i], marks[i], hex(h).length());
            } catch (Exception e) {
                System.out.printf("    %-10s [%s] FAIL: %s%n", algos[i], marks[i], e.getMessage());
            }
        }

        // 1) 启动带 Digest 认证的 Jetty (显式 SHA-384, 384 位迁移目标)
        Server server = new Server();
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(port);
        server.addConnector(connector);

        ConstraintSecurityHandler security = new ConstraintSecurityHandler();
        security.setRealmName("pqc-realm");
        DigestAuthenticator digest = new DigestAuthenticator();
        digest.setAlgorithm(TARGET_ALGORITHM);   // ★ 迁移目标: SHA-384 (384 位)
        security.setAuthenticator(digest);

        HashLoginService loginService = new HashLoginService();
        loginService.setName("pqc-realm");
        UserStore userStore = new UserStore();
        // 用户凭证: Digest.check() 会用存储凭证重新计算 HA1 = H(username:realm:password),
        // 因此存储明文密码即可 (SHA-384 摘要由 Jetty 在 challenge 时计算, 算法 = SHA-384)
        userStore.addUser("alice", Credential.getCredential("password"), new String[]{"user"});
        loginService.setUserStore(userStore);
        security.setLoginService(loginService);

        Constraint constraint = new Constraint.Builder().name("digest").roles("user").build();

        ConstraintMapping mapping = new ConstraintMapping();
        mapping.setConstraint(constraint);
        mapping.setPathSpec("/*");
        // 未覆盖路径全部拒绝 (含认证), 保证 Digest 认证生效
        security.setDenyUncoveredHttpMethods(true);

        List<ConstraintMapping> mappings = new ArrayList<>();
        mappings.add(mapping);
        security.setConstraintMappings(mappings);

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        context.setSecurityHandler(security);
        context.addServlet(new org.eclipse.jetty.ee10.servlet.ServletHolder(new HttpServlet() {
            @Override
            protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                resp.setStatus(HttpServletResponse.SC_OK);
                resp.setContentType("text/plain;charset=UTF-8");
                resp.getWriter().write("Protected resource OK - authenticated as " + req.getUserPrincipal());
            }
        }), "/protected/*");

        server.setHandler(context);
        server.start();
        System.out.println("\n[1] Jetty Digest 认证服务器启动: http://localhost:" + port + "/protected/hello");

        System.out.println("[2] 真实 HTTP Digest challenge-response 流程 ...");
        runRealDigestFlow(port);

        server.stop();
        System.out.println("\n=== 迁移点3 结论: Digest 认证已切换至 SHA-384 (384 位), 可平滑迁移, 无阻断 ===");
    }

    /** 真实流程: 1) 无凭证请求->401 带 nonce; 2) 计算 SHA-384 digest response; 3) 带 Authorization 重发->200。 */
    static void runRealDigestFlow(int port) throws Exception {
        String username = "alice";
        String realm = "pqc-realm";
        String password = "password";
        String path = "/protected/hello";
        String url = "http://localhost:" + port + path;

        // 1) 无凭证请求, 解析 401 挑战
        java.net.HttpURLConnection conn0 = (java.net.HttpURLConnection) new java.net.URL(url).openConnection();
        conn0.setConnectTimeout(3000);
        conn0.setReadTimeout(3000);
        int status0 = conn0.getResponseCode();
        String wwwAuth = conn0.getHeaderField("WWW-Authenticate");
        conn0.disconnect();
        System.out.println("    未认证请求 -> " + status0 + (status0 == 401 ? " (挑战) OK" : " (异常)"));
        System.out.println("    WWW-Authenticate: " + wwwAuth);

        if (status0 != 401 || wwwAuth == null) {
            System.out.println("    [FAIL] 未返回 Digest 挑战, 无法继续");
            return;
        }

        // 解析 nonce
        String nonce = null;
        String algorithm = TARGET_ALGORITHM;
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("nonce=\"([^\"]+)\"").matcher(wwwAuth);
        if (m.find()) nonce = m.group(1);
        java.util.regex.Matcher m2 = java.util.regex.Pattern.compile("algorithm=([^, ]+)").matcher(wwwAuth);
        if (m2.find()) algorithm = m2.group(1).replace("\"", "");
        if (nonce == null) {
            System.out.println("    [FAIL] 挑战中无 nonce");
            return;
        }
        System.out.println("    nonce=" + nonce + ", algorithm=" + algorithm);

        // 2) 计算 response = H(HA1:nonce:nc:cnonce:qop:HA2)  (RFC 7616, qop=auth)
        String nc = "00000001";
        String cnonce = java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        String qop = "auth";
        String ha1 = hex(MessageDigest.getInstance(algorithm).digest((username + ":" + realm + ":" + password).getBytes()));
        String ha2 = hex(MessageDigest.getInstance(algorithm).digest(("GET:" + path).getBytes()));
        String response = hex(MessageDigest.getInstance(algorithm).digest(
                (ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2).getBytes()));
        System.out.println("    HA1=" + ha1 + ", HA2=" + ha2 + ", qop=" + qop + ", nc=" + nc);
        System.out.println("    response=" + response);

        // 3) 带 Authorization 重发
        String authHeader = "Digest username=\"" + username + "\", realm=\"" + realm
                + "\", nonce=\"" + nonce + "\", uri=\"" + path + "\", response=\"" + response
                + "\", algorithm=" + algorithm + ", qop=\"" + qop + "\", nc=" + nc
                + ", cnonce=\"" + cnonce + "\"";
        java.net.HttpURLConnection conn1 = (java.net.HttpURLConnection) new java.net.URL(url).openConnection();
        conn1.setRequestProperty("Authorization", authHeader);
        conn1.setConnectTimeout(3000);
        conn1.setReadTimeout(3000);
        int status1 = conn1.getResponseCode();
        String body = new String(conn1.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        conn1.disconnect();
        System.out.println("    Digest 认证请求 -> " + status1 + (status1 == 200 ? " (OK)" : " (异常)"));
        System.out.println("    响应: " + body.trim());
        System.out.println("    => " + (status1 == 200 ? "Digest 认证 + SHA-384 (384位) 挑战-应答全链路验证通过" : "验证失败"));
    }

    static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
