package pqc.common;

import java.nio.charset.StandardCharsets;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.core5.http.io.entity.EntityUtils;

/**
 * 测试执行工具：输出场景结果 + 会话信息，供测试报告使用。
 */
public final class TestUtils {

    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_RED = "\u001B[31m";

    /** 执行一次 HttpClient5 请求，打印状态码、会话协议/密码套件。 */
    public static void run(PqcClient client, String url, String scenario) {
        long start = System.nanoTime();
        try {
            HttpGet get = new HttpGet(url);
            try (var resp = client.client().execute(get)) {
                int status = resp.getCode();
                String body = EntityUtils.toString(resp.getEntity(), StandardCharsets.UTF_8);
                long ms = (System.nanoTime() - start) / 1_000_000;
                SSLSession session = client.lastSession();
                String sessionInfo = (session == null)
                        ? "n/a"
                        : session.getProtocol() + " | " + session.getCipherSuite();
                System.out.println(ANSI_GREEN + "  [PASS] " + scenario + ANSI_RESET);
                System.out.println("         HTTP " + status + " in " + ms + " ms | TLS session: " + sessionInfo);
                System.out.println("         body: " + truncate(body, 120));
            }
        } catch (Exception e) {
            System.out.println(ANSI_RED + "  [FAIL] " + scenario + ANSI_RESET);
            System.out.println("         " + rootMessage(e));
            markBreak(scenario);
        }
    }

    /** 原生 HttpsURLConnection 直连（用于对照组，绕过 HttpClient5 观察同层行为）。 */
    public static void runRaw(javax.net.ssl.SSLContext ctx, String url, String scenario) {
        long start = System.nanoTime();
        try {
            HttpsURLConnection conn = (HttpsURLConnection) new java.net.URL(url).openConnection();
            conn.setSSLSocketFactory(ctx.getSocketFactory());
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            int status = conn.getResponseCode();
            long ms = (System.nanoTime() - start) / 1_000_000;
            SSLSession session = conn.getSSLSession().orElse(null);
            System.out.println(ANSI_GREEN + "  [PASS] " + scenario + ANSI_RESET);
            System.out.println("         HTTP " + status + " in " + ms + " ms | TLS session: "
                    + (session == null ? "n/a" : session.getProtocol() + " | " + session.getCipherSuite()));
            conn.disconnect();
        } catch (Exception e) {
            System.out.println(ANSI_RED + "  [FAIL] " + scenario + ANSI_RESET);
            System.out.println("         " + rootMessage(e));
            markBreak(scenario);
        }
    }

    private static void markBreak(String scenario) {
        if (scenario.startsWith("正向") || scenario.startsWith("互操作") || scenario.startsWith("回退")) {
            return; // 只有"断点"场景预期失败，正向失败才算真断点
        }
        if (scenario.contains("断点") || scenario.contains("负向")) {
            System.out.println("         (预期失败，属断点验证)");
        }
    }

    private static String rootMessage(Throwable t) {
        Throwable cur = t;
        while (cur.getCause() != null) {
            cur = cur.getCause();
        }
        return cur.getClass().getSimpleName() + ": " + cur.getMessage();
    }

    private static String truncate(String s, int n) {
        return s.length() <= n ? s : s.substring(0, n) + "...";
    }

    private TestUtils() {
    }
}
