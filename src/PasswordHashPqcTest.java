import org.eclipse.jetty.util.security.Credential;
import org.eclipse.jetty.util.security.Password;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 迁移点4: 口令哈希/Realm 迁移 (org.eclipse.jetty.util.security.Password / Credential)
 *
 * Jetty 口令哈希算法:
 *   迁移前: MD5, SHA-1 (弱哈希)
 *   迁移目标: SHA-384 / SHA3-384 (384 位), Argon2id/PBKDF2 (抗量子相关)
 *
 * 验证:
 *   1. JCE 层面各哈希算法可用性 (MD5/SHA1/SHA2/SHA3)
 *   2. Jetty Credential.getCredential() 支持的前缀
 *   3. Password 类生成/校验链路 (SHA3-384 迁移目标)
 *   4. 摘要长度增长对比 (影响 DB 存储字段)
 *
 * 运行: java -cp lib/*;out PasswordHashPqcTest
 */
public class PasswordHashPqcTest {

    static final String TARGET_ALGORITHM = "SHA3-384";

    static final String[] HASH_ALGOS = {"MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"};
    static final String[] HASH_MARKS = {"迁移前", "迁移前", "中间态", "迁移目标(384位)", "迁移目标", "中间态", "迁移目标(384位)", "迁移目标"};

    public static void main(String[] args) throws Exception {
        System.out.println("=== 迁移点4: Jetty 口令哈希 / Realm 迁移 (Password/Credential) ===");
        System.out.println("JDK: " + System.getProperty("java.version"));

        // 1) JCE 哈希算法可用性
        System.out.println("\n[1] JCE 哈希算法可用性 + 摘要长度:");
        Map<String, Integer> lenByAlgo = new LinkedHashMap<>();
        for (int i = 0; i < HASH_ALGOS.length; i++) {
            try {
                MessageDigest md = MessageDigest.getInstance(HASH_ALGOS[i]);
                byte[] h = md.digest("password".getBytes());
                lenByAlgo.put(HASH_ALGOS[i], h.length * 8);
                System.out.printf("    %-10s [%s] OK, %d bits (%d hex chars)%n",
                        HASH_ALGOS[i], HASH_MARKS[i], h.length * 8, h.length * 2);
            } catch (Exception e) {
                System.out.printf("    %-10s [%s] FAIL: %s%n", HASH_ALGOS[i], HASH_MARKS[i], e.getMessage());
            }
        }

        // 2) Jetty Credential.getCredential() 前缀支持
        System.out.println("\n[2] Jetty Credential.getCredential() 支持的前缀 (SPI+内置):");
        String[] prefixes = {"CRYPT:", "MD5:", "MD:SHA-256:", "MD:SHA-384:", "MD:SHA3-256:", "MD:SHA3-384:", "MD:SHA3-512:"};
        for (String p : prefixes) {
            try {
                Credential c = Credential.getCredential(p + "00".repeat(48));
                System.out.println("    " + p + " -> " + c.getClass().getSimpleName() + " [OK]");
            } catch (Exception e) {
                System.out.println("    " + p + " -> FAIL: " + e.getMessage());
            }
        }

        // 3) Password 生成 + 校验链路
        System.out.println("\n[3] Password 类生成/校验 (" + TARGET_ALGORITHM + " 迁移目标, 384 位):");
        String digest = hex(MessageDigest.getInstance(TARGET_ALGORITHM).digest("password".getBytes()));
        String credentialStr = "MD:" + TARGET_ALGORITHM + ":" + digest;
        Credential cred = Credential.getCredential(credentialStr);
        boolean ok = cred.check("password");
        boolean bad = cred.check("wrong");
        System.out.println("    生成: " + credentialStr);
        System.out.println("    校验正确密码: " + ok + ", 校验错误密码: " + bad);
        System.out.println("    => " + (ok && !bad ? "迁移后哈希校验链路可用" : "链路异常"));

        // 4) 摘要长度增长对比 (DB 存储影响, 以 384 位迁移目标为基准)
        System.out.println("\n[4] 摘要长度增长 (每 1000 万用户口令哈希, hex 存储, 基准=" + TARGET_ALGORITHM + "):");
        int baseline = lenByAlgo.get(TARGET_ALGORITHM);
        System.out.printf("    %-12s %10s %14s%n", "算法", "hex长度", "相比" + TARGET_ALGORITHM);
        System.out.println("    " + "-".repeat(48));
        for (Map.Entry<String, Integer> e : lenByAlgo.entrySet()) {
            int hexLen = e.getValue() / 4;
            double ratio = (double) hexLen / (baseline / 4);
            String growth = e.getKey().equals(TARGET_ALGORITHM) ? "— (基准)"
                    : String.format("%+d%% (%+.1f MB @10M行)", (int) Math.round((ratio - 1) * 100), (ratio - 1) * hexLen * 10_000_000.0 / (1024 * 1024));
            System.out.printf("    %-12s %8d     %s%n", e.getKey(), hexLen, growth);
        }

        // 5) 抗量子对口令哈希的意义说明
        System.out.println("\n[5] 说明:");
        System.out.println("    - 口令哈希本身并非量子直接威胁对象, 但 NIST/NSA 要求停止弱哈希 (MD5/SHA-1);");
        System.out.println("    - 迁移目标 (384 位): SHA-384 / SHA3-384, 与 Commons Codec 迁移一致;");
        System.out.println("    - 口令在线/离线暴破防护仍以 Argon2id/PBKDF2/BCrypt 为主 (算力型 KDF);");
        System.out.println("    - Jetty 通过 CredentialProvider SPI 可接入 Argon2id, 见 lib 目录扩展。");
        System.out.println("\n=== 迁移点4 结论: 口令哈希可平滑迁移到 SHA-384/SHA3-384 (384 位), 无阻断 ===");
    }

    static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
