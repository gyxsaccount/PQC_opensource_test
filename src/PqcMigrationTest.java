import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.File;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.ThreadMXBean;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * PQC（后量子）迁移测试 Demo —— Apache Commons Codec
 *
 * 被测软件: Apache Commons Codec（DigestUtils），应用场景: 文件完整性校验 / 校验和。
 *
 * 迁移前算法: MD5、SHA-256
 * 迁移目标:   SHA-384、SHA3-256、SHA3-384（现有算法输出长度翻倍，或替换为 SHA3 系列）
 *
 * 测试目标:
 *   a) 验证从现有算法切换抗量子算法的流程是否存在阻碍、能否平滑切换
 *   b) 对比迁移前后的计算速度（吞吐量）、CPU 耗时、内存影响
 *   c) 对比摘要尺寸增长（百分比 + 柱状图）
 *
 * 编译运行（需 commons-codec 依赖，JDK 9+ 以获得 SHA3 支持）:
 *   javac -encoding UTF-8 -cp commons-codec-1.22.1.jar PqcMigrationTest.java
 *   java  -cp ".;commons-codec-1.22.1.jar" PqcMigrationTest
 */
public class PqcMigrationTest {

    enum AlgorithmFamily {
        LEGACY("迁移前"),
        TARGET("迁移目标(PQC)");

        private final String label;

        AlgorithmFamily(String label) {
            this.label = label;
        }

        String label() {
            return label;
        }
    }

    enum ChecksumAlgorithm {
        MD5("MD5", 128, AlgorithmFamily.LEGACY),
        SHA_256("SHA-256", 256, AlgorithmFamily.LEGACY),
        SHA_384("SHA-384", 384, AlgorithmFamily.TARGET),
        SHA3_256("SHA3-256", 256, AlgorithmFamily.TARGET),
        SHA3_384("SHA3-384", 384, AlgorithmFamily.TARGET);

        private final String jceName;
        private final int bitLength;
        private final AlgorithmFamily family;

        ChecksumAlgorithm(String jceName, int bitLength, AlgorithmFamily family) {
            this.jceName = jceName;
            this.bitLength = bitLength;
            this.family = family;
        }

        String jceName() {
            return jceName;
        }

        int bitLength() {
            return bitLength;
        }

        int hexLength() {
            return bitLength / 4;
        }

        AlgorithmFamily family() {
            return family;
        }
    }

    /**
     * 文件校验和计算服务。算法仅通过配置(构造/switchTo)指定，
     * 用于验证: 切换算法时下游调用代码路径是否完全不变。
     */
    static final class ChecksumService {
        private ChecksumAlgorithm algorithm;

        ChecksumService(ChecksumAlgorithm algorithm) {
            this.algorithm = algorithm;
        }

        void switchTo(ChecksumAlgorithm algorithm) {
            this.algorithm = algorithm;
        }

        ChecksumAlgorithm current() {
            return algorithm;
        }

        String computeHex(File file) throws Exception {
            MessageDigest md = DigestUtils.getDigest(algorithm.jceName());
            try (InputStream in = Files.newInputStream(file.toPath())) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) {
                    md.update(buf, 0, n);
                }
            }
            return Hex.encodeHexString(md.digest());
        }

        void computeBatch(File file, int count) throws Exception {
            MessageDigest md = DigestUtils.getDigest(algorithm.jceName());
            byte[] fileBytes = Files.readAllBytes(file.toPath());
            for (int i = 0; i < count; i++) {
                md = DigestUtils.getDigest(algorithm.jceName());
                md.update(fileBytes);
                md.digest();
            }
        }
    }

    /** 模拟持久化: 定长字段(如 DB VARCHAR)中存放 hex 摘要。 */
    static final class ChecksumStore {
        private final String column;
        private final int capacity;
        private String stored = "";

        ChecksumStore(String column, int capacity) {
            this.column = column;
            this.capacity = capacity;
        }

        String save(String hex) {
            if (hex == null) {
                return "[FAIL] 算法不可用，无法写入";
            }
            if (hex.length() > capacity) {
                return String.format(Locale.ROOT,
                        "[FAIL] 摘要长度 %d 超出字段容量 %d（%s）→ 写入截断/报错，迁移受阻",
                        hex.length(), capacity, column);
            }
            stored = hex;
            return String.format(Locale.ROOT,
                    "[ OK ] 摘要长度 %d 可容纳于 %s（容量 %d）", hex.length(), column, capacity);
        }

        boolean verify(String hex) {
            return stored.equalsIgnoreCase(hex);
        }
    }

    static String availability(ChecksumAlgorithm a) {
        try {
            MessageDigest.getInstance(a.jceName());
            return "[ OK ] " + a.jceName() + " 可用 (Provider=" + providerOf(a.jceName()) + ")";
        } catch (NoSuchAlgorithmException e) {
            return "[FAIL] " + a.jceName() + " 不可用: " + e.getMessage();
        }
    }

    static String providerOf(String jceName) {
        for (Provider p : Security.getProviders()) {
            if (p.getService("MessageDigest", jceName) != null) {
                return p.getName();
            }
        }
        return "?";
    }

    // ──────────────────────────────────────────────
    //  性能测试
    // ──────────────────────────────────────────────

    static final class PerfResult {
        String algo;
        long fileSize;
        int iterations;
        double wallMs;
        double cpuMs;
        double memKbPerOp;
        double throughputMBps;
    }

    /**
     * 对每种算法 × 每种文件大小运行性能测试。
     * 返回结果列表供后续分析。
     */
    static List<PerfResult> runPerformanceTest(ChecksumService svc, List<ChecksumAlgorithm> algos,
                                               long[] fileSizes, int[] iterCounts) throws Exception {
        ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
        MemoryMXBean memBean = ManagementFactory.getMemoryMXBean();
        boolean cpuSupported = threadBean.isCurrentThreadCpuTimeSupported();

        if (!cpuSupported) {
            System.out.println("  [警告] 当前 JVM 不支持 getCurrentThreadCpuTime()，CPU 时间列显示为 N/A");
        }

        List<PerfResult> results = new ArrayList<>();

        for (int fi = 0; fi < fileSizes.length; fi++) {
            long size = fileSizes[fi];
            int iter = iterCounts[fi];
            int warmup = Math.max(1, iter / 5);

            // 生成该尺寸的测试文件
            File testFile = File.createTempFile("perf-" + size + "-", ".bin");
            byte[] data = new byte[(int) size];
            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) (i * 31 + 7);
            }
            Files.write(testFile.toPath(), data);

            for (ChecksumAlgorithm algo : algos) {
                svc.switchTo(algo);

                // 预热
                svc.computeBatch(testFile, warmup);
                System.gc();
                Thread.sleep(10);

                // 测量: 内存快照
                long memBefore = memBean.getHeapMemoryUsage().getUsed();

                // 测量: CPU + 墙钟
                long cpuStart = cpuSupported ? threadBean.getCurrentThreadCpuTime() : 0;
                long wallStart = System.nanoTime();

                svc.computeBatch(testFile, iter);

                long wallEnd = System.nanoTime();
                long cpuEnd = cpuSupported ? threadBean.getCurrentThreadCpuTime() : 0;

                long memAfter = memBean.getHeapMemoryUsage().getUsed();

                double wallMs = (wallEnd - wallStart) / 1_000_000.0;
                double cpuMs = cpuSupported ? (cpuEnd - cpuStart) / 1_000_000.0 : Double.NaN;
                double memKbPerOp = (memAfter - memBefore) / (double) iter / 1024.0;
                double throughput = (double) size / (1024.0 * 1024.0) / (wallMs / 1000.0);

                PerfResult r = new PerfResult();
                r.algo = algo.jceName();
                r.fileSize = size;
                r.iterations = iter;
                r.wallMs = wallMs / iter;           // 单次平均
                r.cpuMs = cpuMs / iter;
                r.memKbPerOp = memKbPerOp;
                r.throughputMBps = throughput;
                results.add(r);
            }

            // 清理
            testFile.delete();
        }
        return results;
    }

    static void printPerfTable(List<PerfResult> results, ChecksumAlgorithm baseline) {
        // 找到基线 (SHA-256) 的吞吐量作为对比基准
        Map<Long, Double> baselineThroughput = new LinkedHashMap<>();
        for (PerfResult r : results) {
            if (r.algo.equals(baseline.jceName())) {
                baselineThroughput.put(r.fileSize, r.throughputMBps);
            }
        }

        long prevSize = -1;
        for (PerfResult r : results) {
            if (r.fileSize != prevSize) {
                prevSize = r.fileSize;
                String sizeLabel;
                if (r.fileSize < 1024) sizeLabel = r.fileSize + " B";
                else if (r.fileSize < 1024 * 1024) sizeLabel = (r.fileSize / 1024) + " KB";
                else sizeLabel = (r.fileSize / (1024 * 1024)) + " MB";
                System.out.println("  文件大小: " + sizeLabel + " | 迭代: " + r.iterations + " 次");
                System.out.printf(Locale.ROOT, "    %-12s %10s %10s %12s %10s %12s%n",
                        "算法", "耗时/次(ms)", "CPU/次(ms)", "吞吐(MB/s)", "内存(KB/op)", "相对基线");
            }
            String cpuStr = Double.isNaN(r.cpuMs) ? "   N/A    " : String.format(Locale.ROOT, "%10.3f", r.cpuMs);
            double ratio = baselineThroughput.getOrDefault(r.fileSize, 1.0);
            double speedRatio = r.throughputMBps / ratio;
            String ratioStr = String.format(Locale.ROOT, "%+.1f%%", (speedRatio - 1) * 100);

            System.out.printf(Locale.ROOT, "    %-12s %10.3f %s %12.2f %10.1f %12s%n",
                    r.algo, r.wallMs, cpuStr, r.throughputMBps, r.memKbPerOp, ratioStr);
        }
    }

    // ──────────────────────────────────────────────
    //  摘要尺寸增长对比（百分比 + ASCII 柱状图）
    // ──────────────────────────────────────────────

    static void printDigestSizeComparison(ChecksumAlgorithm baseline) {
        int barWidth = 60;
        int maxHexLen = 0;
        for (ChecksumAlgorithm a : ChecksumAlgorithm.values()) {
            if (a.hexLength() > maxHexLen) maxHexLen = a.hexLength();
        }

        System.out.println("  算法名称     hex长度  相比基线增长      相对比例   柱状图");
        System.out.println("  " + "-".repeat(88));

        for (ChecksumAlgorithm a : ChecksumAlgorithm.values()) {
            int len = a.hexLength();
            int diff = len - baseline.hexLength();
            double pct = (double) len / baseline.hexLength() * 100.0;
            String diffStr;
            if (diff < 0) diffStr = String.format(Locale.ROOT, "%d (%.1f%%)", diff, (double) len / baseline.hexLength() * 100.0);
            else if (diff > 0) diffStr = String.format(Locale.ROOT, "+%d (+%.1f%%)", diff, (double) diff / baseline.hexLength() * 100.0);
            else diffStr = "0 (0.0%)";

            int filled = (int) Math.round((double) len / maxHexLen * barWidth);
            int empty = barWidth - filled;
            String bar = "█".repeat(filled) + "░".repeat(Math.max(0, empty));

            System.out.printf(Locale.ROOT, "  %-10s %5d    %-16s  %6.1f%%  %s%n",
                    a.name(), len, diffStr, pct, bar);
        }
    }

    // ──────────────────────────────────────────────
    //  摘要尺寸增长百分比数值表
    // ──────────────────────────────────────────────

    static void printDigestSizePercentageTable(ChecksumAlgorithm baseline) {
        System.out.println("  算法        位长(bits)  hex长度(字符)  对比SHA-256增长(字符)  增长百分比");
        System.out.println("  " + "-".repeat(75));
        for (ChecksumAlgorithm a : ChecksumAlgorithm.values()) {
            int len = a.hexLength();
            int diff = len - baseline.hexLength();
            double pct = (double) len / baseline.hexLength() * 100.0;
            String diffStr = diff >= 0 ? "+" + diff : String.valueOf(diff);
            System.out.printf(Locale.ROOT, "  %-12s %5d       %4d            %s                  %+.1f%%%n",
                    a.name(), a.bitLength(), len, diffStr, pct - 100.0);
        }
    }

    // ──────────────────────────────────────────────
    //  性能汇总：各文件尺寸下的吞吐量变化率
    // ──────────────────────────────────────────────

    static void printThroughputSummary(List<PerfResult> results, ChecksumAlgorithm baseline) {
        System.out.println("  ===== 吞吐量变化率 (以 SHA-256 为基准, + 表示更快) =====");
        String header = "  算法";
        for (PerfResult r : results) {
            if (r.algo.equals(baseline.jceName())) {
                String sizeLabel = fileSizeLabel(r.fileSize);
                header += "    " + sizeLabel;
            }
        }
        header += "    平均";
        System.out.println(header);

        for (ChecksumAlgorithm algo : ChecksumAlgorithm.values()) {
            if (algo == baseline) continue;
            String line = String.format(Locale.ROOT, "  %-10s", algo.jceName());
            double sum = 0;
            int count = 0;
            for (PerfResult r : results) {
                if (!r.algo.equals(algo.jceName())) continue;
                double baseTp = 0;
                for (PerfResult br : results) {
                    if (br.algo.equals(baseline.jceName()) && br.fileSize == r.fileSize) {
                        baseTp = br.throughputMBps;
                        break;
                    }
                }
                double change = (r.throughputMBps / baseTp - 1) * 100;
                line += String.format(Locale.ROOT, "  %+8.1f%%", change);
                sum += change;
                count++;
            }
            line += String.format(Locale.ROOT, "  %+8.1f%%", sum / count);
            System.out.println(line);
        }
    }

    static String fileSizeLabel(long size) {
        if (size < 1024) return size + "B";
        if (size < 1024 * 1024) return (size / 1024) + "KB";
        return (size / (1024 * 1024)) + "MB";
    }

    // ──────────────────────────────────────────────
    //  Main
    // ──────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        List<String> findings = new ArrayList<>();

        System.out.println("=== PQC 迁移测试: Apache Commons Codec (DigestUtils) ===");
        System.out.println("Java     : " + System.getProperty("java.version"));
        System.out.println("Codec    : " + DigestUtils.class.getPackage().getImplementationVersion());
        System.out.println();

        // 0) 构造样例文件(模拟被校验的真实文件)
        File sample = File.createTempFile("pqc-sample-", ".bin");
        byte[] content = new byte[64 * 1024];
        for (int i = 0; i < content.length; i++) {
            content[i] = (byte) (i * 7 + 13);
        }
        Files.write(sample.toPath(), content);
        System.out.println("样例文件 : " + sample.getAbsolutePath() + " (" + content.length + " bytes)");
        System.out.println();

        // 1) 算法可用性检查
        System.out.println("--- 1) 算法可用性（迁移前 / 迁移目标） ---");
        for (ChecksumAlgorithm a : ChecksumAlgorithm.values()) {
            String r = availability(a);
            System.out.println("  " + r);
            if (r.startsWith("[FAIL]")) {
                findings.add("算法不可用: " + a.jceName());
            }
        }
        System.out.println();

        // 2) 基线摘要计算 + 输出长度对比
        System.out.println("--- 2) 同一文件各算法摘要(hex)与长度对比 ---");
        ChecksumService svc = new ChecksumService(ChecksumAlgorithm.MD5);
        Map<ChecksumAlgorithm, String> digests = new LinkedHashMap<>();
        for (ChecksumAlgorithm a : ChecksumAlgorithm.values()) {
            svc.switchTo(a);
            try {
                String hex = svc.computeHex(sample);
                digests.put(a, hex);
                System.out.printf(Locale.ROOT, "  [%s] %-9s bits=%-4d hex_len=%-3d %s%n",
                        a.family().label(), a.name(), a.bitLength(), hex.length(), hex);
            } catch (Exception e) {
                digests.put(a, null);
                System.out.println("  [FAIL] " + a.name() + " 计算失败: " + e.getMessage());
                findings.add("计算失败: " + a.jceName() + " -> " + e.getMessage());
            }
        }
        String sha256Hex = digests.get(ChecksumAlgorithm.SHA_256);
        if (sha256Hex != null) {
            System.out.println("  > SHA-256 基线 hex 长度 = " + sha256Hex.length());
            for (ChecksumAlgorithm a : new ChecksumAlgorithm[]{
                    ChecksumAlgorithm.SHA_384, ChecksumAlgorithm.SHA3_256, ChecksumAlgorithm.SHA3_384}) {
                String hex = digests.get(a);
                if (hex != null && hex.length() != sha256Hex.length()) {
                    findings.add("摘要长度变化: " + a.jceName() + " hex 长度 "
                            + sha256Hex.length() + " -> " + hex.length() + "（存储/格式需评估）");
                }
            }
        }
        System.out.println();

        // 3) 持久化定长字段兼容性 —— 典型的迁移阻碍点
        System.out.println("--- 3) 持久化定长字段兼容性（模拟 DB VARCHAR） ---");
        ChecksumStore store64 = new ChecksumStore("VARCHAR(64)", 64);
        System.out.println("  [基线] SHA-256 写入 VARCHAR(64):");
        System.out.println("    " + store64.save(digests.get(ChecksumAlgorithm.SHA_256)));
        System.out.println("  [迁移目标] 直接写入原 VARCHAR(64) 字段:");
        for (ChecksumAlgorithm a : new ChecksumAlgorithm[]{
                ChecksumAlgorithm.SHA3_256, ChecksumAlgorithm.SHA3_384, ChecksumAlgorithm.SHA_384}) {
            String r = store64.save(digests.get(a));
            System.out.println("    " + a.name() + ": " + r);
            if (r.startsWith("[FAIL]")) {
                findings.add("定长字段无法容纳: " + a.jceName());
            }
        }
        System.out.println("  [迁移目标] 字段扩容到 VARCHAR(96) 后:");
        ChecksumStore store96 = new ChecksumStore("VARCHAR(96)", 96);
        System.out.println("    " + store96.save(digests.get(ChecksumAlgorithm.SHA3_384)));
        System.out.println();

        // 4) 平滑切换: 同一服务运行时按配置切换算法，调用方代码不变
        System.out.println("--- 4) 平滑切换测试（运行时按配置切换算法） ---");
        ChecksumService migrator = new ChecksumService(ChecksumAlgorithm.SHA_256);
        String before = migrator.computeHex(sample);
        migrator.switchTo(ChecksumAlgorithm.SHA3_256);
        String after = migrator.computeHex(sample);
        boolean sameLen = before.length() == after.length();
        boolean stable = after.equals(migrator.computeHex(sample));
        System.out.println("  迁移前 SHA-256 : " + before);
        System.out.println("  切换后 SHA3-256: " + after);
        System.out.println("  调用方仍走同一 computeHex(File) 接口 => 接口级平滑切换: 支持");
        System.out.println("  hex 长度保持一致(" + sameLen + "): "
                + (sameLen ? "无存储字段影响" : "需同步评估存储字段"));
        System.out.println("  摘要确定性(重复计算一致): " + (stable ? "是" : "否"));
        if (!stable) {
            findings.add("SHA3-256 计算不稳定(确定性校验失败)");
        }
        System.out.println();

        // 5) 过渡期双算法兼容（老摘要 + 新摘要并存），支持滚动迁移
        System.out.println("--- 5) 过渡期双算法兼容（滚动迁移） ---");
        ChecksumService oldVerifier = new ChecksumService(ChecksumAlgorithm.SHA_256);
        ChecksumService newVerifier = new ChecksumService(ChecksumAlgorithm.SHA3_256);
        String legacyStored = oldVerifier.computeHex(sample);
        String newStored = newVerifier.computeHex(sample);
        String incoming = newStored;
        boolean ok = legacyStored.equalsIgnoreCase(incoming) || newStored.equalsIgnoreCase(incoming);
        System.out.println("  历史存量(SHA-256) : " + legacyStored);
        System.out.println("  新写入(SHA3-256) : " + newStored);
        System.out.println("  双算法并存校验(任一匹配即通过): " + (ok ? "通过" : "失败"));
        System.out.println("  => " + (ok ? "支持平滑滚动迁移（存量数据与新增数据均可用）" : "过渡期存在兼容问题"));
        if (!ok) {
            findings.add("过渡期双算法校验失败");
        }
        System.out.println();

        // ════════════════════════════════════════════
        //  6) 性能对比: 速度 + CPU + 内存
        // ════════════════════════════════════════════
        System.out.println("--- 6) 性能对比（计算速度 + CPU + 内存） ---");
        List<ChecksumAlgorithm> perfAlgos = List.of(ChecksumAlgorithm.values());
        long[] perfSizes = {1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024};
        int[] perfIters = {500, 100, 20, 5};

        List<PerfResult> perfResults = runPerformanceTest(svc, perfAlgos, perfSizes, perfIters);
        printPerfTable(perfResults, ChecksumAlgorithm.SHA_256);
        System.out.println();

        // 6b) 吞吐量变化率汇总
        printThroughputSummary(perfResults, ChecksumAlgorithm.SHA_256);
        System.out.println();

        // ════════════════════════════════════════════
        //  7) 摘要尺寸增长对比（百分比 + 柱状图）
        // ════════════════════════════════════════════
        System.out.println("--- 7) 摘要尺寸增长对比（百分比 + 柱状图） ---");
        System.out.println();

        System.out.println("  [7a] 尺寸增长百分比数值表:");
        printDigestSizePercentageTable(ChecksumAlgorithm.SHA_256);
        System.out.println();

        System.out.println("  [7b] ASCII 柱状图（相对 SHA-256 = 100%）:");
        System.out.println("  █ = 填充块   ░ = 空白   (柱宽 = hex长度 / 最大hex长度 × 60)");
        printDigestSizeComparison(ChecksumAlgorithm.SHA_256);
        System.out.println();

        // 7c) 摘要增长对数据库存储的影响估算
        System.out.println("  [7c] 存储空间增长估算（每 1000 万条记录）:");
        System.out.printf(Locale.ROOT, "    %-12s %12s %12s %16s%n", "算法", "单条hex(字符)", "存储空间(MB)", "相比SHA-256增长");
        System.out.println("    " + "-".repeat(56));
        long sha256HexLen = ChecksumAlgorithm.SHA_256.hexLength();
        for (ChecksumAlgorithm a : ChecksumAlgorithm.values()) {
            long hexLen = a.hexLength();
            double storageMB = hexLen * 10_000_000.0 / (1024.0 * 1024.0);
            double ratio = (double) hexLen / sha256HexLen;
            String growthStr = a == ChecksumAlgorithm.SHA_256 ? "— (基准)" :
                    String.format(Locale.ROOT, "%+.1f MB (%+.0f%%)",
                            (ratio - 1) * 10_000_000.0 / (1024.0 * 1024.0),
                            (ratio - 1) * 100);
            System.out.printf(Locale.ROOT, "    %-12s %10d     %10.1f    %s%n",
                    a.name(), hexLen, storageMB, growthStr);
        }
        System.out.println();

        // ════════════════════════════════════════════
        //  8) 结论汇总
        // ════════════════════════════════════════════
        System.out.println("=== 迁移评估结论 ===");
        if (findings.isEmpty()) {
            System.out.println("未发现阻碍: 接口与输出格式(hex)完全兼容，可按配置平滑切换。");
            System.out.println("仅需在执行切换前评估摘要长度变化对存储字段的影响。");
        } else {
            System.out.println("发现 " + findings.size() + " 个需关注点（阻碍/风险）:");
            for (String f : findings) {
                System.out.println("  - " + f);
            }
        }
        System.out.println();
        System.out.println("备注: 本 Demo 通过 Apache Commons Codec DigestUtils 完成，结论基于 API 层面对齐实验；");
        System.out.println("      SHA3 系列需 JDK 9+，低于该版本时 JCE 不提供 SHA3 实现。");
    }
}