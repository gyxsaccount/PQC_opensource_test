# Apache Commons Codec 后量子（PQC）迁移测试报告

## 目录

1. [测试概述](#1-测试概述)
2. [迁移点总览](#2-迁移点总览)
3. [组件版本配套关系](#3-组件版本配套关系)
4. [迁移点 M1：算法清单定义层](#4-迁移点-m1算法清单定义层)
5. [迁移点 M2：校验服务层（平滑切换核心）](#5-迁移点-m2校验服务层平滑切换核心)
6. [迁移点 M3：持久化兼容层](#6-迁移点-m3持久化兼容层)
7. [迁移点 M4：过渡期双算法校验](#7-迁移点-m4过渡期双算法校验)
8. [迁移点 M5：性能对比（速度/CPU/内存）](#8-迁移点-m5性能对比速度cp内存)
9. [迁移点 M6：摘要尺寸增长对比](#9-迁移点-m6摘要尺寸增长对比)
10. [迁移断点与解决方案](#10-迁移断点与解决方案)
11. [工程结构](#11-工程结构)
12. [结论与实施路线](#12-结论与实施路线)

---

## 1. 测试概述

**测试目标**：将 Apache Commons Codec（`DigestUtils`）在**完整性保护 / 文件校验**场景下的摘要算法，从经典算法（MD5 / SHA-256）迁移到抗量子算法（SHA-384 / SHA3-256 / SHA3-384），验证迁移流程是否有阻碍、能否平滑切换，并量化迁移代价（速度、CPU、内存、摘要尺寸）。

**核心结论**：

- **API 层面对齐，切换零代码改动**：Commons Codec 通过 `DigestUtils.getDigest(算法名)` 按名称构造 `MessageDigest`，业务代码只需改变算法名配置 → **算法切换在接口层面完全平滑**。
- **输出格式完全兼容**：所有算法统一输出 hex 字符串，下游 hex 解析代码无需修改。
- **唯一阻碍是存储层**：SHA-384 / SHA3-384 输出 96 个 hex 字符，超出 SHA-256 配套的 `VARCHAR(64)` 定长字段 → 需扩容或改选长度不变的 SHA3-256。
- **性能代价可量化**：SHA3 系列吞吐相对 SHA-256 下降约 **40~79%**（随文件尺寸增大趋稳于 -72%~-79%），内存占用基本持平。

**测试环境**：

| 项目 | 规格 |
|---|---|
| 操作系统 | Windows x86-64 |
| JDK | **JDK 27**（build 27+35-2325，2026-09-15），SHA3 由 SUN provider 提供 |
| commons-codec | **1.22.1** |
| 测试目录 | `D:\PQC-test\Apache_Commons_CodeC_PQC\` |

---

## 2. 迁移点总览

| # | 迁移点 | 使用面 | 经典算法 | 后量子方案 | 状态 |
|---|---|---|---|---|---|
| **M1** | 算法清单 | 完整性保护 | MD5 / SHA-256 | SHA-384 / SHA3-256 / SHA3-384 | ✅ 已实现/实测 |
| **M2** | 校验服务（平滑切换） | 文件校验 | SHA-256 → SHA3-256 运行时切换 | 配置驱动 `switchTo()`，接口零改动 | ✅ 已实现/实测 |
| **M3** | 持久化兼容 | 存储 | `VARCHAR(64)` | SHA3-256 兼容；SHA-384/SHA3-384 需 `VARCHAR(96)` | ✅ 已实现/实测 |
| **M4** | 过渡期双算法校验 | 滚动迁移 | SHA-256 存量 | SHA-256 + SHA3-256 并存，任一匹配即通过 | ✅ 已实现/实测 |
| **M5** | 性能对比 | 计算开销 | MD5/SHA-256 基线 | SHA-384/SHA3-256/SHA3-384 速度/CPU/内存 | ✅ 已实现/实测 |
| **M6** | 摘要尺寸增长 | 存储/格式 | 64 字符基线 | 96 字符（+50%）百分比 + 柱状图 | ✅ 已实现/实测 |

### 实测结果速览

| 验证项 | 结果 |
|---|---|
| 5 种算法 JCE 可用性（SUN provider） | ✅ 全部 `[ OK ]` |
| SHA-256 → SHA3-256 运行时切换（接口不变） | ✅ 支持，hex 长度一致，确定性通过 |
| 过渡期双算法并存校验（SHA-256 + SHA3-256） | ✅ 通过，支持滚动迁移 |
| SHA3-256 写入 VARCHAR(64) | ✅ `[ OK ]` |
| SHA3-384 / SHA-384 写入 VARCHAR(64) | ✅ 按预期 `[FAIL]`（断点 1 实证） |
| SHA3-384 写入扩容后 VARCHAR(96) | ✅ `[ OK ]` |
| 吞吐量对比（10 MB 稳态）：MD5 -52% / SHA-384 -58% / SHA3-256 -72% / SHA3-384 -79% | ✅ 已量化 |
| 摘要尺寸：SHA-384/SHA3-384 相对 SHA-256 增长 **+50%**（96 vs 64 字符） | ✅ 已量化 |

---

## 3. 组件版本配套关系

### 3.1 依赖矩阵（lib/ 下已内置）

| 组件 | 版本 | 作用 | 配套说明 |
|---|---|---|---|
| **commons-codec** | 1.22.1 | `DigestUtils` 摘要 API（完整性保护/文件校验） | 唯一运行依赖 |
| JDK | **27** | SUN provider 提供 MD5/SHA-256/SHA-384/SHA3-256/SHA3-384 | SHA3 需 JDK 9+ |

### 3.2 版本配套关系（关键约束）

```
commons-codec 1.22.1 ── DigestUtils.getDigest(String jceName)
                         └── 底层 MessageDigest 由 JDK SUN provider 提供
                               ├─ MD5 / SHA-256 / SHA-384：JDK 任意版本
                               └─ SHA3-256 / SHA3-384：⚠️ 需 JDK 9+（断点 2）
```

**版本敏感性提示**：
- `DigestUtils.getDigest()` 自 1.6 起存在，1.22.1 对上述 5 种算法名均支持。
- 若更换 commons-codec 版本，需确认 `SHA3-256` / `SHA3-384` 的 JCE 名称映射未变化。
- JDK 8 及以下无 SHA3 → 迁移目标退化为 SHA-384，或升级 JDK。

---

## 4. 迁移点 M1：算法清单定义层

**修改文件**：`src/PqcMigrationTest.java`（新增）

**修改点**：定义迁移前/迁移后算法的枚举，用 `AlgorithmFamily` 区分归属，是整份测试的"迁移清单"。

```java
// [PQC-MOD] 新增: 算法族标签（迁移前 / 迁移目标）
enum AlgorithmFamily {
    LEGACY("迁移前"),
    TARGET("迁移目标(PQC)");
    ...
}

// [PQC-MOD] 新增: 迁移前后算法清单（M1 核心）
enum ChecksumAlgorithm {
    MD5("MD5", 128, AlgorithmFamily.LEGACY),
    SHA_256("SHA-256", 256, AlgorithmFamily.LEGACY),
    // ── 迁移目标（现有算法长度翻倍或替换为 SHA3）──
    SHA_384("SHA-384", 384, AlgorithmFamily.TARGET),   // [PQC-MOD] 256→384 长度翻倍
    SHA3_256("SHA3-256", 256, AlgorithmFamily.TARGET), // [PQC-MOD] SHA3 替换，长度不变
    SHA3_384("SHA3-384", 384, AlgorithmFamily.TARGET); // [PQC-MOD] SHA3 + 长度翻倍
    ...
}
```

**说明**：枚举携带 JCE 名称、位长、归属族三类元数据，所有后续迁移点（M2–M6）均以该清单为数据源，保证"一次定义、处处一致"。

---

## 5. 迁移点 M2：校验服务层（平滑切换核心）

**修改文件**：`src/PqcMigrationTest.java`（新增）

**修改点**：`ChecksumService` 以构造参数/`switchTo()` 注入算法，`computeHex()` 走统一接口。**这是"平滑切换"的直接证据**——切换算法只改配置，调用方代码路径不变。

```java
// [PQC-MOD] 新增: 文件校验服务，算法仅通过配置指定
static final class ChecksumService {
    private ChecksumAlgorithm algorithm;

    ChecksumService(ChecksumAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    // [PQC-MOD] 修改点: 运行时按配置切换算法（平滑切换入口）
    void switchTo(ChecksumAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    // [PQC-MOD] 修改点: 统一计算接口 —— 切换算法后此方法体不变
    String computeHex(File file) throws Exception {
        MessageDigest md = DigestUtils.getDigest(algorithm.jceName());  // 按名称取算法
        try (InputStream in = Files.newInputStream(file.toPath())) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                md.update(buf, 0, n);   // 流式更新，适配任意文件大小
            }
        }
        return Hex.encodeHexString(md.digest());  // 统一 hex 输出
    }
}
```

**实测结论**：`SHA-256 → SHA3-256` 切换后，`computeHex()` 方法体零修改，hex 长度保持一致（64 字符），摘要确定性通过。

---

## 6. 迁移点 M3：持久化兼容层

**修改文件**：`src/PqcMigrationTest.java`（新增）

**修改点**：`ChecksumStore` 模拟数据库定长字段（`VARCHAR(n)`），检验新算法摘要能否直接写入既有存储——**这是迁移流程中最常见的阻碍点**。

```java
// [PQC-MOD] 新增: 模拟持久化定长字段（如 DB VARCHAR）
static final class ChecksumStore {
    private final String column;
    private final int capacity;
    private String stored = "";

    ChecksumStore(String column, int capacity) { ... }

    // [PQC-MOD] 修改点: 超长截断检测 —— 迁移阻碍的判定逻辑
    String save(String hex) {
        if (hex.length() > capacity) {
            return String.format(Locale.ROOT,
                    "[FAIL] 摘要长度 %d 超出字段容量 %d（%s）→ 写入截断/报错，迁移受阻", ...);
        }
        stored = hex;
        return String.format(Locale.ROOT,
                "[ OK ] 摘要长度 %d 可容纳于 %s（容量 %d）", ...);
    }
}
```

**实测结论**：
- SHA3-256（64 字符）→ `[ OK ]` 兼容原 `VARCHAR(64)`。
- SHA3-384 / SHA-384（96 字符）→ `[FAIL]` 超容，**迁移受阻**（断点 1）。
- 字段扩容到 `VARCHAR(96)` 后 → `[ OK ]`。

---

## 7. 迁移点 M4：过渡期双算法校验

**修改文件**：`src/PqcMigrationTest.java`（新增）

**修改点**：过渡期内新旧摘要并存，校验时"任一匹配即通过"，支撑**滚动迁移**（存量数据无需立即重算）。

```java
// [PQC-MOD] 新增: 过渡期双算法并存校验（滚动迁移）
ChecksumService oldVerifier = new ChecksumService(ChecksumAlgorithm.SHA_256);
ChecksumService newVerifier = new ChecksumService(ChecksumAlgorithm.SHA3_256);
String legacyStored = oldVerifier.computeHex(sample);   // 历史存量
String newStored    = newVerifier.computeHex(sample);   // 新写入

// [PQC-MOD] 修改点: 双算法并存校验 —— 任一匹配即通过
boolean ok = legacyStored.equalsIgnoreCase(incoming)
          || newStored.equalsIgnoreCase(incoming);
```

**实测结论**：双算法并存校验通过 → 支持平滑滚动迁移（存量数据与新增数据均可用）。

---

## 8. 迁移点 M5：性能对比（速度/CPU/内存）

**修改文件**：`src/PqcMigrationTest.java`（新增）

**修改点**：新增 `PerfResult` 模型与 `runPerformanceTest()`，对 4 档文件尺寸（1KB/64KB/1MB/10MB）逐算法测量墙钟时间、CPU 时间（`ThreadMXBean`）、堆内存增量、吞吐量。

```java
// [PQC-MOD] 新增: 性能测试 —— 4 档文件尺寸 × 5 种算法
static List<PerfResult> runPerformanceTest(ChecksumService svc, List<ChecksumAlgorithm> algos,
                                           long[] fileSizes, int[] iterCounts) throws Exception {
    ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
    MemoryMXBean memBean = ManagementFactory.getMemoryMXBean();
    ...
    for (int fi = 0; fi < fileSizes.length; fi++) {
        ...
        for (ChecksumAlgorithm algo : algos) {
            svc.switchTo(algo);
            // [PQC-MOD] 测量: CPU + 墙钟 + 内存快照
            long cpuStart = threadBean.getCurrentThreadCpuTime();
            long wallStart = System.nanoTime();
            svc.computeBatch(testFile, iter);
            long wallEnd = System.nanoTime();
            long cpuEnd = threadBean.getCurrentThreadCpuTime();
            ...
        }
    }
}
```

**实测结果（稳态 10 MB 档）**：

| 算法 | 耗时/次(ms) | 吞吐(MB/s) | 相对 SHA-256 | 内存(KB/op) |
|---|---|---|---|---|
| MD5 | 11.07 | 180.6 | **-51.8%** | 2457.6 |
| SHA-256（基线） | 5.34 | 374.5 | 0.0% | 2457.6 |
| SHA-384 | 12.81 | 156.2 | **-58.3%** | 2457.6 |
| SHA3-256 | 19.35 | 103.3 | **-72.4%** | 2457.6 |
| SHA3-384 | 24.90 | 80.3 | **-78.6%** | 2457.6 |

> 注：SHA3 系列吞吐相对 SHA-256 下降 72%~79%；MD5 与 SHA-256 同为经典基线；内存占用各算法持平（流式处理，无显著差异）。

---

## 9. 迁移点 M6：摘要尺寸增长对比

**修改文件**：`src/PqcMigrationTest.java`（新增）

**修改点**：新增百分比数值表 + ASCII 柱状图 + 存储空间估算，量化"长度翻倍"对存储的影响。

```java
// [PQC-MOD] 新增: 摘要尺寸百分比表 + ASCII 柱状图 + 存储估算
static void printDigestSizeComparison(ChecksumAlgorithm baseline) {
    ...
    String bar = "█".repeat(filled) + "░".repeat(Math.max(0, empty));  // [PQC-MOD] 柱状图
    ...
}
```

**实测结果（以 SHA-256 为基准）**：

| 算法 | 位长(bits) | hex长度(字符) | 增长 | 百分比 |
|---|---|---|---|---|
| MD5 | 128 | 32 | -32 | **-50.0%** |
| SHA-256（基线） | 256 | 64 | +0 | 0.0% |
| SHA-384 | 384 | 96 | +32 | **+50.0%** |
| SHA3-256 | 256 | 64 | +0 | 0.0% |
| SHA3-384 | 384 | 96 | +32 | **+50.0%** |

**存储估算（每 1000 万条记录）**：SHA-256 占 610.4 MB；SHA-384/SHA3-384 占 915.5 MB（**+305 MB，+50%**）。

---

## 10. 迁移断点与解决方案

> 断点 = 迁移过程中发现的阻碍/风险点。本节给出根因 + 代码侧对策。

### 断点 1：摘要长度翻倍 → 定长存储字段超容

- **根因**：SHA-384 / SHA3-384 输出 96 个 hex 字符，超出 SHA-256 配套的 `VARCHAR(64)` 定长字段，写入会截断/报错。
- **实证**：`ChecksumStore.save(SHA3-384)` → `[FAIL] 摘要长度 96 超出字段容量 64（VARCHAR(64)）`。
- **解决方案**（二选一）：
  1. **选 SHA3-256**（长度不变，零存储改动，推荐）——兼容既有 `VARCHAR(64)`；
  2. 选 SHA-384 / SHA3-384 时**扩容字段**至 `VARCHAR(96)`，并评估索引/分区策略。
- **报告回链**：见 `README.md §七 断点 1`。

### 断点 2：SHA3 依赖 JDK 9+

- **根因**：`SHA3-256`/`SHA3-384` 由 JDK SUN provider 提供，JDK 8 及以下 `MessageDigest.getInstance("SHA3-256")` 抛 `NoSuchAlgorithmException`。
- **实证**：`availability()` 对不可用算法返回 `[FAIL]`。
- **解决方案**：JDK < 9 时迁移目标退化为 **SHA-384**（长度翻倍方案，无 JDK 版本门槛），或升级 JDK。

### 断点 3：同长度异值 → 存量摘要全部失效

- **根因**：SHA3-256 与 SHA-256 同为 64 字符但取值不同，历史校验记录无法与新算法摘要匹配。
- **实证**：迁移前 `SHA-256` 与切换后 `SHA3-256` 摘要值不同。
- **解决方案**：过渡期**双算法并存校验**（M4），任一匹配即通过，配合滚动重算存量数据。

---

## 11. 工程结构

```
Apache_Commons_CodeC_PQC/
├── lib/commons-codec-1.22.1.jar   # 唯一依赖
├── src/PqcMigrationTest.java       # 迁移测试 Demo（单文件，M1–M6 全部实现）
├── reports/                        # 本报告（.md + .html）
├── build.ps1                       # 编译脚本
├── run-all.ps1                     # 一键运行
└── README.md
```

---

## 12. 结论与实施路线

### 结论

1. **切换流程无阻碍（接口层）**：Commons Codec `DigestUtils` 按名称取算法，业务代码只需改算法名配置，`computeHex()` 等调用方代码**零修改** → **支持平滑切换**。
2. **输出格式完全兼容**：统一 hex 字符串，下游解析无需改动。
3. **唯一实质性阻碍是存储层**：384 位目标算法摘要翻倍（64→96 字符），需扩容定长字段；改选 SHA3-256 则完全规避。
4. **性能代价明确**：SHA3 系列吞吐较 SHA-256 下降约 40~79%，内存持平；完整性校验为低频操作，通常可接受。

### 推荐迁移路线

```
SHA-256（现状）
  ├─ 推荐: → SHA3-256（长度不变，零存储改动，平滑切换 + 双算法过渡）
  └─ 备选: → SHA-384 或 SHA3-384（抗量子余量更大，需扩容字段 VARCHAR(96)，成本 +50%）
```
