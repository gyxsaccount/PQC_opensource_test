# Apache Commons Codec 后量子（PQC）迁移测试

Apache Commons Codec（`DigestUtils`）在**完整性保护 / 文件校验**场景下的后量子迁移测试工程：验证从现有算法（MD5 / SHA-256）切换抗量子算法（SHA-384 / SHA3-256 / SHA3-384）的流程是否存在阻碍、能否平滑切换，并对比迁移前后的计算速度、CPU/内存开销与摘要尺寸增长。

- 详细技术报告（含每个代码修改点、版本配套、迁移断点根因）：[CommonsCodec_PQC_迁移测试报告.md](reports/CommonsCodec_PQC_迁移测试报告.md)
- 可视化 HTML 报告（多色代码高亮）：[CommonsCodec_PQC_迁移测试报告.html](reports/CommonsCodec_PQC_迁移测试报告.html)

## 目录结构

```
Apache_Commons_CodeC_PQC/
├── lib/                        # 依赖 jar（见「依赖安装」）
│   └── commons-codec-1.22.1.jar
├── src/
│   └── PqcMigrationTest.java   # 迁移测试 Demo（单文件，无包名）
├── reports/                    # 迁移测试报告（.md + .html）
├── logs/                       # 运行日志（run-all.ps1 生成）
├── build.ps1                   # 编译脚本（纯 javac，无需 Maven）
├── run-all.ps1                 # 一键编译 + 运行 + 生成日志
├── Apache_Commons_CodeC_PQC.iml  # IntelliJ IDEA 工程文件
└── README.md
```

---

## 一、环境要求

| 项目 | 要求 | 说明 |
|---|---|---|
| 操作系统 | Windows（本工程在 Windows x86-64 验证） | 脚本为 PowerShell |
| **JDK** | **9+**，推荐 **JDK 27**（本工程在 JDK 27 验证） | SHA3 系列需 JDK 9+ 才有 JCE 实现（SUN provider） |
| commons-codec | **1.22.1**（`lib/` 已内置） | `DigestUtils.getDigest()` 自 1.6 起支持按名称取摘要算法 |
| PowerShell | 5.1+ | 运行 `build.ps1` / `run-all.ps1` |
| Git（可选） | 任意 | 仅版本管理使用，运行测试不需要 |

> **JDK 版本敏感性**（详见断点 2）：
> - **JDK 9+**：`SHA3-256` / `SHA3-384` 可用（SUN provider）。
> - **JDK 8-**：JCE 无 SHA3 实现，`MessageDigest.getInstance("SHA3-256")` 抛 `NoSuchAlgorithmException` → 只能选用 SHA-384 作为迁移目标。

---

## 二、依赖安装

本项目采用「纯 javac + 本地 jar 目录」的方式，**无需 Maven**。`lib/` 已内置全部依赖。

### 依赖清单（lib/ 下已内置）

| 组件 | 版本 | 用途 |
|---|---|---|
| commons-codec | 1.22.1 | `DigestUtils`（文件校验/完整性保护的核心 API） |

### 重新安装依赖（可选）

如需从 Maven Central 重新下载：

```powershell
# 方式1：直接使用内置 lib/（推荐，无需任何操作）
# 方式2：Maven 下载到 lib/
mvn dependency:copy-dependencies -DoutputDirectory=lib
# 方式3：手工下载
# https://repo1.maven.org/maven2/commons-codec/commons-codec/1.22.1/commons-codec-1.22.1.jar
```

---

## 三、运行

```powershell
# 1. 编译（纯 javac，输出到 out/）
powershell -ExecutionPolicy Bypass -File build.ps1

# 2. 一键运行（含日志，写入 logs/run.log）
powershell -ExecutionPolicy Bypass -File run-all.ps1
```

如需手动运行：

```powershell
javac -encoding UTF-8 -cp "lib\commons-codec-1.22.1.jar" -d out src\PqcMigrationTest.java
java  -cp "out;lib\commons-codec-1.22.1.jar" PqcMigrationTest
```

> 若 Windows 控制台出现中文乱码，请先 `chcp 65001`（切到 UTF-8 代码页）再运行，或在 IntelliJ 中运行。

---

## 四、预期输出

程序依次输出 7 个测试段，末尾给出「迁移评估结论」。关键判定锚点如下：

### 1) 算法可用性 —— 应全部 `[ OK ]`

```
  [ OK ] MD5 可用 (Provider=SUN)
  [ OK ] SHA-256 可用 (Provider=SUN)
  [ OK ] SHA-384 可用 (Provider=SUN)
  [ OK ] SHA3-256 可用 (Provider=SUN)
  [ OK ] SHA3-384 可用 (Provider=SUN)
```

### 2) 摘要(hex)与长度对比 —— SHA3-256 与 SHA-256 同为 64 字符，SHA-384/SHA3-384 为 96 字符

```
  [迁移前] MD5       bits=128  hex_len=32  <32位hex>
  [迁移前] SHA_256   bits=256  hex_len=64  <64位hex>
  [迁移目标(PQC)] SHA_384   bits=384  hex_len=96  <96位hex>
  [迁移目标(PQC)] SHA3_256  bits=256  hex_len=64  <64位hex>
  [迁移目标(PQC)] SHA3_384  bits=384  hex_len=96  <96位hex>
```

### 3) 持久化定长字段 —— SHA3-256 直接兼容 VARCHAR(64)；SHA-384/SHA3-384 需扩容 VARCHAR(96)

```
  SHA3_256: [ OK ] 摘要长度 64 可容纳于 VARCHAR(64)
  SHA3_384: [FAIL] 摘要长度 96 超出字段容量 64（VARCHAR(64)）→ 写入截断/报错，迁移受阻
  SHA_384:  [FAIL] 摘要长度 96 超出字段容量 64（VARCHAR(64)）→ 写入截断/报错，迁移受阻
  [迁移目标] 字段扩容到 VARCHAR(96) 后: [ OK ] 摘要长度 96 可容纳于 VARCHAR(96)
```

### 4) 平滑切换 —— 接口级平滑切换「支持」、hex 长度一致「true」、确定性「是」

```
  调用方仍走同一 computeHex(File) 接口 => 接口级平滑切换: 支持
  hex 长度保持一致(true): 无存储字段影响
  摘要确定性(重复计算一致): 是
```

### 5) 过渡期双算法兼容 —— 滚动迁移「通过」

```
  双算法并存校验(任一匹配即通过): 通过
  => 支持平滑滚动迁移（存量数据与新增数据均可用）
```

### 6) 性能对比 —— 输出各文件尺寸下每算法的耗时/CPU/吞吐/内存，及相对 SHA-256 的变化率

```
  文件大小: 10 MB | 迭代: 5 次
    算法              耗时/次(ms)  CPU/次(ms)     吞吐(MB/s)  内存(KB/op)         相对基线
    MD5               11.071      9.375       180.64     2457.6       -51.8%
    SHA-256            5.340      6.250       374.52     2457.6        +0.0%
    SHA-384           12.808     12.500       156.16     2457.6       -58.3%
    SHA3-256          19.353     18.750       103.34     2457.6       -72.4%
    SHA3-384          24.904     25.000        80.31     2457.6       -78.6%
```

### 7) 摘要尺寸增长 —— 百分比表 + 柱状图 + 存储估算（SHA-384/SHA3-384 相对 SHA-256 增长 +50%）

```
  SHA_384        384         96            +32                  +50.0%
  SHA3_384       384         96            +32                  +50.0%
```

### 结论段 —— 列出 4 个需关注点（均为「摘要长度变化导致的存储字段扩容」问题）

```
=== 迁移评估结论 ===
发现 4 个需关注点（阻碍/风险）:
  - 摘要长度变化: SHA-384 hex 长度 64 -> 96（存储/格式需评估）
  - 摘要长度变化: SHA3-384 hex 长度 64 -> 96（存储/格式需评估）
  - 定长字段无法容纳: SHA3-384
  - 定长字段无法容纳: SHA-384
```

**判定标准**：第 1/4/5 段无 `[FAIL]`；第 3 段 SHA3-256 为 `[OK]`、SHA-384/SHA3-384 为预期 `[FAIL]`（属存储层断点实证）；程序以「迁移评估结论」收尾且无未预期的 `Exception`。

---

## 五、严格性说明

本工程定位为**迁移可行性验证 Demo**，以下简化项在使用到生产环境前必须升级：

| 项 | 现状 | 生产要求 |
|---|---|---|
| **性能测试方法** | 轻量自研微基准（`System.nanoTime` + `ThreadMXBean`），每尺寸仅 5~500 次迭代 | 生产用 JMH：多轮预热 + 统计收敛 + 多隔离场景，消除 JIT/GC 抖动 |
| **吞吐量小文件失真** | < 1 MB 时单次迭代为亚毫秒级，受 JIT/GC/测量开销干扰（如 1KB 吞吐异常偏高/偏低） | 关注 **10 MB 档位**（稳态吞吐），小尺寸仅供趋势参考 |
| **内存测量** | 堆快照增量按迭代均摊（`MemoryMXBean.getHeapMemoryUsage`），受 GC 时机影响 | 生产用 `-Xmx` 固定堆 + JMH `-prof gc` 精确统计 |
| **定长字段模拟** | 内存中模拟 DB `VARCHAR(n)` | 生产需实测目标数据库列类型（`char`/`varbinary`）实际截断行为 |
| **校验流程** | 同一 `computeHex(File)` 接口按配置切算法，双算法并存校验 | 生产需补充密钥/盐无关性、编码一致性（hex 大小写）规范 |
| **MD5 使用** | 仅作迁移前基线对比（MD5 本身已不安全，非量子问题） | 生产禁用 MD5，直接迁移 SHA-256 或更高 |

**已验证范围**：5 种算法的 JCE 可用性、同一文件摘要确定性、hex 输出格式一致性、运行时按配置切换算法（接口零改动）、过渡期双算法并存校验、4 档文件尺寸下的速度/CPU/内存对比、摘要尺寸增长百分比与存储影响估算。

**未覆盖范围**：真实数据库定长列、真实文件系统 I/O（本测试按字节块流式读取）、多线程并发校验、JMH 级精确基准、SHA-512/128 位以上更多目标算法。

---

## 六、版本记录

| 版本 | 日期 | 变更 |
|---|---|---|
| 1.0.0 | 2026-10-15 | 初始版本：迁移流程测试（可用性/平滑切换/滚动迁移/存储兼容）+ 性能对比（速度/CPU/内存）+ 摘要尺寸增长（百分比/柱状图/存储估算）、可视化报告（.md + .html） |

### 配套组件版本（当前已验证组合）

| 组件 | 版本 |
|---|---|
| JDK | 27 (build 27+35-2325) |
| commons-codec | 1.22.1 |

---

## 七、断点说明

> 完整根因分析与解决代码见：[迁移测试报告 §9 迁移断点与解决方案](reports/CommonsCodec_PQC_迁移测试报告.md#9-迁移断点与解决方案)

| # | 断点 | 一句话说明 | 解决方案 |
|---|---|---|---|
| 1 | [摘要长度翻倍 → 定长存储字段超容](reports/CommonsCodec_PQC_迁移测试报告.md#断点-1摘要长度翻倍--定长存储字段超容) | SHA-384/SHA3-384 输出 96 个 hex 字符，超出原 SHA-256 配套的 `VARCHAR(64)` | 选 SHA3-256（长度不变，零存储改动）或对 384 位目标扩容字段至 `VARCHAR(96)` |
| 2 | [SHA3 依赖 JDK 9+](reports/CommonsCodec_PQC_迁移测试报告.md#断点-2sha3-依赖-jdk-9) | JDK 8 的 JCE 无 SHA3 实现，`getInstance("SHA3-256")` 抛异常 | JDK<9 退而选用 SHA-384 作为迁移目标，或升级 JDK |
| 3 | [同长度异值 → 存量摘要全部失效](reports/CommonsCodec_PQC_迁移测试报告.md#断点-3同长度异值--存量摘要全部失效) | SHA3-256 与 SHA-256 同为 64 字符但取值不同，历史校验记录不兼容 | 过渡期双算法并存校验（任一匹配即通过），滚动重算存量 |

---

## License

本项目为后量子密码迁移测试工程，依赖组件版权归其各自作者（Apache Commons / Oracle）。
