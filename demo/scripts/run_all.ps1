# ============================================================================
# run_all.ps1  --  Demo 总编排
#   1. 迁移前基线采集
#   2. 兼容性断点矩阵 (M1 软迁移 + M2 硬迁移)
#   3. 真实互通测试 (连 github.com 抓协商)
#   4. 算法健康审计 (弱算法排查)
#   5. Markdown 报告 + HTML 可视化报告
# ============================================================================
[CmdletBinding()]
param([switch]$SkipBaseline, [switch]$SkipLive)

$ErrorActionPreference = "Continue"
$root = "D:\PQC-test\libSSH2\demo"

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  libSSH2 后量子迁移测试 Demo" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# ---------- 1. 迁移前基线 ----------
if (-not $SkipBaseline) {
    & "$root\scripts\capture_baseline.ps1"
} else {
    Write-Host "[-] 跳过基线采集" -ForegroundColor Yellow
}
Write-Host ""

# ---------- 2. 断点矩阵 (双模式) ----------
& "$root\scripts\compatibility_matrix.ps1"

# ---------- 3. 真实互通测试 ----------
if (-not $SkipLive) {
    Write-Host ""
    Write-Host "--- 真实互通测试 ---" -ForegroundColor Cyan
    & "$root\scripts\live_negotiation.ps1" -Target github.com -Port 22 -User git -TimeoutSec 15
} else {
    Write-Host "[-] 跳过真实互通测试" -ForegroundColor Yellow
}

# ---------- 4. 算法健康审计 ----------
Write-Host ""
Write-Host "--- 算法健康审计 ---" -ForegroundColor Cyan
& "$root\scripts\algorithm_audit.ps1"

# ---------- 5. Markdown 报告 ----------
Write-Host ""
Write-Host "--- 生成 Markdown 报告 ---" -ForegroundColor Cyan
$report = Get-Content "$root\results\compatibility_matrix.json" -Raw -Encoding UTF8 | ConvertFrom-Json

$md = @()
$md += "# libSSH2 后量子迁移测试报告"
$md += ""
$md += "生成时间: $($report.generated_at)"
$md += "基线工具: $($report.baseline_tool)"
$md += ""
$md += "## 配置模式"
$md += ""
foreach ($cfg in $report.configuration) {
    $md += "- **$($cfg.mode)**: $($cfg.note) (目标: $($cfg.target_scope))"
}
$md += ""
$md += "## 汇总"
$md += ""
$md += "| 指标 | 值 |"
$md += "|---|---|"
$md += "| 总场景数 | $($report.summary.total_scenarios) |"
$md += "| 断点场景数 | $($report.summary.breakpoint_scenarios) |"
$md += "| 安全场景数 | $($report.summary.safe_scenarios) |"
$md += ""
$md += "## 逐场景协商结果"
$md += ""
$md += "| 场景 | KEX | Hostkey | Cipher | MAC | 断点 |"
$md += "|---|---|---|---|---|---|"
$i = 0
foreach ($r in $report.results) {
    $i++
    $mode = if ($i -le 4) { "M1" } else { "M2" }
    $bp = if ($r.has_breakpoint) { "**$($r.breakpoints -join ', ')**" } else { "无" }
    $md += "| **$mode-$($r.scenario)** | $($r.kex) | $($r.hostkey) | $($r.cipher) | $($r.mac) | $bp |"
}
$md += ""
$md += "### 如何阅读这张表 (详细说明)"
$md += ""
$md += "#### 表头 (4 列算法 + 1 列结果)"
$md += ""
$md += "| 列 | 含义 | 判定 |"
$md += "|---|---|---|"
$md += "| **KEX** | 密钥交换算法: 如何协商出加密密钥 (本表关注是否选出后量子混合 KEX) | `matched: <算法>` = 协商成功 |"
$md += "| **Hostkey** | 主机密钥算法: 如何验证服务器身份 | `MISMATCH` = 无共同算法 = 断点 |"
$md += "| **Cipher** | 对称加密算法: 传输数据加密 | |"
$md += "| **MAC** | 完整性校验算法: 防篡改 | |"
$md += "| **断点** | 4 类中协商失败的类别 | `无` = 握手成功; 列出类别 = 连接失败 |"
$md += ""
$md += "> **核心规则**: SSH 握手必须 4 类算法每类都选出一个双方共有的算法。任一类别 `MISMATCH` → 连接直接失败。"
$md += ""
$md += "#### 场景名含义: 三种部署类型 (M1/M2 × C1-C4)"
$md += ""
$md += "**每个端点的部署类型** (由算法集自动识别, 显示在场景标签的 `[ ]` 里):"
$md += ""
$md += "| 类型 | 含义 | 算法组成 |"
$md += "|---|---|---|"
$md += "| **传统** | 只用经典算法, 无任何后量子 | 纯 ECDH/DH + RSA/ECDSA/Ed25519 |"
$md += "| **混合** | 经典 + 后量子**同时部署** (渐进迁移) | `mlkem768x25519` + `curve25519` 等并存 |"
$md += "| **纯后量子** | **只**用后量子算法, 删光经典 (硬迁移) | 仅 `mlkem768x25519` + `ml-dsa-44` |"
$md += ""
$md += "**M1 / M2 = 迁移模式**:"
$md += ""
$md += "- **M1 (软迁移)**: 新服务端 = **混合** (经典 + 后量子同时保留, 不伤旧客户端)"
$md += "- **M2 (硬迁移)**: 新服务端 = **纯后量子** (删光经典算法, 会切断旧客户端)"
$md += ""
$md += "**C1-C4 = 客户端 × 服务端的 4 种组合** (场景标签直接写明双方类型):"
$md += ""
$md += "| 代号 | 实际标签 | 一句话 |"
$md += "|---|---|---|"
$md += "| C1 | 客户端[传统] → 服务端[传统] | 迁移前环境, 双方纯经典 |"
$md += "| C2 | 客户端[传统] → 服务端[混合/纯后量子] | 老客户端连新服务端 |"
$md += "| C3 | 客户端[混合/纯后量子] → 服务端[传统] | 新客户端连老服务端 |"
$md += "| C4 | 客户端[混合/纯后量子] → 服务端[混合/纯后量子] | 双方都是新环境 |"
$md += ""
$md += "> 场景标签是**自动生成**的: 按实际算法集识别 `[传统]/[混合]/[纯后量子]`, 不再用笼统的新旧表述。"
$md += ""
$md += "#### 单元格值怎么读"
$md += ""
$md += "- `matched: curve25519-sha256` = 双方协商成功, 选出了该算法 (客户端offer与服务端offer第一个交集)"
$md += "- `MISMATCH` = 该类别双方**无共同算法**, 握手失败"
$md += "- 带 `mlkem` / `sntrup` 的算法 = **后量子混合算法** (迁移目标)"
$md += ""
$md += "#### 四行关键解读 (对应本报告实际输出)"
$md += ""
$md += "| 场景 | 白话解读 | 结论 |"
$md += "|---|---|---|"
$md += "| **M1-C2** 客户端[传统] → 服务端[混合] | 老客户端只会经典, 混合服务端退一步用经典算法回应 | 软迁移下老客户端不受影响 = 向后兼容 ✅ |"
$md += "| **M1-C4** 客户端[混合] → 服务端[混合] | 双方都带后量子, 选出 `mlkem768x25519-sha256` + `ssh-ed25519+ml-dsa-44` | 后量子算法真正生效 = 迁移目标达成 🎉 |"
$md += "| **M2-C2** 客户端[传统] → 服务端[纯后量子] | 老客户端只会经典, 服务端只留后量子, 无交集 | **硬迁移切断所有老客户端** = 最大断点 ❌ |"
$md += "| **M2-C3** 客户端[纯后量子] → 服务端[传统] | 客户端只发后量子, 老服务端全不认 | 纯后量子客户端必须保留经典兜底才能连老服务端 ❌ |"
$md += ""
$md += "#### 核心结论"
$md += ""
$md += "> 盯三件事: ① 有没有 `MISMATCH` (有=断点=连不上); ② M1 全绿 → 渐进迁移是安全路径;"
$md += "> ③ M2 出现断点 → 激进迁移会伤老客户端, 必须等客户端全升级后才能用。"
$md += ""
$md += "**推荐采用 M1 软迁移 (永远有回退、无断点); M2 硬迁移只在所有客户端升级完毕后使用。**"
$md += ""
$md += "## 断点详情"
$md += ""
if ($report.summary.breakpoint_scenarios -gt 0) {
    foreach ($bp in $report.summary.breakpoint_details) {
        $md += "- **$($bp.scenario)**: 失败类别 = $($bp.categories -join ', ')"
    }
    $md += ""
    $md += "### 断点分析"
    $md += ""
    $md += "| 断点分类 | 对应案例 | 解释 |"
    $md += "|---|---|---|"
    $md += "| KEX | M2-C2 | 旧客户端不认识 `mlkem768x25519-sha256`, 服务端无经典回退 - 无共同 KEX |"
    $md += "| Hostkey | M2-C2 | 旧客户端不认识 `ssh-ed25519+ml-dsa-44`, 服务端无纯 `ssh-ed25519` - 无共同签名 |"
    $md += '| Cipher/MAC | - | 若保持 `aes256-gcm` / `hmac-sha2-256`, 新旧两端通常无断点 |'
    $md += ""
    $md += "> 断点消除策略: 迁移过渡期服务端必须保留经典算法双轨运行 (`KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,...`)。"
} else {
    $md += "无断点, 当前迁移路径平滑 (新服务端保留了经典回退)。"
    $md += ""
    $md += "> 如需检测断点: 使用 `pq_target_strict.json` 做 PQ-only 测试 (见模式 M2)。"
}
$md += ""
$md += "## 自实现代码位置"
$md += ""
$md += "| 文件 | 功能 |"
$md += "|---|---|"
$md += "| `self_implemented/hybrid_kex.c/.h` | ML-KEM-768 + X25519 混合 KEX |"
$md += "| `self_implemented/hybrid_signature.c/.h` | ML-DSA-44 + Ed25519 混合签名 |"
$md += "| `self_implemented/libssh2_pq.patch` | libssh2 集成补丁 |"
$md += ""
$md += "详见 `VERSION_MATRIX.md`(版本清单) 和 `BREAKPOINTS.md`(断点分析)。"

$mdPath = "$root\results\report.md"
$md -join "`n" | Set-Content -Path $mdPath -Encoding UTF8
Write-Host "Markdown 报告已生成: $mdPath" -ForegroundColor Green

# ---------- 6. HTML 报告 ----------
Write-Host ""
Write-Host "--- 生成 HTML 报告 ---" -ForegroundColor Cyan
& "$root\scripts\generate_html_report.ps1"

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Demo 完成! 查看结果:" -ForegroundColor Cyan
Write-Host "    JSON:     $root\results\*.json" -ForegroundColor Green
Write-Host "    Markdown: $root\results\report.md" -ForegroundColor Green
Write-Host "    HTML:     $root\results\report.html (自动弹出浏览器)" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Cyan