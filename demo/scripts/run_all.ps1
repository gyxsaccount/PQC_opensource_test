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