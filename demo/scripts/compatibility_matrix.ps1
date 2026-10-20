# ============================================================================
# compatibility_matrix.ps1  --  迁移兼容性矩阵测试主入口
# 用途: 加载基线 + PQ 目标算法集 → 模拟 2 种模式 x 4 场景 → 输出断点报告
# 模式:
#   M1 (soft):  新服务端保留经典回退 → 无断点 (推荐做法)
#   M2 (strict):新服务端仅 PQ 算法  → C2 断点 (检测迁移阻碍)
# ============================================================================
[CmdletBinding()]
param(
    [string]$BaselineFile  = "D:\PQC-test\libSSH2\demo\results\baseline_pre_migration.json",
    [string]$PQTargetFile  = "D:\PQC-test\libSSH2\demo\scripts\pq_target_algorithms.json",
    [string]$PQStrictFile  = "D:\PQC-test\libSSH2\demo\scripts\pq_target_strict.json",
    [string]$OutFile       = "D:\PQC-test\libSSH2\demo\results\compatibility_matrix.json"
)

$ErrorActionPreference = "Continue"

. "D:\PQC-test\libSSH2\demo\scripts\negotiation_simulator.ps1"

# ---- 1. 加载算法集 ----
if (-not (Test-Path $BaselineFile)) {
    Write-Warning "基线文件不存在, 请先运行 capture_baseline.ps1"
    & "D:\PQC-test\libSSH2\demo\scripts\capture_baseline.ps1"
}

$baselineJson = Get-Content $BaselineFile -Raw -Encoding UTF8 | ConvertFrom-Json
$pqTargetJson  = Get-Content $PQTargetFile -Raw -Encoding UTF8 | ConvertFrom-Json
$pqStrictJson  = Get-Content $PQStrictFile -Raw -Encoding UTF8 | ConvertFrom-Json

function ConvertTo-Hashtable($obj) {
    $ht = @{}
    $obj.PSObject.Properties | ForEach-Object { $ht[$_.Name] = [string[]]$_.Value }
    return $ht
}

$baselineClient = ConvertTo-Hashtable $baselineJson.client
$baselineServer = @{
    kex     = @($baselineJson.server_default.kex)
    hostkey = @($baselineJson.server_default.hostkey)
    cipher  = @("aes256-gcm@openssh.com","aes128-gcm@openssh.com","chacha20-poly1305@openssh.com","aes256-ctr","aes192-ctr","aes128-ctr")
    mac     = @("hmac-sha2-256-etm@openssh.com","hmac-sha2-512-etm@openssh.com","hmac-sha2-256","hmac-sha2-512")
}

$pqSoftClient  = ConvertTo-Hashtable $pqTargetJson
$pqSoftServer  = ConvertTo-Hashtable $pqTargetJson

$pqStrictClient = ConvertTo-Hashtable $pqStrictJson
$pqStrictServer = ConvertTo-Hashtable $pqStrictJson

# ---- 2. 运行双模式矩阵 ----
Write-Host "== 迁移兼容性矩阵测试 ==" -ForegroundColor Cyan

# M1: 软迁移 (服务端保留经典回退)
Write-Host "--- 模式 M1: 软迁移 (经典+PQ 混合) ---" -ForegroundColor Yellow
$resultsM1 = Measure-CompatibilityMatrix `
    -BaselineClient $baselineClient -BaselineServer $baselineServer `
    -PQClient $pqSoftClient -PQServer $pqSoftServer `
    -ModeLabel "M1-soft"

# M2: 硬迁移 (服务端仅 PQ)
Write-Host "--- 模式 M2: 硬迁移 (服务端仅 PQ) ---" -ForegroundColor Yellow
$resultsM2 = Measure-CompatibilityMatrix `
    -BaselineClient $baselineClient -BaselineServer $baselineServer `
    -PQClient $pqStrictClient -PQServer $pqStrictServer `
    -ModeLabel "M2-strict"

$allResults = @($resultsM1) + @($resultsM2)

# ---- 3. 输出 ----
$report = [ordered]@{
    title             = "libSSH2 后量子迁移 — 兼容性矩阵报告"
    generated_at      = (Get-Date).ToUniversalTime().ToString("o")
    baseline_tool     = $baselineJson.tool_version
    configuration     = @(
        [ordered]@{ mode="M1-soft";  note="推荐: 服务端保留经典算法回退 (渐进迁移)"; target_scope=$pqTargetJson.scope }
        [ordered]@{ mode="M2-strict"; note="严格: 服务端仅启用 PQ 算法 (硬迁移, 用于断点检测)"; target_scope=$pqStrictJson.scope }
    )
    results           = @($allResults)
    summary           = @{}
}

$breakpointCases = @($allResults | Where-Object { $_.has_breakpoint })
$safeCases       = @($allResults | Where-Object { -not $_.has_breakpoint })

$report.summary = [ordered]@{
    total_scenarios      = $allResults.Count
    breakpoint_scenarios = $breakpointCases.Count
    safe_scenarios       = $safeCases.Count
    breakpoint_details   = @($breakpointCases | ForEach-Object {
        [ordered]@{
            scenario   = $_.scenario
            categories = $_.breakpoints
        }
    })
}

$dir = Split-Path -Parent $OutFile
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force > $null }
$report | ConvertTo-Json -Depth 6 | Set-Content -Path $OutFile -Encoding UTF8

Write-Host ("矩阵结果已写入: {0}" -f $OutFile) -ForegroundColor Green
Write-Host ("  总场景数: {0} (双模式 x 4 = {1})" -f $allResults.Count, $allResults.Count) -ForegroundColor Yellow
Write-Host ("  断点场景: {0}" -f $breakpointCases.Count) -ForegroundColor Red
Write-Host ("  安全场景: {0}" -f $safeCases.Count) -ForegroundColor Green

foreach ($bp in $breakpointCases) {
    Write-Host ("  [断点] {0} → 失败类别: {1}" -f $bp.scenario, ($bp.breakpoints -join ", ")) -ForegroundColor Red
}
if ($breakpointCases.Count -eq 0) {
    Write-Host "  （提示: 无断点是因为当前服务端配置保留了经典回退；如需检测断点，请切换为 strict 模式）" -ForegroundColor Gray
}