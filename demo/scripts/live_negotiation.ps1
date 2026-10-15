# ============================================================================
# live_negotiation.ps1  --  真实互通测试: 连远程 SSH 服务端抓协商日志
# 用途: 用 ssh -vvv 连接真实服务端, 捕获 KEXINIT 交换, 解析 client offer、
#       server offer 和最终协商结果, 输出结构化 JSON + 与矩阵预测对比。
#
# 依赖: 本机 OpenSSH 客户端 (ssh.exe)
# 输出: results/live_negotiation.json
# ============================================================================
[CmdletBinding()]
param(
    [string]$Target        = "github.com",
    [int]$Port             = 22,
    [string]$User          = "git",
    [string]$OutDir        = "D:\PQC-test\libSSH2\demo\results",
    [int]$TimeoutSec       = 20,
    [switch]$SkipMatrixCheck
)

$ErrorActionPreference = "Continue"

# ---- 1. 运行 ssh -vvv 并捕获输出 ----
Write-Host "== 真实互通测试: $User@$Target`:$Port ==" -ForegroundColor Cyan

$sshArgs = @(
    "-vvv",
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "UserKnownHostsFile=NUL",
    "-o", "ConnectTimeout=5",
    "-p", "$Port",
    "$User@$Target"
) -join " "

try {
    $rawOutput = & cmd /c "ssh $sshArgs 2>&1"
} catch {
    Write-Warning "ssh 执行异常: $($_.Exception.Message)"
    $rawOutput = ""
}

if (-not $rawOutput -or $rawOutput -match "Connection timed out") {
    Write-Error "未捕获到协商输出 (连接超时或目标不可达)"
    return
}

# ---- 2. 解析协商日志 ----
# 从 -vvv 输出中提取 "debug2: KEX algorithms: ..." 与 "debug1: kex: ..." 行
$kexLines = $rawOutput -split "`r?`n" | Where-Object { $_ -match "debug[123]:\s+(KEX|kex|host key|peer server|local client|first_kex)" }

$clientKex = ""
$clientHostkey = ""
$serverKex = ""
$serverHostkey = ""
$inClient = $false
$inServer = $false
$negotiated = [ordered]@{
    kex = ""; hostkey = ""; cipher = ""; mac = ""; cipher_cs = ""; mac_cs = ""
}

foreach ($line in $kexLines) {
    # 切换上下文: local client KEXINIT -> 客户端 offer 段
    if ($line -match "local client KEXINIT proposal") { $inClient = $true; $inServer = $false; continue }
    if ($line -match "peer server KEXINIT proposal")  { $inServer = $true;  $inClient = $false; continue }
    if ($line -match "kex_choose_conf|will use strict") { $inClient = $false; $inServer = $false }

    if ($inClient) {
        if ($line -match "debug2:\s+KEX algorithms:\s+(.+)")          { $clientKex = $matches[1].Trim() }
        elseif ($line -match "debug2:\s+host key algorithms:\s+(.+)") { $clientHostkey = $matches[1].Trim() }
    }
    elseif ($inServer) {
        if ($line -match "debug2:\s+KEX algorithms:\s+(.+)")          { $serverKex = $matches[1].Trim() }
        elseif ($line -match "debug2:\s+host key algorithms:\s+(.+)") { $serverHostkey = $matches[1].Trim() }
    }

    # 最终协商结果
    if ($line -match 'debug1:\s+kex: algorithm:\s+(.+)')              { $negotiated.kex = $matches[1].Trim() }
    elseif ($line -match 'debug1:\s+kex: host key algorithm:\s+(.+)') { $negotiated.hostkey = $matches[1].Trim() }
    elseif ($line -match 'debug1:\s+kex:\s+server->client cipher:\s+(\S+).*MAC:\s+(\S+)') {
        $negotiated.cipher = $matches[1].Trim(); $negotiated.mac = $matches[2].Trim()
    }
    elseif ($line -match 'debug1:\s+kex:\s+client->server cipher:\s+(\S+).*MAC:\s+(\S+)') {
        $negotiated.cipher_cs = $matches[1].Trim(); $negotiated.mac_cs = $matches[2].Trim()
    }
}

$parsed = [ordered]@{
    connection_status = ""
    client_kex   = @($clientKex -split ",\s*" | Where-Object { $_ })
    client_hostkey = @($clientHostkey -split ",\s*" | Where-Object { $_ })
    server_kex   = @($serverKex -split ",\s*" | Where-Object { $_ })
    server_hostkey = @($serverHostkey -split ",\s*" | Where-Object { $_ })
    negotiated   = $negotiated
}

# 连接状态
if ($rawOutput -match "Connection refused|Connection timed out|Name or service not known|network is unreachable") {
    $parsed.connection_status = "FAILED: $($matches[0])"
} elseif ($rawOutput -match "Authenticated to|Authentication succeeded|Authenticated to") {
    $parsed.connection_status = "AUTHENTICATED"
} elseif ($negotiated.kex) {
    $parsed.connection_status = "HANDSHAKE_OK (auth failed, 协商阶段已成功)"
} else {
    $parsed.connection_status = "NO_HANDSHAKE"
}

# ---- 3. 与矩阵预测对比 ----
$parsed.client_has_pq_kex = @($parsed.client_kex | Where-Object { $_ -match "mlkem|sntrup|ntru|bike|hqc|frodo|mceliece|kyber" }).Count -gt 0
$parsed.server_has_pq_kex = @($parsed.server_kex | Where-Object { $_ -match "mlkem|sntrup|ntru|bike|hqc|frodo|mceliece|kyber" }).Count -gt 0

if ($parsed.client_has_pq_kex -and $parsed.server_has_pq_kex) {
    $parsed.matrix_scenario = "C4 (hybrid -> hybrid) - PQ 生效"
} elseif ($parsed.client_has_pq_kex -and -not $parsed.server_has_pq_kex) {
    $parsed.matrix_scenario = "C3 (hybrid -> pre-PQ) - 应自动回退"
} elseif (-not $parsed.client_has_pq_kex -and $parsed.server_has_pq_kex) {
    $parsed.matrix_scenario = "C2 (pre-PQ -> hybrid) - 需服务端经典回退, 否则断点!"
} else {
    $parsed.matrix_scenario = "C1 (pre-PQ -> pre-PQ) - 迁移前基线"
}

$parsed.is_pq_negotiated = ($negotiated.kex -match "mlkem|sntrup|ntru|kyber") -or
                           ($negotiated.hostkey -match "ml-dsa|slh-dsa|falcon")

# ---- 4. 输出 ----
$report = [ordered]@{
    title          = "真实互通测试 (Live Negotiation Capture)"
    target         = "$User@$Target`:$Port"
    captured_at    = (Get-Date).ToUniversalTime().ToString("o")
    tool_version   = (& cmd /c "ssh -V 2>&1") -join ""
    connection = [ordered]@{
        status          = $parsed.connection_status
        matrix_scenario = $parsed.matrix_scenario
        is_pq_negotiated = $parsed.is_pq_negotiated
    }
    client_offer = [ordered]@{
        kex          = $parsed.client_kex
        hostkey      = $parsed.client_hostkey
        has_pq_kex   = $parsed.client_has_pq_kex
    }
    server_offer = [ordered]@{
        kex          = $parsed.server_kex
        hostkey      = $parsed.server_hostkey
        has_pq_kex   = $parsed.server_has_pq_kex
    }
    negotiated = $parsed.negotiated
}

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force > $null }
$outFile = "$OutDir\live_negotiation.json"
$report | ConvertTo-Json -Depth 6 | Set-Content -Path $outFile -Encoding UTF8

Write-Host ("结果已写入: {0}" -f $outFile) -ForegroundColor Green
Write-Host ("  连接状态:      {0}" -f $parsed.connection_status) -ForegroundColor Yellow
Write-Host ("  矩阵场景:      {0}" -f $parsed.matrix_scenario) -ForegroundColor Cyan
Write-Host ("  协商 KEX:      {0}" -f $negotiated.kex) -ForegroundColor Green
Write-Host ("  协商 Hostkey:  {0}" -f $negotiated.hostkey) -ForegroundColor Green
Write-Host ("  协商 Cipher:   {0}" -f $negotiated.cipher) -ForegroundColor Green
Write-Host ("  服务端含 PQ KEX: {0}" -f $parsed.server_has_pq_kex) -ForegroundColor Magenta
Write-Host ("  本机含 PQ KEX:   {0}" -f $parsed.client_has_pq_kex) -ForegroundColor Magenta
Write-Host ("  是否协商出 PQ:   {0}" -f $parsed.is_pq_negotiated) -ForegroundColor Red