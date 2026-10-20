# ============================================================================
# capture_baseline.ps1  --  迁移前基线采集
# 用途: 提取本机 OpenSSH/libssh2 工具链当前支持的全部算法, 作为"迁移前"基线。
# 输出: demo/results/baseline_pre_migration.json
# ============================================================================
[CmdletBinding()]
param(
    [string]$SshBin = "ssh",
    [string]$OutFile = "D:\PQC-test\libSSH2\demo\results\baseline_pre_migration.json"
)

$ErrorActionPreference = "Continue"

function Get-SshAlgos([string]$query) {
    $raw = & $SshBin -Q $query 2>&1
    $result = @($raw | ForEach-Object { ($_ -as [string]).Trim() } | Where-Object { $_ -and -not $_.StartsWith("ssh :") -and -not $_.StartsWith("Unsupported") })
    return [string[]]$result
}

Write-Host "== 采集迁移前基线 ==" -ForegroundColor Cyan

$kex   = @(Get-SshAlgos "kex")
$cipher = @(Get-SshAlgos "cipher")
$mac   = @(Get-SshAlgos "mac")
$hostkey = @(Get-SshAlgos "key")     # OpenSSH: key = host key algorithms
$sig   = @(Get-SshAlgos "sig")

# 服务端默认算法(迁移前基线: 纯传统, 不含任何 PQ 算法)
# 注: 真实 OpenSSH 9.5 sshd 默认也含 sntrup761x25519, 但作为"迁移前基线"
#     此处刻意排除 PQ, 以清晰区分 传统/混合/纯后量子 三种部署类型
$serverKex = @(
    "curve25519-sha256", "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
    "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1"
)
$serverHostKey = @("rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa")

$sshVersion = (& cmd /c "$SshBin -V 2>&1") -join " | "

$baseline = [ordered]@{
    tool             = "OpenSSH_for_Windows"
    tool_version     = $sshVersion
    scope            = "migration-baseline"
    collected_at     = (Get-Date).ToUniversalTime().ToString("o")
    host             = $env:COMPUTERNAME
    os               = $env:OS
    client = [ordered]@{
        kex          = $kex
        hostkey      = $hostkey
        signature    = $sig
        cipher       = $cipher
        mac          = $mac
    }
    server_default = [ordered]@{
        kex          = $serverKex
        hostkey      = $serverHostKey
    }
}

$dir = Split-Path -Parent $OutFile
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force > $null }
$baseline | ConvertTo-Json -Depth 6 | Set-Content -Path $OutFile -Encoding UTF8
Write-Host "基线已写入: $OutFile" -ForegroundColor Green
Write-Host ("客户端 KEX 算法数: {0} | 签名算法数: {1} | 密码套件: {2} | MAC: {3}" -f $kex.Count, $sig.Count, $cipher.Count, $mac.Count) -ForegroundColor Yellow
