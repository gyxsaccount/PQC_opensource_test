# ============================================================================
# algorithm_audit.ps1  --  算法健康审计
# 用途: 审查迁移前基线, 标记应淘汰/替换的弱算法, 给出迁移优先级。
#       弱算法在 PQC 迁移过程中应一并清除(它们也是量子攻击/降级攻击入口)。
# 输出: results/algorithm_audit.json
# ============================================================================
[CmdletBinding()]
param(
    [string]$BaselineFile = "D:\PQC-test\libSSH2\demo\results\baseline_pre_migration.json",
    [string]$OutDir       = "D:\PQC-test\libSSH2\demo\results"
)

$ErrorActionPreference = "Continue"

if (-not (Test-Path $BaselineFile)) {
    Write-Error "基线文件不存在: $BaselineFile (先运行 capture_baseline.ps1)"
    return
}
$base = Get-Content $BaselineFile -Raw -Encoding UTF8 | ConvertFrom-Json

# ---- 弱算法黑名单 ----
$weakRules = [ordered]@{
    kex = [ordered]@{
        "diffie-hellman-group1-sha1"         = "SHA-1 + 1024-bit DH, 已被实践攻击"
        "diffie-hellman-group14-sha1"        = "SHA-1 弱哈希"
        "diffie-hellman-group-exchange-sha1" = "SHA-1 弱哈希"
    }
    hostkey = [ordered]@{
        "ssh-dss"    = "DSA 1024-bit, OpenSSH 8.2+ 默认禁用"
        "ssh-rsa"    = "SHA-1 签名, 已弃用(仅 rsa-sha2-256/512 可用)"
    }
    cipher = [ordered]@{
        "3des-cbc"   = "56-bit 有效强度, 已弃用"
        "aes128-cbc" = "CBC 模式 Padding Oracle 风险, 建议 CTR/GCM"
        "aes192-cbc" = "CBC 模式 Padding Oracle 风险"
        "aes256-cbc" = "CBC 模式 Padding Oracle 风险"
    }
    mac = [ordered]@{
        "hmac-md5"       = "MD5 已破"
        "hmac-md5-96"    = "MD5 已破"
        "hmac-sha1"      = "SHA-1 弱哈希"
        "hmac-sha1-96"   = "SHA-1 弱哈希"
        "umac-64@openssh.com" = "64-bit tag 过短"
    }
}

# ---- 执行审计 ----
function Audit-Category($category, $list, $rules) {
    $found = @()
    foreach ($alg in $list) {
        if ($rules.Contains($alg)) {
            $found += [ordered]@{
                algorithm = $alg
                risk      = $rules[$alg]
                action    = "淘汰"
            }
        } else {
            # 弱算法 family 匹配 (如 aes128-ctr 正常, 但 hmac-sha1-etm 也算弱)
            foreach ($key in $rules.Keys) {
                if ($alg -like "$key*") {
                    $found += [ordered]@{
                        algorithm = $alg
                        risk      = $rules[$key]
                        action    = "淘汰"
                    }
                    break
                }
            }
        }
    }
    return $found
}

$audit = [ordered]@{
    title     = "算法健康审计 (迁移前)"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    baseline  = $base.tool_version
    findings  = [ordered]@{
        kex     = @(Audit-Category "kex"     $base.client.kex     $weakRules.kex)
        hostkey = @(Audit-Category "hostkey" $base.client.hostkey $weakRules.hostkey)
        cipher  = @(Audit-Category "cipher"  $base.client.cipher  $weakRules.cipher)
        mac     = @(Audit-Category "mac"     $base.client.mac     $weakRules.mac)
    }
}

# 汇总统计
$totalWeak = 0
foreach ($cat in @("kex","hostkey","cipher","mac")) {
    $totalWeak += $audit.findings.$cat.Count
}
$audit.summary = [ordered]@{
    weak_algorithm_count = $totalWeak
    kex_deprecated   = $audit.findings.kex.Count
    hostkey_deprecated = $audit.findings.hostkey.Count
    cipher_deprecated = $audit.findings.cipher.Count
    mac_deprecated    = $audit.findings.mac.Count
    recommendation = "上述弱算法应在 PQC 迁移前一并从配置中移除, 防止降级攻击 (迁移断点的隐蔽诱因)"
}

# ---- 输出 ----
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force > $null }
$outFile = "$OutDir\algorithm_audit.json"
$audit | ConvertTo-Json -Depth 6 | Set-Content -Path $outFile -Encoding UTF8

Write-Host "== 算法健康审计 ==" -ForegroundColor Cyan
Write-Host ("结果已写入: {0}" -f $outFile) -ForegroundColor Green
Write-Host ("  待淘汰弱算法总数: {0}" -f $totalWeak) -ForegroundColor Red
Write-Host ("    KEX: {0} | Hostkey: {1} | Cipher: {2} | MAC: {3}" -f `
    $audit.findings.kex.Count, $audit.findings.hostkey.Count, `
    $audit.findings.cipher.Count, $audit.findings.mac.Count) -ForegroundColor Yellow

foreach ($cat in @("kex","hostkey","cipher","mac")) {
    if ($audit.findings.$cat.Count -gt 0) {
        Write-Host ("  [{0}] 待淘汰: {1}" -f $cat, (($audit.findings.$cat | ForEach-Object { $_.algorithm }) -join ", ")) -ForegroundColor Red
    }
}