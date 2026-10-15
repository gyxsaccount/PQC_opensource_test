# 一键运行三个方案的 Angus Mail PQC 迁移测试（含 TLS 握手调试日志）
# 用法: powershell -ExecutionPolicy Bypass -File run-all.ps1
$ErrorActionPreference = "Continue"

powershell -ExecutionPolicy Bypass -File build.ps1
if ($LASTEXITCODE -ne 0) { Write-Error "编译失败"; exit 1 }

$cp = (Get-ChildItem "lib" -Filter *.jar | ForEach-Object { $_.FullName }) -join ';'

if (-not (Test-Path "logs")) { New-Item -ItemType Directory -Path "logs" | Out-Null }

Write-Host "========== 运行 方案A (JDK 内置) =========="
& cmd /c "java -Djavax.net.debug=ssl:handshake -cp `"out;$cp`" pqc.approachA.MainA 2>&1" | Tee-Object "logs\runA.log"
Write-Host "========== 运行 方案B (BouncyCastle) =========="
& cmd /c "java -Djavax.net.debug=ssl:handshake -cp `"out;$cp`" pqc.approachB.MainB 2>&1" | Tee-Object "logs\runB.log"
Write-Host "========== 运行 方案C (混合式全迁移点) =========="
& cmd /c "java -Djavax.net.debug=ssl:handshake -cp `"out;$cp`" pqc.approachC.MainC 2>&1" | Tee-Object "logs\runC.log"

Write-Host "`n全部完成。日志位于 logs\runA.log / runB.log / runC.log"
