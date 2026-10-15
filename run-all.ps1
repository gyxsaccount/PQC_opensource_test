# 一键运行 Apache Commons Codec PQC 迁移测试
# 用法: powershell -ExecutionPolicy Bypass -File run-all.ps1
$ErrorActionPreference = "Continue"

powershell -ExecutionPolicy Bypass -File build.ps1
if ($LASTEXITCODE -ne 0) { Write-Error "编译失败"; exit 1 }

$cp = (Get-ChildItem "lib" -Filter *.jar | ForEach-Object { $_.FullName }) -join ';'

if (-not (Test-Path "logs")) { New-Item -ItemType Directory -Path "logs" | Out-Null }

Write-Host "========== 运行 PqcMigrationTest =========="
& cmd /c "java -cp `"out;$cp`" PqcMigrationTest 2>&1" | Tee-Object "logs\run.log"

Write-Host "`n全部完成。日志位于 logs\run.log"
