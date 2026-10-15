# 构建脚本：编译全部源码到 out/
# 用法: powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = "Stop"
$lib = (Get-ChildItem "lib" -Filter *.jar | ForEach-Object { $_.FullName }) -join ';'
$srcs = Get-ChildItem "src" -Recurse -Filter *.java | ForEach-Object { $_.FullName }

if (-not (Test-Path "out")) { New-Item -ItemType Directory -Path "out" | Out-Null }

javac -encoding UTF-8 -cp $lib -d "out" $srcs
if ($LASTEXITCODE -ne 0) { Write-Error "编译失败"; exit 1 }
Write-Host "编译完成 -> out/"
