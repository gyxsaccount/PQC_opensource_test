# ============================================================================
# generate_html_report.ps1  --  HTML 可视化报告生成器
# 用途: 读取所有 results/*.json, 生成单文件 self-contained HTML 报告,
#       用红/绿/黄颜色直观展示断点、弱算法、PQ 覆盖情况。
# 输出: results/report.html (双击即可在浏览器查看)
# ============================================================================
[CmdletBinding()]
param(
    [string]$ResultsDir = "D:\PQC-test\libSSH2\demo\results"
)

$ErrorActionPreference = "Continue"

# ---- 加载所有 JSON ----
$matrix = Get-Content "$ResultsDir\compatibility_matrix.json" -Raw -Encoding UTF8 | ConvertFrom-Json
$baseline = Get-Content "$ResultsDir\baseline_pre_migration.json" -Raw -Encoding UTF8 | ConvertFrom-Json
$audit = Get-Content "$ResultsDir\algorithm_audit.json" -Raw -Encoding UTF8 | ConvertFrom-Json
$live = $null
if (Test-Path "$ResultsDir\live_negotiation.json") {
    $live = Get-Content "$ResultsDir\live_negotiation.json" -Raw -Encoding UTF8 | ConvertFrom-Json
}

# ---- 构造 HTML ----
$h = New-Object System.Text.StringBuilder

[void]$h.AppendLine("<!DOCTYPE html>")
[void]$h.AppendLine("<html lang=`"zh`">")
[void]$h.AppendLine("<head>")
[void]$h.AppendLine("<meta charset=`"UTF-8`">")
[void]$h.AppendLine("<title>libSSH2 PQC 迁移测试报告</title>")
[void]$h.AppendLine(@"
<style>
  body { font-family: 'Segoe UI', Consolas, sans-serif; margin: 24px; background:#f5f6fa; color:#222; }
  h1 { color:#1a237e; } h2 { color:#283593; border-bottom:2px solid #c5cae9; padding-bottom:4px; margin-top:32px; }
  table { border-collapse: collapse; margin: 12px 0; width: 100%; background:#fff; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
  th, td { border:1px solid #e0e0e0; padding:6px 10px; font-size:13px; text-align:left; }
  th { background:#e8eaf6; }
  .ok { color:#1b5e20; font-weight:bold; }
  .bad { color:#b71c1c; font-weight:bold; }
  .warn { color:#e65100; }
  .card { background:#fff; border:1px solid #ddd; border-radius:6px; padding:14px 18px; margin:10px 0; }
  .metric { display:inline-block; margin:8px 24px 8px 0; }
  .metric .num { font-size:28px; font-weight:bold; }
  .metric .lbl { font-size:12px; color:#666; }
  .red { color:#b71c1c; } .green { color:#1b5e20; } .yellow { color:#e65100; }
  code { background:#eceff1; padding:1px 4px; border-radius:3px; font-size:12px; }
  .note { font-size:12px; color:#666; }
</style>
"@)
[void]$h.AppendLine("</head>")
[void]$h.AppendLine("<body>")
[void]$h.AppendLine("<h1>libSSH2 后量子迁移测试报告</h1>")
[void]$h.AppendLine("<p class=`"note`">生成时间: $($matrix.generated_at) | 基线工具: $($matrix.baseline_tool)</p>")

# ---- 汇总指标 ----
$bp = $matrix.summary.breakpoint_scenarios
$safe = $matrix.summary.safe_scenarios
$bpColor = if ($bp -gt 0) { "red" } else { "green" }
$safeColor = if ($safe -gt 0) { "green" } else { "red" }
[void]$h.AppendLine("<div class=`"card`">")
[void]$h.AppendLine("<div class=`"metric`"><div class=`"num $bpColor`">$bp</div><div class=`"lbl`">断点场景数</div></div>")
[void]$h.AppendLine("<div class=`"metric`"><div class=`"num $safeColor`">$safe</div><div class=`"lbl`">安全场景数</div></div>")
[void]$h.AppendLine("<div class=`"metric`"><div class=`"num`">$($matrix.summary.total_scenarios)</div><div class=`"lbl`">总场景数</div></div>")
if ($live) {
    $liveCls = if ($live.connection.is_pq_negotiated) { "green" } else { "yellow" }
    [void]$h.AppendLine("<div class=`"metric`"><div class=`"num $liveCls`">$($live.negotiated.kex)</div><div class=`"lbl`">真实协商 KEX ($($live.target))</div></div>")
}
[void]$h.AppendLine("</div>")

# ---- 配置模式 ----
[void]$h.AppendLine("<h2>配置模式</h2>")
[void]$h.AppendLine("<ul>")
foreach ($cfg in $matrix.configuration) {
    [void]$h.AppendLine("<li><strong>$($cfg.mode)</strong>: $($cfg.note)</li>")
}
[void]$h.AppendLine("</ul>")

# ---- 兼容性矩阵 ----
[void]$h.AppendLine("<h2>兼容性矩阵 (断点检测)</h2>")
[void]$h.AppendLine("<table><tr><th>场景</th><th>KEX</th><th>Hostkey</th><th>Cipher</th><th>MAC</th><th>断点</th></tr>")
foreach ($r in $matrix.results) {
    $bpCell = if ($r.has_breakpoint) { "<span class='bad'>" + ($r.breakpoints -join ", ") + "</span>" } else { "<span class='ok'>无</span>" }
    $kexCls = if ($r.kex -match "MISMATCH") { "bad" } elseif ($r.kex -match "mlkem|sntrup|ml-dsa") { "ok" } else { "" }
    $hkCls = if ($r.hostkey -match "MISMATCH") { "bad" } elseif ($r.hostkey -match "mlkem|sntrup|ml-dsa") { "ok" } else { "" }
    [void]$h.AppendLine("<tr><td>$($r.scenario)</td><td class='$kexCls'>$($r.kex)</td><td class='$hkCls'>$($r.hostkey)</td><td>$($r.cipher)</td><td>$($r.mac)</td><td>$bpCell</td></tr>")
}
[void]$h.AppendLine("</table>")

# ---- 断点详情 ----
if ($bp -gt 0) {
    [void]$h.AppendLine("<h2>断点详情</h2>")
    [void]$h.AppendLine("<ul>")
    foreach ($d in $matrix.summary.breakpoint_details) {
        [void]$h.AppendLine("<li><span class='bad'>$($d.scenario)</span> - 失败类别: $($d.categories -join ', ')</li>")
    }
    [void]$h.AppendLine("</ul>")
    [void]$h.AppendLine("<div class=`"card`"><strong>断点消除策略:</strong> 迁移过渡期服务端必须保留经典算法双轨运行, 例: <code>KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,...</code>。</div>")
}

# ---- 真实互通 ----
if ($live) {
    [void]$h.AppendLine("<h2>真实互通测试</h2>")
    $pq = if ($live.connection.is_pq_negotiated) { "<span class='ok'>是</span>" } else { "<span class='warn'>否 (未协商出 PQ)</span>" }
    [void]$h.AppendLine("<table><tr><th>目标</th><th>矩阵场景</th><th>协商 KEX</th><th>协商 Hostkey</th><th>服务端含 PQ KEX</th><th>本机含 PQ KEX</th><th>PQ 生效</th></tr>")
    $srvCls = if ($live.server_offer.has_pq_kex) { "ok" } else { "" }
    $cliCls = if ($live.client_offer.has_pq_kex) { "ok" } else { "warn" }
    [void]$h.AppendLine("<tr><td>$($live.target)</td><td>$($live.connection.matrix_scenario)</td><td>$($live.negotiated.kex)</td><td>$($live.negotiated.hostkey)</td><td class='$srvCls'>$($live.server_offer.has_pq_kex)</td><td class='$cliCls'>$($live.client_offer.has_pq_kex)</td><td>$pq</td></tr>")
    [void]$h.AppendLine("</table>")
}

# ---- 算法审计 ----
[void]$h.AppendLine("<h2>算法健康审计 (待淘汰弱算法)</h2>")
[void]$h.AppendLine("<div class=`"card`"><div class=`"metric`"><div class=`"num red`">$($audit.summary.weak_algorithm_count)</div><div class=`"lbl`">待淘汰算法数</div></div>")
[void]$h.AppendLine("<div class=`"metric`"><div class=`"num`">$($audit.summary.kex_deprecated)</div><div class=`"lbl`">KEX</div></div>")
[void]$h.AppendLine("<div class=`"metric`"><div class=`"num`">$($audit.summary.hostkey_deprecated)</div><div class=`"lbl`">Hostkey</div></div>")
[void]$h.AppendLine("<div class=`"metric`"><div class=`"num`">$($audit.summary.cipher_deprecated)</div><div class=`"lbl`">Cipher</div></div>")
[void]$h.AppendLine("<div class=`"metric`"><div class=`"num`">$($audit.summary.mac_deprecated)</div><div class=`"lbl`">MAC</div></div>")
[void]$h.AppendLine("<p class='note'>$($audit.summary.recommendation)</p></div>")

[void]$h.AppendLine("<table><tr><th>类别</th><th>待淘汰算法</th></tr>")
foreach ($cat in @("kex","hostkey","cipher","mac")) {
    $algs = @($audit.findings.$cat | ForEach-Object { "<code>$($_.algorithm)</code>" }) -join " "
    [void]$h.AppendLine("<tr><td>$cat</td><td class='bad'>$algs</td></tr>")
}
[void]$h.AppendLine("</table>")

# ---- 迁移路线图 ----
[void]$h.AppendLine("<h2>迁移路线图</h2>")
[void]$h.AppendLine("<ol>")
[void]$h.AppendLine("<li><strong>阶段 0</strong>: 清除弱算法 (上表 20 项), 消灭降级攻击面</li>")
[void]$h.AppendLine("<li><strong>阶段 1</strong>: 服务端启用混合 KEX <code>mlkem768x25519-sha256</code>, 保留经典回退 (M1 模式)</li>")
[void]$h.AppendLine("<li><strong>阶段 2</strong>: 客户端 (libssh2 + OpenSSL 3.5 + 自实现补丁) 升级, 优先协商 PQ</li>")
[void]$h.AppendLine("<li><strong>阶段 3</strong>: 监控无 PQ 连接占比清零后, 再移除经典算法 (M2 严格模式)</li>")
[void]$h.AppendLine("</ol>")
[void]$h.AppendLine("<p class='note'>自实现代码: <code>self_implemented/hybrid_kex.c</code>, <code>hybrid_signature.c</code>, <code>libssh2_pq.patch</code> | 版本清单: VERSION_MATRIX.md</p>")

# ---- 代码修改点 ----
[void]$h.AppendLine("<h2>代码修改点（具体位置 + 高亮）</h2>")
[void]$h.AppendLine("<p class='note'>基于 libssh2 1.11.0 源码实测行号。完整 diff 见 <code>results/code_modification_points.md</code> 与 <code>self_implemented/libssh2_pq.patch</code></p>")
[void]$h.AppendLine("<table><tr><th>文件</th><th>行号</th><th>修改类型</th><th>用途</th></tr>")
[void]$h.AppendLine("<tr><td><code>src/kex.c</code></td><td><strong>L3040-3059</strong></td><td>新增算法条目</td><td>注册 <code>mlkem768x25519-sha256</code> / <code>sntrup761x25519-sha512</code></td></tr>")
[void]$h.AppendLine("<tr><td><code>src/kex.h</code></td><td>新增</td><td>函数声明</td><td>声明混合 KEX 实现函数</td></tr>")
[void]$h.AppendLine("<tr><td><code>src/hostkey.c</code></td><td><strong>L1275-1302</strong></td><td>新增算法条目</td><td>注册 <code>ssh-ed25519+ml-dsa-44</code> 混合主机密钥</td></tr>")
[void]$h.AppendLine("<tr><td><code>src/transport.c</code></td><td>协商逻辑</td><td>修改</td><td>混合算法优先匹配 + 经典回退</td></tr>")
[void]$h.AppendLine("<tr><td><code>src/openssl.h</code></td><td><strong>L395-397</strong></td><td>新增类型映射</td><td>桥接 OpenSSL 3.5 EVP_PKEY</td></tr>")
[void]$h.AppendLine("<tr><td><code>CMakeLists.txt</code></td><td><strong>L281-303</strong></td><td>新增选项</td><td><code>ENABLE_POST_QUANTUM</code> + OpenSSL 3.5 检测</td></tr>")
[void]$h.AppendLine("<tr><td><code>self_implemented/hybrid_kex.c</code></td><td>全文件</td><td>新增</td><td>ML-KEM-768 + X25519 混合 KEX</td></tr>")
[void]$h.AppendLine("<tr><td><code>self_implemented/hybrid_signature.c</code></td><td>全文件</td><td>新增</td><td>ML-DSA-44 + Ed25519 混合签名</td></tr>")
[void]$h.AppendLine("</table>")

[void]$h.AppendLine("<div class='card'><strong>高亮示例 1:</strong> <code>src/kex.c</code> L3040-3059 KEX 算法表插入点（置顶优先）<br>")
[void]$h.AppendLine("<pre style='background:#263238;color:#d6e6f0;padding:10px;border-radius:4px;overflow-x:auto;font-size:12px;'><span style='color:#8c9eff;'> static const LIBSSH2_KEX_METHOD *libssh2_kex_methods[] = {</span><br><span style='color:#ff8a80;'>+#if LIBSSH2_POST_QUANTUM</span><br><span style='color:#ff8a80;'>+    &amp;kex_method_mlkem768x25519_sha256,   /* NEW: ML-KEM-768 + X25519 */</span><br><span style='color:#ff8a80;'>+    &amp;kex_method_sntrup761x25519_sha512,  /* NEW: NTRU Prime + X25519 */</span><br><span style='color:#ff8a80;'>+#endif</span><br><span style='color:#d6e6f0;'> #if LIBSSH2_ED25519</span><br><span style='color:#d6e6f0;'>     &amp;kex_method_ssh_curve25519_sha256,   /* 经典算法保留尾部 = 回退 */</span></pre></div>")

[void]$h.AppendLine("<div class='card'><strong>高亮示例 2:</strong> <code>src/hostkey.c</code> L1275-1302 主机密钥表插入点<br>")
[void]$h.AppendLine("<pre style='background:#263238;color:#d6e6f0;padding:10px;border-radius:4px;overflow-x:auto;font-size:12px;'><span style='color:#8c9eff;'> static const LIBSSH2_HOSTKEY_METHOD *hostkey_methods[] = {</span><br><span style='color:#ff8a80;'>+#if LIBSSH2_POST_QUANTUM</span><br><span style='color:#ff8a80;'>+    &amp;hostkey_method_ed25519_mldsa44,     /* NEW: Ed25519 + ML-DSA-44 */</span><br><span style='color:#ff8a80;'>+#endif</span><br><span style='color:#d6e6f0;'> #if LIBSSH2_ECDSA</span><br><span style='color:#d6e6f0;'>     &amp;hostkey_method_ecdsa_ssh_nistp256,</span></pre></div>")

[void]$h.AppendLine("<div class='card'><strong>高亮示例 3:</strong> <code>CMakeLists.txt</code> L281-303 构建开关<br>")
[void]$h.AppendLine("<pre style='background:#263238;color:#d6e6f0;padding:10px;border-radius:4px;overflow-x:auto;font-size:12px;'><span style='color:#ff8a80;'>+option(ENABLE_POST_QUANTUM &quot;Enable hybrid post-quantum algorithms (OpenSSL 3.5+)&quot; OFF)</span><br><span style='color:#8c9eff;'> if(CRYPTO_BACKEND STREQUAL &quot;OpenSSL&quot; OR NOT CRYPTO_BACKEND)</span><br><span style='color:#ff8a80;'>-    find_package(OpenSSL ${SPECIFIC_CRYPTO_REQUIREMENT})</span><br><span style='color:#ff8a80;'>+    if(ENABLE_POST_QUANTUM)</span><br><span style='color:#ff8a80;'>+        find_package(OpenSSL 3.5 REQUIRED)</span><br><span style='color:#ff8a80;'>+    else()</span><br><span style='color:#ff8a80;'>+        find_package(OpenSSL ${SPECIFIC_CRYPTO_REQUIREMENT})</span><br><span style='color:#ff8a80;'>+    endif()</span></pre></div>")

[void]$h.AppendLine("<p class='note'>完整修改点与断点对应关系见 <code>results/code_modification_points.md</code> 第 9 节。</p>")

[void]$h.AppendLine("</body></html>")

# ---- 写入 ----
$outFile = "$ResultsDir\report.html"
[System.IO.File]::WriteAllText($outFile, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))
Write-Host "HTML 报告已生成: $outFile" -ForegroundColor Green
Write-Host "用浏览器打开即可查看: explorer $outFile"

# 打开浏览器
try {
    Start-Process $outFile -ErrorAction SilentlyContinue
} catch {}