# ============================================================================
# negotiation_simulator.ps1  --  SSH 协商逻辑模拟器
# 用途: 模拟 SSH 客户端/服务端算法协商 (client-offer → server-pick 模型),
#       测试迁移前后的兼容性矩阵, 找出断点。
# ============================================================================

function Invoke-SSHNegotiation {
    <#
    .SYNOPSIS
      模拟 SSH 密钥交换协商: 客户端发 offer(算法列表), 服务端选择第一个匹配的算法。
      此过程对 KEX / 签名 / 密码 / MAC 均适用。
    .PARAMETER ClientOffer
      客户端按优先级排列的算法列表
    .PARAMETER ServerOffer
      服务端按优先级排列的算法列表
    .RETURNS
      协商结果字符串: "matched: <alg>" 或 "MISMATCH"
    #>
    param(
        [string[]]$ClientOffer,
        [string[]]$ServerOffer
    )
    foreach ($c in $ClientOffer) {
        foreach ($s in $ServerOffer) {
            # 匹配规则: 精确字符串匹配(SSH 协议 name-list 匹配)
            # 混合算法 (如 "ssh-ed25519 + ssh-ml-dsa-44") 需要服务端也支持混合
            if ($c -eq $s) {
                return "matched: $c"
            }
        }
    }
    return "MISMATCH"
}

function Measure-CompatibilityMatrix {
    <#
    .SYNOPSIS
      运行兼容性矩阵: (旧/新) × (旧/新) 的 4 种组合,
      对 KEX / 签名 / 密码 / MAC 分别测试, 记录断点。
    .PARAMETER BaselineClient
      迁移前客户端算法集 (hashtable)
    .PARAMETER BaselineServer
      迁移前服务端算法集 (hashtable)
    .PARAMETER PQClient
      迁移后(含混合 PQ)客户端算法集 (hashtable)
    .PARAMETER PQServer
      迁移后(含混合 PQ)服务端算法集 (hashtable)
    .PARAMETER ScenarioName
      可选的场景名称, 用于结果标记
    .RETURNS
      hashtable[]: 每类一个结果条目
    #>
    param(
        [hashtable]$BaselineClient,
        [hashtable]$BaselineServer,
        [hashtable]$PQClient,
        [hashtable]$PQServer,
        [string]$ScenarioName = "compatibility-matrix"
    )

    $categories = @("kex", "hostkey", "cipher", "mac")
    $cases = @(
        @{ label = "C1: 旧客户端 → 旧服务端 (pre-PQ→pre-PQ)";   client = $BaselineClient; server = $BaselineServer },
        @{ label = "C2: 旧客户端 → 新服务端 (pre-PQ→hybrid)";   client = $BaselineClient; server = $PQServer },
        @{ label = "C3: 新客户端 → 旧服务端 (hybrid→pre-PQ)";   client = $PQClient;       server = $BaselineServer },
        @{ label = "C4: 新客户端 → 新服务端 (hybrid→hybrid)";   client = $PQClient;       server = $PQServer }
    )

    $results = @()
    foreach ($case in $cases) {
        $entry = @{
            scenario = $case.label
        }
        $breakpoints = @()
        foreach ($cat in $categories) {
            $clientAlgos = if ($case.client.ContainsKey($cat)) { $case.client[$cat] } else { @() }
            $serverAlgos = if ($case.server.ContainsKey($cat)) { $case.server[$cat] } else { @() }
            $result = Invoke-SSHNegotiation -ClientOffer $clientAlgos -ServerOffer $serverAlgos
            $entry[$cat] = $result
            if ($result -eq "MISMATCH") {
                $breakpoints += $cat
            }
        }
        $entry["breakpoints"] = $breakpoints
        $entry["has_breakpoint"] = ($breakpoints.Count -gt 0)
        $results += $entry
    }
    return $results
}