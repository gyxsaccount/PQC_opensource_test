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

function Get-AlgoSetType {
    <#
    .SYNOPSIS
      识别一组算法的部署类型: 传统 / 混合 / 纯后量子
    .PARAMETER Algos
      算法列表 (字符串数组)
    .RETURNS
      "传统" (只有经典算法) | "混合" (经典+PQ都有) | "纯后量子" (只有PQ)
    #>
    param([string[]]$Algos)
    # PQ 关键词: KEX 混合 (mlkem/sntrup/ntru) 或 混合签名 (ml-dsa/slh-dsa/falcon)
    $pqPattern = "mlkem|sntrup|ntru|kyber|ml-dsa|mldsa|slh-dsa|falcon|dilithium|sphincs"
    $hasPQ = @($Algos | Where-Object { $_ -match $pqPattern }).Count -gt 0
    $hasClassic = @($Algos | Where-Object { $_ -notmatch $pqPattern }).Count -gt 0
    if ($hasPQ -and $hasClassic) { return "混合" }
    elseif ($hasPQ) { return "纯后量子" }
    else { return "传统" }
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
        [string]$ScenarioName = "compatibility-matrix",
        [string]$ModeLabel = ""   # 例如 "M1-soft" / "M2-strict", 用于场景命名
    )

    $categories = @("kex", "hostkey", "cipher", "mac")

    # 识别每个端点的实际部署类型 (传统/混合/纯后量子)
    $baseClientType = Get-AlgoSetType -Algos $BaselineClient.kex
    $baseServerType = Get-AlgoSetType -Algos $BaselineServer.kex
    $pqClientType   = Get-AlgoSetType -Algos $PQClient.kex
    $pqServerType   = Get-AlgoSetType -Algos $PQServer.kex

    $cases = @(
        @{ label = "C1: 客户端[$baseClientType] → 服务端[$baseServerType]"; client = $BaselineClient; server = $BaselineServer },
        @{ label = "C2: 客户端[$baseClientType] → 服务端[$pqServerType]";   client = $BaselineClient; server = $PQServer },
        @{ label = "C3: 客户端[$pqClientType] → 服务端[$baseServerType]";   client = $PQClient;       server = $BaselineServer },
        @{ label = "C4: 客户端[$pqClientType] → 服务端[$pqServerType]";     client = $PQClient;       server = $PQServer }
    )

    $results = @()
    foreach ($case in $cases) {
        $entry = @{
            scenario = $case.label
        }
        # 携带部署类型信息 (客户端/服务端用了 传统|混合|纯后量子)
        $entry["client_type"] = if ($case.client -eq $BaselineClient) { $baseClientType } else { $pqClientType }
        $entry["server_type"] = if ($case.server -eq $BaselineServer) { $baseServerType } else { $pqServerType }
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