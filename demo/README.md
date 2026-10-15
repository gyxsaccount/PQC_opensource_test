# libSSH2 后量子迁移测试 Demo

目标: 针对开源软件 **libssh2** (SSH 协议数据传输), 搭建**迁移前/后算法对照测试**,
检测迁移过程中是否存在**阻碍或断点**, 保证**迁移敏捷性** (渐进迁移、随时可回退)。

## 目录结构

```
libSSH2/
└── demo/
    ├── README.md                  ← 本文档
    ├── VERSION_MATRIX.md          ← 组件/版本清单 + 自实现标注
    ├── BREAKPOINTS.md             ← 断点成因与消除策略
    ├── scripts/
    │   ├── capture_baseline.ps1   ← 采集迁移前基线 (ssh -Q 真实数据)
    │   ├── pq_target_algorithms.json ← 迁移后目标算法集
    │   ├── negotiation_simulator.ps1 ← SSH 协商逻辑模拟器
    │   └── compatibility_matrix.ps1  ← 四象限兼容性矩阵测试 (断点检测)
    ├── self_implemented/          ← [SELF-IMPLEMENT] 自实现部分
    │   ├── hybrid_kex.c / .h      ← ML-KEM-768 + X25519 混合 KEX
    │   ├── hybrid_signature.c / .h← ML-DSA-44 + Ed25519 混合签名
    │   └── libssh2_pq.patch       ← libssh2 集成补丁
    ├── results/                   ← 测试结果 (JSON/MD)
    └── tests/                     ← 测试辅助目录
```

## 快速开始 (本机已具备 OpenSSH 9.5)

```powershell
cd D:\PQC-test\libSSH2\demo

# 1. 采集迁移前基线 (提取本机所有算法清单)
.\scripts\capture_baseline.ps1
#    → results/baseline_pre_migration.json

# 2. 运行兼容性矩阵测试 (检测迁移断点)
.\scripts\compatibility_matrix.ps1
#    → results/compatibility_matrix.json
```

## 测试原理

| 阶段 | 方法 | 判定 |
|---|---|---|
| 迁移前 | `ssh -Q` 采集客户端全部算法 | 生成基线清单 |
| 迁移后 | `pq_target_algorithms.json` 定义目标混合算法集 | 对照 |
| 断点检测 | 模拟 SSH 协商 (client offer → server pick) | 无交集=断点 |
| 四象限 | 旧/新 × 旧/新 = 4 场景 | C2 是主要风险 |

## 重要结论 (详见 BREAKPOINTS.md)

1. 真正的量子风险在**非对称部分** (KEX + 签名), 对称加密/哈希无需更换。
2. **C3 (新客户端→旧服务端) 安全**: PQ 客户端自动回退到经典算法。
3. **C2 (旧客户端→新服务端) 是断点**: 服务端不能删除经典算法, 必须混合双轨。
4. OpenSSL 3.5 原生支持 ML-KEM/ML-DSA → **算法原语无需自实现**;
   需自实现的是 **SSH 协议层的混合封装与协商** (`self_implemented/` 下 3 个文件)。

## 依赖与版本

| 组件 | 版本要求 | PQC 支持 |
|---|---|---|
| libssh2 | 1.11.x + 补丁 | 🛠 需自实现集成 |
| OpenSSL | >= 3.5.0 | ✅ ML-KEM/ML-DSA 原生 |
| liboqs(可选) | >= 0.12.0 | ✅ |
| oqs-provider(可选) | >= 0.8.0 | ✅ |
| OpenSSH | >= 9.9 (参考) | ✅ mlkem768x25519 |

> 完整表格见 `VERSION_MATRIX.md`, 自实现代码见 `self_implemented/`。
