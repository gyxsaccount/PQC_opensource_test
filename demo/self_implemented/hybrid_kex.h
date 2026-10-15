// ============================================================================
// hybrid_kex.h  --  ML-KEM-768 + X25519 混合密钥交换 (HYBRID KEX) 自实现
//
// 标注: [SELF-IMPLEMENT] — 此文件为自实现代码, libssh2/OpenSSH 原生不含
//       后量子 KEX, 需手动集成到 SSH 协议层。
//
// 依赖版本:
//   - OpenSSL >= 3.5.0 （原生支持 ML-KEM (FIPS 203), EVP_KEM API）
//   - libssh2  >= 1.11.0 （需打补丁添加新 KEX 算法枚举和协商）
//   - OpenSSH  >= 9.9     （参考线: 原生支持 mlkem768x25519-sha256）
//
// 设计原则 (RFC 9708 / OpenSSH hybrid):
//   1. 客户端同时执行 X25519 ECDH 和 ML-KEM-768 KEM
//   2. 服务端分别回复 ECDH 公钥 + KEM 密文
//   3. 两个共享密钥 XOR 后作为最终 shared secret 送 SHA256
//   4. 协商名称 (kex_algo): "mlkem768x25519-sha256"
//
// 若不支持 OpenSSL 3.5+, 可使用 liboqs (OQS-Provider) 替代:
//   liboqs >= 0.12.0 + oqs-provider >= 0.8.0
// ============================================================================
#ifndef HYBRID_KEX_H
#define HYBRID_KEX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 常量 ---------- */
#define X25519_KEYLEN         32     /* X25519 私钥/公钥/shared secret (字节) */
#define MLKEM768_PUBLEN       1184   /* ML-KEM-768 公钥长度 */
#define MLKEM768_SECLEN       2400   /* ML-KEM-768 私钥长度 */
#define MLKEM768_CIPHERLEN    1088   /* ML-KEM-768 密文长度 */
#define MLKEM768_SHAREDLEN    32     /* ML-KEM-768 输出共享密钥长度 */
#define HYBRID_SS_LEN         32     /* XOR 后最终 shared secret 长度 */
#define KEX_NAME              "mlkem768x25519-sha256"

/* ---------- 错误码 ---------- */
#define HYBRID_OK             0
#define HYBRID_ERR_CRYPTO    -1
#define HYBRID_ERR_INTERNAL  -2

/* ---------- 数据结构 ---------- */
/* 客户端第 1 阶段: 生成两对密钥, 发送公钥 + KEM 公钥 */
typedef struct {
    uint8_t x25519_pubkey[X25519_KEYLEN];
    uint8_t mlkem_pubkey[MLKEM768_PUBLEN];
} hybrid_kex_client_offer;

/* 服务端第 1 阶段: 收到 offer → 回复 ECDH 公钥 + KEM 密文 */
typedef struct {
    uint8_t x25519_pubkey[X25519_KEYLEN];
    uint8_t mlkem_ciphertext[MLKEM768_CIPHERLEN];
} hybrid_kex_server_reply;

/* ---------- API ---------- */

/**
 * hybrid_kex_client_round1()  [SELF-IMPLEMENT]
 *
 * 客户端生成 X25519 临时密钥对 + ML-KEM-768 临时密钥对,
 * 填充 hybrid_kex_client_offer (发送给服务端)。
 *
 * @param offer      [out] 发送给服务端的 offer
 * @param x_secret   [out] X25519 私钥 (调用方管理生命周期)
 * @param mlkem_sk   [out] ML-KEM-768 私钥
 * @return HYBRID_OK 或错误码
 *
 * 使用 OpenSSL API:
 *   - EVP_PKEY_keygen (X25519)
 *   - EVP_PKEY_keygen / OQS_KEM_keypair (ML-KEM-768)
 */
int hybrid_kex_client_round1(hybrid_kex_client_offer *offer,
                             uint8_t x_secret[X25519_KEYLEN],
                             uint8_t mlkem_sk[MLKEM768_SECLEN]);

/**
 * hybrid_kex_server_round()  [SELF-IMPLEMENT]
 *
 * 服务端收到 offer, 生成 X25519 密钥对+ML-KEM-768 封装, 计算共享密钥。
 *
 * @param offer      [in]  客户端 offer (含 x25519_pubkey + mlkem_pubkey)
 * @param reply      [out] 回复给客户端 (含 x25519_pubkey + ciphertext)
 * @param shared     [out] 最终的 HYBRID shared secret (32 bytes)
 * @return HYBRID_OK 或错误码
 *
 * 使用 OpenSSL API:
 *   - EVP_PKEY_keygen (X25519)
 *   - EVP_PKEY_derive (ECDH)
 *   - EVP_KEM_encapsulate (ML-KEM-768)
 */
int hybrid_kex_server_round(const hybrid_kex_client_offer *offer,
                            hybrid_kex_server_reply *reply,
                            uint8_t shared[HYBRID_SS_LEN]);

/**
 * hybrid_kex_client_round2()  [SELF-IMPLEMENT]
 *
 * 客户端收到服务端回复, 完成 X25519 派生 + ML-KEM-768 解封装, 计算 shared secret。
 *
 * @param x_secret   [in]  客户端 X25519 私钥
 * @param mlkem_sk   [in]  客户端 ML-KEM-768 私钥
 * @param reply      [in]  服务端回复
 * @param shared     [out] 最终的 HYBRID shared secret (32 bytes)
 * @return HYBRID_OK 或错误码
 *
 * 使用 OpenSSL API:
 *   - EVP_PKEY_derive (ECDH)
 *   - EVP_KEM_decapsulate (ML-KEM-768)
 */
int hybrid_kex_client_round2(const uint8_t x_secret[X25519_KEYLEN],
                             const uint8_t mlkem_sk[MLKEM768_SECLEN],
                             const hybrid_kex_server_reply *reply,
                             uint8_t shared[HYBRID_SS_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_KEX_H */