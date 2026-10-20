// ============================================================================
// hybrid_kex.c  --  ML-KEM-768 + X25519 混合密钥交换实现 (补全版)
//
// ============================ 自实现声明 ===================================
// 本文件为 [SELF-IMPLEMENT] 自实现代码。声明如下:
//
// 1. libssh2 (1.11.x 及以下) 原生【不具备】以下能力, 需本自实现补齐:
//    a) 后量子 KEX 算法注册: libssh2 的 kex.c 算法表只有经典算法
//       (curve25519/ecdh/diffie-hellman), 没有 "mlkem768x25519-sha256";
//    b) 混合共享密钥组合: SSH 协议无"两个共享密钥 XOR 合并"的标准实现;
//    c) 混合密钥的序列化/解析 framing。
// 2. 算法原语(ML-KEM-768 / X25519)来自 OpenSSL 3.5+, 非本文件实现;
//    本文件实现的是【SSH 协议层的混合封装与协商接入】。
// 3. 直接运行本文件无法独立工作, 必须:
//    - 链接 OpenSSL 3.5+ (libcrypto)
//    - 接入 libssh2 的 kex.c/transport.c (见下方 修改点标记)
// 4. 若改用它: 可将 ML-KEM 部分替换为 liboqs (OQS_KEM_new 等), 接口不变。
// ============================================================================
//  修改点标记: 每一处改动用 【MOD-K#】 标注, 对应
//              demo/results/code_modification_points.md 第 2/8 节。
// ============================================================================
#include "hybrid_kex.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>

/* ---------- 内部辅助 ---------- */
/* 【MOD-K1】XOR 两个 32 字节共享密钥 (混合 KEX 核心组合逻辑) */
static void xor_shared_secret(uint8_t out[32],
                              const uint8_t a[32],
                              const uint8_t b[32]) {
    for (int i = 0; i < 32; i++) out[i] = a[i] ^ b[i];
}

/* 【MOD-K2】生成 X25519 临时密钥对 (OpenSSL 3.x EVP API, 已补全) */
static int x25519_keygen(EVP_PKEY **pkey, uint8_t pubkey[32], uint8_t privkey[32]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return HYBRID_ERR_CRYPTO;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return HYBRID_ERR_CRYPTO; }
    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) { EVP_PKEY_CTX_free(ctx); return HYBRID_ERR_CRYPTO; }
    EVP_PKEY_CTX_free(ctx);

    if (pubkey) {
        size_t publen = 32;
        if (EVP_PKEY_get_raw_public_key(key, pubkey, &publen) <= 0) {
            EVP_PKEY_free(key); return HYBRID_ERR_CRYPTO;
        }
    }
    if (privkey) {
        size_t privlen = 32;
        if (EVP_PKEY_get_raw_private_key(key, privkey, &privlen) <= 0) {
            EVP_PKEY_free(key); return HYBRID_ERR_CRYPTO;
        }
    }
    *pkey = key;
    return HYBRID_OK;
}

/* 【MOD-K3】X25519 ECDH 派生 (补全: 用原始私钥构造 EVP_PKEY, 修复原骨架 bug) */
static int x25519_derive(const uint8_t priv[32], const uint8_t peer_pub[32],
                         uint8_t shared[32]) {
    /* 构造本端私钥对象 */
    EVP_PKEY *our = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    if (!our) return HYBRID_ERR_CRYPTO;
    /* 构造对端公钥对象 */
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    if (!peer) { EVP_PKEY_free(our); return HYBRID_ERR_CRYPTO; }

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(our, NULL);
    if (!dctx) { EVP_PKEY_free(our); EVP_PKEY_free(peer); return HYBRID_ERR_CRYPTO; }
    if (EVP_PKEY_derive_init(dctx) <= 0) {
        EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(our); EVP_PKEY_free(peer); return HYBRID_ERR_CRYPTO;
    }
    if (EVP_PKEY_derive_set_peer(dctx, peer) <= 0) {
        EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(our); EVP_PKEY_free(peer); return HYBRID_ERR_CRYPTO;
    }
    size_t slen = 32;
    if (EVP_PKEY_derive(dctx, shared, &slen) <= 0) {
        EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(our); EVP_PKEY_free(peer);
        return HYBRID_ERR_CRYPTO;
    }
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(our);
    EVP_PKEY_free(peer);
    return HYBRID_OK;
}

/* 【MOD-K4】ML-KEM-768 密钥对生成 (OpenSSL 3.5+ EVP_KEM API, 已补全) */
static int mlkem768_keygen(EVP_PKEY **pub, EVP_PKEY **priv,
                           uint8_t pubkey[MLKEM768_PUBLEN],
                           uint8_t seckey[MLKEM768_SECLEN]) {
    EVP_PKEY *key = NULL;
    /* OpenSSL 3.5: 用 Q_keygen 直接生成 ML-KEM-768 密钥对象 */
    key = EVP_PKEY_Q_keygen(NULL, NULL, NULL, "ML-KEM-768");
    if (!key) return HYBRID_ERR_CRYPTO;

    /* 导出原始公钥 (ML-KEM-768 公钥固定 1184 字节) */
    if (pubkey) {
        size_t publen = MLKEM768_PUBLEN;
        if (EVP_PKEY_get_raw_public_key(key, pubkey, &publen) <= 0) {
            EVP_PKEY_free(key); return HYBRID_ERR_CRYPTO;
        }
    }
    /* 导出原始私钥 (ML-KEM-768 私钥固定 2400 字节) */
    if (seckey) {
        size_t seclen = MLKEM768_SECLEN;
        if (EVP_PKEY_get_raw_private_key(key, seckey, &seclen) <= 0) {
            EVP_PKEY_free(key); return HYBRID_ERR_CRYPTO;
        }
    }
    *pub = key;
    *priv = key;
    return HYBRID_OK;
}

/* 【MOD-K5】从原始私钥字节构造 ML-KEM-768 私钥对象 (供解封装用) */
static EVP_PKEY *mlkem768_priv_from_bytes(const uint8_t sec[MLKEM768_SECLEN]) {
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_MLKEM768, NULL, sec, MLKEM768_SECLEN);
}

/* 【MOD-K6】从原始公钥字节构造 ML-KEM-768 公钥对象 (供封装用) */
static EVP_PKEY *mlkem768_pub_from_bytes(const uint8_t pub[MLKEM768_PUBLEN]) {
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_MLKEM768, NULL, pub, MLKEM768_PUBLEN);
}

/* 【MOD-K7】ML-KEM-768 封装: 输入对端公钥 → 输出密文 + 共享密钥 */
static int mlkem768_encapsulate(const uint8_t peer_pub[MLKEM768_PUBLEN],
                                uint8_t ct[MLKEM768_CIPHERLEN],
                                uint8_t ss[MLKEM768_SHAREDLEN]) {
    EVP_PKEY *peer = mlkem768_pub_from_bytes(peer_pub);
    if (!peer) return HYBRID_ERR_CRYPTO;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, peer, NULL);
    if (!ctx) { EVP_PKEY_free(peer); return HYBRID_ERR_CRYPTO; }

    size_t ct_len = MLKEM768_CIPHERLEN, ss_len = MLKEM768_SHAREDLEN;
    if (EVP_PKEY_kem_encapsulate_init(ctx, NULL) <= 0 ||
        EVP_PKEY_kem_encapsulate(ctx, ct, &ct_len, ss, &ss_len) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(peer);
        return HYBRID_ERR_CRYPTO;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    return HYBRID_OK;
}

/* 【MOD-K8】ML-KEM-768 解封装: 输入本端私钥 + 密文 → 输出共享密钥 */
static int mlkem768_decapsulate(const uint8_t sec[MLKEM768_SECLEN],
                                const uint8_t ct[MLKEM768_CIPHERLEN],
                                uint8_t ss[MLKEM768_SHAREDLEN]) {
    EVP_PKEY *priv = mlkem768_priv_from_bytes(sec);
    if (!priv) return HYBRID_ERR_CRYPTO;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL);
    if (!ctx) { EVP_PKEY_free(priv); return HYBRID_ERR_CRYPTO; }

    size_t ss_len = MLKEM768_SHAREDLEN;
    if (EVP_PKEY_kem_decapsulate_init(ctx, NULL) <= 0 ||
        EVP_PKEY_kem_decapsulate(ctx, ss, &ss_len, ct, MLKEM768_CIPHERLEN) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(priv);
        return HYBRID_ERR_CRYPTO;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    return HYBRID_OK;
}

/* ---------- 公开 API 实现 ---------- */
/* 【MOD-K9】客户端第 1 阶段: 生成 X25519 密钥对 + ML-KEM-768 密钥对 */
int hybrid_kex_client_round1(hybrid_kex_client_offer *offer,
                             uint8_t x_secret[X25519_KEYLEN],
                             uint8_t mlkem_sk[MLKEM768_SECLEN]) {
    if (!offer || !x_secret || !mlkem_sk) return HYBRID_ERR_INTERNAL;

    /* 1) X25519 临时密钥对 */
    EVP_PKEY *xkey = NULL;
    if (x25519_keygen(&xkey, offer->x25519_pubkey, x_secret) != HYBRID_OK)
        return HYBRID_ERR_CRYPTO;
    EVP_PKEY_free(xkey);

    /* 2) ML-KEM-768 密钥对 */
    EVP_PKEY *ml_pub = NULL, *ml_priv = NULL;
    if (mlkem768_keygen(&ml_pub, &ml_priv,
                        offer->mlkem_pubkey, mlkem_sk) != HYBRID_OK)
        return HYBRID_ERR_CRYPTO;
    EVP_PKEY_free(ml_pub);
    EVP_PKEY_free(ml_priv);

    return HYBRID_OK;
}

/* 【MOD-K10】服务端: X25519 派生 + ML-KEM 封装 → XOR 合并共享密钥 */
int hybrid_kex_server_round(const hybrid_kex_client_offer *offer,
                            hybrid_kex_server_reply *reply,
                            uint8_t shared[HYBRID_SS_LEN]) {
    if (!offer || !reply || !shared) return HYBRID_ERR_INTERNAL;

    uint8_t x_shared[32] = {0};
    uint8_t kem_shared[MLKEM768_SHAREDLEN] = {0};
    uint8_t x_priv[32] = {0};

    /* 1) X25519: 生成服务端临时密钥对, 与客户端公钥派生共享密钥 */
    EVP_PKEY *xkey = NULL;
    if (x25519_keygen(&xkey, reply->x25519_pubkey, x_priv) != HYBRID_OK)
        return HYBRID_ERR_CRYPTO;
    EVP_PKEY_free(xkey);
    if (x25519_derive(x_priv, offer->x25519_pubkey, x_shared) != HYBRID_OK)
        return HYBRID_ERR_CRYPTO;

    /* 2) ML-KEM-768: 用客户端公钥封装, 得到密文 + 共享密钥 */
    if (mlkem768_encapsulate(offer->mlkem_pubkey,
                             reply->mlkem_ciphertext, kem_shared) != HYBRID_OK)
        return HYBRID_ERR_CRYPTO;

    /* 3) XOR 合并两个共享密钥 → 最终混合 shared secret */
    xor_shared_secret(shared, x_shared, kem_shared);

    /* 安全擦除敏感临时量 */
    OPENSSL_cleanse(x_priv, sizeof(x_priv));
    OPENSSL_cleanse(x_shared, sizeof(x_shared));
    return HYBRID_OK;
}

/* 【MOD-K11】客户端第 2 阶段: X25519 派生 + ML-KEM 解封装 → XOR 合并 */
int hybrid_kex_client_round2(const uint8_t x_secret[X25519_KEYLEN],
                             const uint8_t mlkem_sk[MLKEM768_SECLEN],
                             const hybrid_kex_server_reply *reply,
                             uint8_t shared[HYBRID_SS_LEN]) {
    if (!x_secret || !mlkem_sk || !reply || !shared) return HYBRID_ERR_INTERNAL;

    uint8_t x_shared[32] = {0};
    uint8_t kem_shared[MLKEM768_SHAREDLEN] = {0};

    /* 1) X25519 派生 */
    if (x25519_derive(x_secret, reply->x25519_pubkey, x_shared) != HYBRID_OK)
        return HYBRID_ERR_CRYPTO;

    /* 2) ML-KEM-768 解封装 */
    if (mlkem768_decapsulate(mlkem_sk, reply->mlkem_ciphertext, kem_shared) != HYBRID_OK)
        return HYBRID_ERR_CRYPTO;

    /* 3) XOR 合并 */
    xor_shared_secret(shared, x_shared, kem_shared);

    OPENSSL_cleanse(x_shared, sizeof(x_shared));
    OPENSSL_cleanse(kem_shared, sizeof(kem_shared));
    return HYBRID_OK;
}
