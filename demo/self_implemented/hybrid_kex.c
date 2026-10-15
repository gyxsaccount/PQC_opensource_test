// ============================================================================
// hybrid_kex.c  --  ML-KEM-768 + X25519 混合密钥交换实现
//
// 标注: [SELF-IMPLEMENT] — SSH 协议层尚无标准混合 KEX 实现,
//       此文件为自实现参考代码, 需接入 libssh2 的 transport.c。
//
// 编译依赖:
//   - OpenSSL 3.5+ headers & libs (libcrypto.lib / libcrypto.a)
//     可选: 若使用 liboqs → liboqs.lib + oqs-provider
//
// SSH 协议集成点 (libssh2):
//   - 在 session->kex_list 中注册新条目:
//     { "mlkem768x25519-sha256", &kex_mlkem768x25519 }
//   - _libssh2_kex_method_mlkem768x25519 实现 kex_exchange_func_t
//   - 调用 hybrid_kex_client_round1/2 + hybrid_kex_server_round
//   - shared secret → SHA256 → 参与 exchange_hash (SSH 标准流程)
// ============================================================================
#include "hybrid_kex.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <string.h>
#include <stdlib.h>

/* ---------- 内部辅助 ---------- */
/* [SELF-IMPLEMENT]  XOR 两个 32 字节共享密钥 */
static void xor_shared_secret(uint8_t out[32],
                              const uint8_t a[32],
                              const uint8_t b[32]) {
    for (int i = 0; i < 32; i++) out[i] = a[i] ^ b[i];
}

/* [SELF-IMPLEMENT]  生成 X25519 密钥对 (OpenSSL 3.x EVP API) */
static int x25519_keygen(EVP_PKEY **pkey, uint8_t pubkey[32], uint8_t privkey[32]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return HYBRID_ERR_CRYPTO;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return HYBRID_ERR_CRYPTO; }
    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) { EVP_PKEY_CTX_free(ctx); return HYBRID_ERR_CRYPTO; }
    EVP_PKEY_CTX_free(ctx);

    // 导出公钥
    size_t publen = 32;
    if (EVP_PKEY_get_raw_public_key(key, pubkey, &publen) <= 0) {
        EVP_PKEY_free(key); return HYBRID_ERR_CRYPTO;
    }
    size_t privlen = 32;
    if (EVP_PKEY_get_raw_private_key(key, privkey, &privlen) <= 0) {
        EVP_PKEY_free(key); return HYBRID_ERR_CRYPTO;
    }
    *pkey = key;
    return HYBRID_OK;
}

/* [SELF-IMPLEMENT]  X25519 ECDH 派生 */
static int x25519_derive(const uint8_t priv[32], const uint8_t peer_pub[32],
                         uint8_t shared[32]) {
    EVP_PKEY *our = NULL;
    if (x25519_keygen(&our, NULL, NULL) != HYBRID_OK) return HYBRID_ERR_CRYPTO;
    // 实际应直接用原始私钥构造 EVP_PKEY, 简化写法:
    // 实际使用: EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32)
    // 但这里演示逻辑; 生产代码需正确处理
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    if (!peer) { EVP_PKEY_free(our); return HYBRID_ERR_CRYPTO; }

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(our, NULL);
    if (!dctx) { EVP_PKEY_free(our); EVP_PKEY_free(peer); return HYBRID_ERR_CRYPTO; }
    if (EVP_PKEY_derive_init(dctx) <= 0) { EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(our); EVP_PKEY_free(peer); return HYBRID_ERR_CRYPTO; }
    if (EVP_PKEY_derive_set_peer(dctx, peer) <= 0) { EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(our); EVP_PKEY_free(peer); return HYBRID_ERR_CRYPTO; }

    size_t slen = 32;
    if (EVP_PKEY_derive(dctx, shared, &slen) <= 0) {
        EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(our); EVP_PKEY_free(peer);
        return HYBRID_ERR_CRYPTO;
    }
    EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(our); EVP_PKEY_free(peer);
    return HYBRID_OK;
}

/* [SELF-IMPLEMENT]  ML-KEM-768 密钥对生成 (OpenSSL 3.5+ EVP_KEM API) */
/*  注: OpenSSL 3.5 中 ML-KEM 通过 EVP_PKEY 的 KEM 操作实现 */
static int mlkem768_keygen(EVP_PKEY **pub, EVP_PKEY **priv,
                           uint8_t pubkey[MLKEM768_PUBLEN],
                           uint8_t seckey[MLKEM768_SECLEN]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_MLKEM768, NULL);
    if (!ctx) return HYBRID_ERR_CRYPTO;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return HYBRID_ERR_CRYPTO; }
    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) { EVP_PKEY_CTX_free(ctx); return HYBRID_ERR_CRYPTO; }
    EVP_PKEY_CTX_free(ctx);

    // OpenSSL 3.5 的 ML-KEM 公/私钥可能是 DER 编码的; 实际需用 i2d_PUBKEY
    // 此处仅为 API 示例原型:
    // if (EVP_PKEY_get_raw_public_key(key, pubkey, &pubkey_len) <= 0) ...
    // [SELF-IMPLEMENT] 注意: OpenSSL 3.5.0 β1 中的 ML-KEM raw 接口可能为 OSSL_PKEY_PARAM_PUB_KEY

    *pub = key;
    // 完整实现需从 EVP_PKEY 提取 raw pubkey/privkey
    (void)pubkey; (void)seckey; // placeholder

    // 如果是使用 liboqs: OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    // OQS_KEM_keypair(kem, pubkey, seckey);
    // 此处 hybrid demo 仅展示接口骨架

    return HYBRID_OK;
}

/* 以下 API 实现函数为骨架, 完整实现需基于 OpenSSL 3.5+ EVP API 完成 */
/* 参考: https://github.com/openssl/openssl/blob/master/doc/man7/EVP_KEM.pod */

/* ---------- 公开 API 实现 ---------- */
int hybrid_kex_client_round1(hybrid_kex_client_offer *offer,
                             uint8_t x_secret[X25519_KEYLEN],
                             uint8_t mlkem_sk[MLKEM768_SECLEN]) {
    if (!offer || !x_secret || !mlkem_sk) return HYBRID_ERR_INTERNAL;
    EVP_PKEY *key = NULL, *mlkem_pub = NULL, *mlkem_priv = NULL;

    // 1) X25519 密钥对
    if (x25519_keygen(&key, offer->x25519_pubkey, x_secret) != HYBRID_OK)
        return HYBRID_ERR_CRYPTO;
    EVP_PKEY_free(key);

    // 2) ML-KEM-768 密钥对
    if (mlkem768_keygen(&mlkem_pub, &mlkem_priv,
                        offer->mlkem_pubkey, mlkem_sk) != HYBRID_OK)
        return HYBRID_ERR_CRYPTO;
    EVP_PKEY_free(mlkem_pub);
    EVP_PKEY_free(mlkem_priv);

    return HYBRID_OK;
}

int hybrid_kex_server_round(const hybrid_kex_client_offer *offer,
                            hybrid_kex_server_reply *reply,
                            uint8_t shared[HYBRID_SS_LEN]) {
    if (!offer || !reply || !shared) return HYBRID_ERR_INTERNAL;

    uint8_t x_shared[32], kem_shared[MLKEM768_SHAREDLEN];
    uint8_t x_priv[32];
    EVP_PKEY *x25519_key = NULL, *mlkem_eph = NULL, *mlkem_priv = NULL;

    // 1) X25519: 生成服务端临时密钥对, 计算共享密钥
    if (x25519_keygen(&x25519_key, reply->x25519_pubkey, x_priv) != HYBRID_OK)
        return HYBRID_ERR_CRYPTO;
    // 实际 derive 需要将 offer->x25519_pubkey 转为 EVP_PKEY
    // 此处从简, 用 x25519_derive 做演示
    (void)x_priv; // 应使用 EVP_PKEY_new_raw_private_key

    // 2) ML-KEM-768: 封装 (encapsulate)
    // EVP_PKEY *peer_mlkem = EVP_PKEY_new_raw_public_key(EVP_PKEY_MLKEM768, NULL,
    //                                                     offer->mlkem_pubkey, MLKEM768_PUBLEN);
    // EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(peer_mlkem, NULL);
    // EVP_PKEY_kem_encapsulate_init(kctx, NULL);
    // EVP_PKEY_kem_encapsulate(kctx, reply->mlkem_ciphertext, &ct_len, kem_shared, &ss_len);
    // [SELF-IMPLEMENT] 替换为上述真实调用

    // 3) XOR 两个 shared secret
    xor_shared_secret(shared, x_shared, kem_shared);

    EVP_PKEY_free(x25519_key);
    return HYBRID_OK;
}

int hybrid_kex_client_round2(const uint8_t x_secret[X25519_KEYLEN],
                             const uint8_t mlkem_sk[MLKEM768_SECLEN],
                             const hybrid_kex_server_reply *reply,
                             uint8_t shared[HYBRID_SS_LEN]) {
    if (!x_secret || !mlkem_sk || !reply || !shared) return HYBRID_ERR_INTERNAL;

    uint8_t x_shared[32] = {0}, kem_shared[MLKEM768_SHAREDLEN] = {0};

    // 1) X25519 派生: EVP_PKEY_new_raw_private_key → EVP_PKEY_derive_set_peer
    //    with reply->x25519_pubkey
    // [SELF-IMPLEMENT] 如 x25519_derive 所示

    // 2) ML-KEM-768 解封装:
    // EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_MLKEM768, NULL,
    //                                                 mlkem_sk, MLKEM768_SECLEN);
    // EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(priv, NULL);
    // EVP_PKEY_kem_decapsulate_init(kctx, NULL);
    // EVP_PKEY_kem_decapsulate(kctx, kem_shared, &ss_len, reply->mlkem_ciphertext, ct_len);

    // 3) XOR
    xor_shared_secret(shared, x_shared, kem_shared);
    (void)mlkem_sk; // placeholder
    (void)reply;

    return HYBRID_OK;
}