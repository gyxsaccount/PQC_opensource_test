// ============================================================================
// hybrid_signature.c  --  ML-DSA-44 + Ed25519 混合签名实现 (补全版)
//
// ============================ 自实现声明 ===================================
// 本文件为 [SELF-IMPLEMENT] 自实现代码。声明如下:
//
// 1. libssh2 (1.11.x 及以下) 原生【不具备】以下能力, 需本自实现补齐:
//    a) 后量子签名算法注册: libssh2 的 hostkey.c 只有经典签名
//       (ssh-ed25519/rsa-sha2/ecdsa), 没有 "ssh-ed25519+ml-dsa-44";
//    b) 混合签名 framing: SSH 协议无"双签名拼接"的格式定义;
//    c) 混合密钥的序列化/解析 (len-prefix framing)。
// 2. 算法原语(ML-DSA-44 / Ed25519)来自 OpenSSL 3.5+, 非本文件实现;
//    本文件实现的是【SSH 协议层的混合签名封装与验证逻辑】。
// 3. 直接运行本文件无法独立工作, 必须:
//    - 链接 OpenSSL 3.5+ (libcrypto)
//    - 接入 libssh2 的 hostkey.c (见下方 修改点标记)
// 4. 若改用它: 可将 ML-DSA 部分替换为 liboqs (OQS_SIGN_new 等), 接口不变。
// ============================================================================
//  修改点标记: 每一处改动用 【MOD-S#】 标注, 对应
//              demo/results/code_modification_points.md 第 4/8 节。
// ============================================================================
#include "hybrid_signature.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* ---------- 序列化 framing (SSH 风格: uint32 big-endian length + data) ---------- */
/* 【MOD-S1】写 blob: [len(4)][data] */
static int write_blob(uint8_t **buf, size_t *remain, const uint8_t *data, uint32_t len) {
    if (*remain < 4 + len) return -1;
    (*buf)[0] = (uint8_t)(len >> 24);
    (*buf)[1] = (uint8_t)(len >> 16);
    (*buf)[2] = (uint8_t)(len >> 8);
    (*buf)[3] = (uint8_t)(len >> 0);
    memcpy(*buf + 4, data, len);
    *buf += 4 + len;
    *remain -= 4 + len;
    return 0;
}

/* 【MOD-S2】读 blob */
static int read_blob(const uint8_t **buf, size_t *remain, const uint8_t **data, uint32_t *len) {
    if (*remain < 4) return -1;
    *len = ((uint32_t)(*buf)[0] << 24) | ((uint32_t)(*buf)[1] << 16) |
           ((uint32_t)(*buf)[2] << 8)  |  (uint32_t)(*buf)[3];
    *buf += 4; *remain -= 4;
    if (*remain < *len) return -1;
    *data = *buf;
    *buf += *len;
    *remain -= *len;
    return 0;
}

/* ---------- 内部密码原语 (OpenSSL 3.5+ 真实 API) ---------- */

/* 【MOD-S3】Ed25519 密钥对生成 (真实 API 已补全) */
static int ed25519_keygen(uint8_t pub[ED25519_PUBLEN], uint8_t sec[ED25519_SECLEN]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) return -1;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    EVP_PKEY_CTX_free(ctx);

    /* Ed25519 私钥 = 32字节种子 || 32字节公钥 */
    size_t publen = ED25519_PUBLEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &publen) <= 0) {
        EVP_PKEY_free(pkey); return -1;
    }
    size_t secseed = 32;   /* 只取种子部分 */
    if (EVP_PKEY_get_raw_private_key(pkey, sec, &secseed) <= 0) {
        EVP_PKEY_free(pkey); return -1;
    }
    /* sec[0..31] = 种子; sec[32..63] = 公钥 (libssh2 约定存 64 字节) */
    memcpy(sec + 32, pub, ED25519_PUBLEN);
    EVP_PKEY_free(pkey);
    return 0;
}

/* 【MOD-S4】Ed25519 签名 (真实 API) */
static int ed25519_sign(const uint8_t sec[ED25519_SECLEN],
                        const uint8_t *msg, size_t msg_len,
                        uint8_t sig[ED25519_SIGLEN]) {
    /* 用种子构造私钥对象 */
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sec, 32);
    if (!pkey) return -1;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) { EVP_PKEY_free(pkey); return -1; }

    size_t siglen = ED25519_SIGLEN;
    if (EVP_DigestSignInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0 ||
        EVP_DigestSign(mctx, sig, &siglen, msg, msg_len) <= 0) {
        EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey);
        return -1;
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return (siglen == ED25519_SIGLEN) ? 0 : -1;
}

/* 【MOD-S5】Ed25519 验证 (真实 API) */
static int ed25519_verify(const uint8_t pub[ED25519_PUBLEN],
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t sig[ED25519_SIGLEN]) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, ED25519_PUBLEN);
    if (!pkey) return -1;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) { EVP_PKEY_free(pkey); return -1; }

    int ret = -1;
    if (EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0) {
        EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey);
        return -1;
    }
    ret = EVP_DigestVerify(mctx, sig, ED25519_SIGLEN, msg, msg_len);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return (ret == 1) ? 0 : -1;
}

/* 【MOD-S6】ML-DSA-44 密钥对生成 (OpenSSL 3.5+, 真实 API) */
static int mldsa44_keygen(uint8_t pub[MLDSA44_PUBLEN], uint8_t sec[MLDSA44_SECLEN]) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, NULL, "ML-DSA-44");
    if (!pkey) return -1;

    size_t publen = MLDSA44_PUBLEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &publen) <= 0) {
        EVP_PKEY_free(pkey); return -1;
    }
    size_t seclen = MLDSA44_SECLEN;
    if (EVP_PKEY_get_raw_private_key(pkey, sec, &seclen) <= 0) {
        EVP_PKEY_free(pkey); return -1;
    }
    EVP_PKEY_free(pkey);
    return 0;
}

/* 【MOD-S7】ML-DSA-44 签名 (真实 API: 预哈希模式) */
static int mldsa44_sign(const uint8_t sec[MLDSA44_SECLEN],
                        const uint8_t *msg, size_t msg_len,
                        uint8_t sig[MLDSA44_SIGLEN], size_t *siglen_out) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_MLDSA44, NULL, sec, MLDSA44_SECLEN);
    if (!pkey) return -1;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) { EVP_PKEY_free(pkey); return -1; }

    size_t siglen = MLDSA44_SIGLEN;
    /* 注: ML-DSA 在 OpenSSL 3.5 使用 "ML-DSA-44" digest 名做纯签名 (pure) */
    if (EVP_DigestSignInit_ex(mctx, NULL, "ML-DSA-44", NULL, NULL, pkey, NULL) <= 0 ||
        EVP_DigestSign(mctx, sig, &siglen, msg, msg_len) <= 0) {
        EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey);
        return -1;
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    *siglen_out = siglen;
    return 0;
}

/* 【MOD-S8】ML-DSA-44 验证 (真实 API) */
static int mldsa44_verify(const uint8_t pub[MLDSA44_PUBLEN],
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t sig[MLDSA44_SIGLEN], size_t siglen) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_MLDSA44, NULL, pub, MLDSA44_PUBLEN);
    if (!pkey) return -1;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) { EVP_PKEY_free(pkey); return -1; }

    int ret = -1;
    if (EVP_DigestVerifyInit_ex(mctx, NULL, "ML-DSA-44", NULL, NULL, pkey, NULL) <= 0) {
        EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey);
        return -1;
    }
    ret = EVP_DigestVerify(mctx, sig, siglen, msg, msg_len);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return (ret == 1) ? 0 : -1;
}

/* ---------- 公开 API (已补全, 替换原 placeholder) ---------- */

/* 【MOD-S9】混合密钥生成: Ed25519 + ML-DSA-44 密钥对 + 拼接序列化 */
int hybrid_sign_keygen(uint8_t *hybrid_pub, size_t *hybrid_pub_len,
                       uint8_t *hybrid_sec, size_t *hybrid_sec_len) {
    if (!hybrid_pub || !hybrid_pub_len || !hybrid_sec || !hybrid_sec_len)
        return -1;

    uint8_t ed_pub[ED25519_PUBLEN], ed_sec[ED25519_SECLEN];
    uint8_t ml_pub[MLDSA44_PUBLEN], ml_sec[MLDSA44_SECLEN];

    /* 真实密钥生成 */
    if (ed25519_keygen(ed_pub, ed_sec) != 0) return -1;
    if (mldsa44_keygen(ml_pub, ml_sec) != 0) return -1;

    /* 构造混合公钥: len(ed_pub)||ed_pub||len(ml_pub)||ml_pub */
    size_t pub_need = 4 + ED25519_PUBLEN + 4 + MLDSA44_PUBLEN;
    if (*hybrid_pub_len < pub_need) { *hybrid_pub_len = pub_need; return -1; }
    size_t sec_need = 4 + ED25519_SECLEN + 4 + MLDSA44_SECLEN;
    if (*hybrid_sec_len < sec_need) { *hybrid_sec_len = sec_need; return -1; }

    uint8_t *p = hybrid_pub; size_t r = *hybrid_pub_len;
    write_blob(&p, &r, ed_pub, ED25519_PUBLEN);
    write_blob(&p, &r, ml_pub, MLDSA44_PUBLEN);
    *hybrid_pub_len = p - hybrid_pub;

    p = hybrid_sec; r = *hybrid_sec_len;
    write_blob(&p, &r, ed_sec, ED25519_SECLEN);
    write_blob(&p, &r, ml_sec, MLDSA44_SECLEN);
    *hybrid_sec_len = p - hybrid_sec;

    OPENSSL_cleanse(ed_sec, sizeof(ed_sec));
    OPENSSL_cleanse(ml_sec, sizeof(ml_sec));
    return 0;
}

/* 【MOD-S10】混合签名: Ed25519 签名 + ML-DSA-44 签名 + 拼接 */
int hybrid_sign(const uint8_t *hybrid_sec,
                const uint8_t *msg, size_t msg_len,
                uint8_t *hybrid_sig, size_t *hybrid_sig_len) {
    /* 解析组合私钥 */
    const uint8_t *ed_sec, *ml_sec;
    uint32_t ed_sec_len, ml_sec_len;
    const uint8_t *p = hybrid_sec;
    size_t r = 4 + ED25519_SECLEN + 4 + MLDSA44_SECLEN;
    if (read_blob(&p, &r, &ed_sec, &ed_sec_len) < 0) return -1;
    if (read_blob(&p, &r, &ml_sec, &ml_sec_len) < 0) return -1;
    if (ed_sec_len != ED25519_SECLEN || ml_sec_len != MLDSA44_SECLEN) return -1;

    /* 真实签名 */
    uint8_t ed_sig[ED25519_SIGLEN];
    if (ed25519_sign(ed_sec, msg, msg_len, ed_sig) != 0) return -1;

    uint8_t ml_sig[MLDSA44_SIGLEN];
    size_t ml_sig_len = 0;
    if (mldsa44_sign(ml_sec, msg, msg_len, ml_sig, &ml_sig_len) != 0) return -1;

    /* 序列化混合签名: len(ed_sig)||ed_sig||len(ml_sig)||ml_sig */
    size_t need = 4 + ED25519_SIGLEN + 4 + ml_sig_len;
    if (*hybrid_sig_len < need) { *hybrid_sig_len = need; return -1; }

    uint8_t *out = hybrid_sig; size_t out_r = *hybrid_sig_len;
    write_blob(&out, &out_r, ed_sig, ED25519_SIGLEN);
    write_blob(&out, &out_r, ml_sig, (uint32_t)ml_sig_len);
    *hybrid_sig_len = out - hybrid_sig;
    return 0;
}

/* 【MOD-S11】混合签名验证 (AND 语义: 两个签名都通过) */
int hybrid_verify(const uint8_t *hybrid_pub, size_t hybrid_pub_len,
                  const uint8_t *msg, size_t msg_len,
                  const uint8_t *hybrid_sig, size_t hybrid_sig_len) {
    /* 解析混合公钥 */
    const uint8_t *ed_pub, *ml_pub;
    uint32_t ed_pub_len, ml_pub_len;
    const uint8_t *p = hybrid_pub;
    size_t r = hybrid_pub_len;
    if (read_blob(&p, &r, &ed_pub, &ed_pub_len) < 0) return -1;
    if (read_blob(&p, &r, &ml_pub, &ml_pub_len) < 0) return -1;
    if (ed_pub_len != ED25519_PUBLEN || ml_pub_len != MLDSA44_PUBLEN) return -1;

    /* 解析混合签名 */
    const uint8_t *ed_sig, *ml_sig;
    uint32_t ed_sig_len, ml_sig_len;
    p = hybrid_sig; r = hybrid_sig_len;
    if (read_blob(&p, &r, &ed_sig, &ed_sig_len) < 0) return -1;
    if (read_blob(&p, &r, &ml_sig, &ml_sig_len) < 0) return -1;

    /* AND 语义验证: 两个签名都必须有效 */
    if (ed25519_verify(ed_pub, msg, msg_len, ed_sig) != 0) return -1;
    if (mldsa44_verify(ml_pub, msg, msg_len, ml_sig, ml_sig_len) != 0) return -1;

    return 0;
}
