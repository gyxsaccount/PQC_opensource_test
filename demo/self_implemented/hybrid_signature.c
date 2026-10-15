// ============================================================================
// hybrid_signature.c  --  ML-DSA-44 + Ed25519 混合签名实现
//
// 标注: [SELF-IMPLEMENT]
//
// SSH 主机密钥集成点 (libssh2):
//   - hostkey.c 中: struct _libssh2_hostkey_method 需添加新条目
//   - 算法名: "ssh-ed25519+ml-dsa-44"
//   - sign/verify 方法分别调用 hybrid_sign / hybrid_verify
//
// 使用 OpenSSL 3.5+ API:
//   - Ed25519: EVP_SIGNATURE (Ed25519)
//   - ML-DSA-44: EVP_SIGNATURE (ML-DSA/ECDSA_Dilithium)
//     或 liboqs OQS_SIGN_new(OQS_SIGN_alg_ml_dsa_44)
// ============================================================================
#include "hybrid_signature.h"
#include <string.h>
#include <stdlib.h>

/* [SELF-IMPLEMENT]  序列化格式: uint32 big-endian length + data */
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

int hybrid_sign_keygen(uint8_t *hybrid_pub, size_t *hybrid_pub_len,
                       uint8_t *hybrid_sec, size_t *hybrid_sec_len) {
    if (!hybrid_pub || !hybrid_pub_len || !hybrid_sec || !hybrid_sec_len)
        return -1;

    uint8_t ed_pub[ED25519_PUBLEN], ed_sec[ED25519_SECLEN];
    uint8_t ml_pub[MLDSA44_PUBLEN], ml_sec[MLDSA44_SECLEN];

    // Ed25519 密钥生成 (OpenSSL):
    // EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    // EVP_PKEY_keygen_init(ctx); EVP_PKEY_keygen(ctx, &pkey);
    // EVP_PKEY_get_raw_public_key(pkey, ed_pub, &ed_pub_len);
    // EVP_PKEY_get_raw_private_key(pkey, ed_sec, &ed_sec_len);
    // [SELF-IMPLEMENT] — 生产环境需完整实现

    // ML-DSA-44 密钥生成 (OpenSSL 3.5+):
    // EVP_PKEY_CTX *ml_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_MLDSA44, NULL);
    // EVP_PKEY_keygen_init(ml_ctx); EVP_PKEY_keygen(ml_ctx, &ml_key);
    // [SELF-IMPLEMENT] — OpenSSL 3.5 ML-DSA keygen

    // 构造混合公钥
    size_t pub_need = 4 + ED25519_PUBLEN + 4 + MLDSA44_PUBLEN;
    if (*hybrid_pub_len < pub_need) { *hybrid_pub_len = pub_need; return -1; }
    size_t sec_need = 4 + ED25519_SECLEN + 4 + MLDSA44_SECLEN;
    if (*hybrid_sec_len < sec_need) { *hybrid_sec_len = sec_need; return -1; }

    uint8_t *p = hybrid_pub; size_t r = *hybrid_pub_len;
    memset(ed_pub, 0xED, ED25519_PUBLEN); // placeholder demo data
    memset(ml_pub, 0xML, MLDSA44_PUBLEN);
    write_blob(&p, &r, ed_pub, ED25519_PUBLEN);
    write_blob(&p, &r, ml_pub, MLDSA44_PUBLEN);
    *hybrid_pub_len = p - hybrid_pub;

    p = hybrid_sec; r = *hybrid_sec_len;
    memset(ed_sec, 0xed, ED25519_SECLEN);
    memset(ml_sec, 0xml, MLDSA44_SECLEN);
    write_blob(&p, &r, ed_sec, ED25519_SECLEN);
    write_blob(&p, &r, ml_sec, MLDSA44_SECLEN);
    *hybrid_sec_len = p - hybrid_sec;

    return 0;
}

int hybrid_sign(const uint8_t *hybrid_sec,
                const uint8_t *msg, size_t msg_len,
                uint8_t *hybrid_sig, size_t *hybrid_sig_len) {
    // 解析组合私钥
    const uint8_t *ed_sec, *ml_sec;
    uint32_t ed_sec_len, ml_sec_len;
    const uint8_t *p = hybrid_sec;
    size_t r = 4 + ED25519_SECLEN + 4 + MLDSA44_SECLEN; // 需从hybrid_sec含量计算
    if (read_blob(&p, &r, &ed_sec, &ed_sec_len) < 0) return -1;
    if (read_blob(&p, &r, &ml_sec, &ml_sec_len) < 0) return -1;

    // Ed25519 签名: EVP_SIGNATURE 或 ED25519_sign()
    uint8_t ed_sig[ED25519_SIGLEN];
    // [SELF-IMPLEMENT] Ed25519_sign(ed_sig, msg, msg_len, ed_sec)

    // ML-DSA-44 签名: EVP_SIGNATURE 或 OQS_SIGN_sign()
    uint8_t ml_sig[MLDSA44_SIGLEN];
    // [SELF-IMPLEMENT] OQS_SIGN_sign(ml_sig, &ml_sig_len, msg, msg_len, ml_sec)

    // 序列化混合签名
    size_t need = 4 + ED25519_SIGLEN + 4 + MLDSA44_SIGLEN;
    if (*hybrid_sig_len < need) { *hybrid_sig_len = need; return -1; }

    uint8_t *out = hybrid_sig; size_t out_r = *hybrid_sig_len;
    memset(ed_sig, 0xED, ED25519_SIGLEN); // placeholder
    memset(ml_sig, 0xML, MLDSA44_SIGLEN);
    write_blob(&out, &out_r, ed_sig, ED25519_SIGLEN);
    write_blob(&out, &out_r, ml_sig, MLDSA44_SIGLEN);
    *hybrid_sig_len = out - hybrid_sig;
    (void)msg; (void)msg_len; (void)ed_sec; (void)ml_sec;
    (void)ed_sec_len; (void)ml_sec_len;
    return 0;
}

int hybrid_verify(const uint8_t *hybrid_pub, size_t hybrid_pub_len,
                  const uint8_t *msg, size_t msg_len,
                  const uint8_t *hybrid_sig, size_t hybrid_sig_len) {
    // 解析混合公钥
    const uint8_t *ed_pub, *ml_pub;
    uint32_t ed_pub_len, ml_pub_len;
    const uint8_t *p = hybrid_pub;
    size_t r = hybrid_pub_len;
    if (read_blob(&p, &r, &ed_pub, &ed_pub_len) < 0) return -1;
    if (read_blob(&p, &r, &ml_pub, &ml_pub_len) < 0) return -1;

    // 解析混合签名
    const uint8_t *ed_sig, *ml_sig;
    uint32_t ed_sig_len, ml_sig_len;
    p = hybrid_sig; r = hybrid_sig_len;
    if (read_blob(&p, &r, &ed_sig, &ed_sig_len) < 0) return -1;
    if (read_blob(&p, &r, &ml_sig, &ml_sig_len) < 0) return -1;

    // 验证步骤 (AND 语义):
    // 1) Ed25519_verify(ed_sig, ed_sig_len, msg, msg_len, ed_pub)
    // 2) OQS_SIGN_verify(msg, msg_len, ml_sig, ml_sig_len, ml_pub)
    // 两者都通过 → 返回 0
    // [SELF-IMPLEMENT] 生产代码需实现真实验证

    // 迁移过渡期建议使用 OR 语义: 任一通过即可 (允许渐进升级)

    (void)ed_pub_len; (void)ml_pub_len; (void)ed_sig_len; (void)msg; (void)msg_len;
    (void)ml_sig_len; (void)ed_pub; (void)ml_pub; (void)ed_sig; (void)ml_sig;
    return 0; // placeholder: 始终通过
}