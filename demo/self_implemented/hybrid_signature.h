// ============================================================================
// hybrid_signature.h  --  ML-DSA-44 (Dilithium) + Ed25519 混合签名自实现
//
// 标注: [SELF-IMPLEMENT] — SSH 协议层尚无标准混合签名格式,
//       此文件参考 IETF draft-ssh-hybrid-signatures-04 实现。
//
// 依赖版本:
//   - OpenSSL >= 3.5.0 （原生支持 ML-DSA-44, EVP_SIGNATURE API）
//     或 liboqs >= 0.12.0 + oqs-provider >= 0.8.0
//   - 标准: FIPS 204 (ML-DSA), RFC 8709 (Ed25519 SSH)
//
// 混合签名格式 (draft):
//   "ssh-ed25519+ml-dsa-44" — 签名 = len(ed25519_sig) || ed25519_sig || len(ml-dsa_sig) || ml-dsa_sig
//   验证: 两端任一通过即为合法(OR 语义, 用于迁移过渡)
//   更强: AND 语义 → 两个签名都需验证通过
//
// 主机密钥格式:
//   "ssh-ed25519+ml-dsa-44" — 公钥 = len(ed25519_pub) || ed25519_pub || len(ml-dsa_pub) || ml-dsa_pub
// ============================================================================
#ifndef HYBRID_SIGNATURE_H
#define HYBRID_SIGNATURE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 常量 ---------- */
#define ED25519_PUBLEN      32
#define ED25519_SIGLEN      64
#define ED25519_SECLEN      64      /* seed + pub */

#define MLDSA44_PUBLEN      1312    /* ML-DSA-44 公钥 */
#define MLDSA44_SECLEN      2560    /* ML-DSA-44 私钥 */
#define MLDSA44_SIGLEN      2420    /* ML-DSA-44 签名 */

#define HYBRID_SIG_ALGO     "ssh-ed25519+ml-dsa-44"
#define HYBRID_PUBKEY_ALGO  "ssh-ed25519+ml-dsa-44"

/* ---------- API ---------- */

/**
 * hybrid_sign_keygen()  [SELF-IMPLEMENT]
 *
 * 生成 Ed25519 + ML-DSA-44 混合密钥对。
 * 公钥格式: len(ed25519_pub) || ed25519_pub || len(ml-dsa_pub) || ml-dsa_pub
 *
 * @param hybrid_pub  [out] 混合公钥 (serialized)
 * @param hybrid_pub_len [in/out] 输入缓冲区大小, 输出实际长度
 * @param hybrid_sec  [out] 混合私钥 (两个私钥拼接)
 * @param hybrid_sec_len [in/out] 同上
 * @return 0=成功, -1=失败
 */
int hybrid_sign_keygen(uint8_t *hybrid_pub, size_t *hybrid_pub_len,
                       uint8_t *hybrid_sec, size_t *hybrid_sec_len);

/**
 * hybrid_sign()  [SELF-IMPLEMENT]
 *
 * 对消息 m 同时执行 Ed25519 签名 + ML-DSA-44 签名, 输出混合签名。
 *
 * 签名格式: len(ed25519_sig) || ed25519_sig || len(ml-dsa_sig) || ml-dsa_sig
 *
 * @param hybrid_sec  混合私钥
 * @param msg         消息
 * @param msg_len     消息长度
 * @param hybrid_sig  [out] 混合签名
 * @param hybrid_sig_len [in/out] 输入缓冲区大小, 输出实际长度
 * @return 0=成功, -1=失败
 */
int hybrid_sign(const uint8_t *hybrid_sec,
                const uint8_t *msg, size_t msg_len,
                uint8_t *hybrid_sig, size_t *hybrid_sig_len);

/**
 * hybrid_verify()  [SELF-IMPLEMENT]
 *
 * 验证混合签名。AND 语义: 两个子签名都需通过 (推荐)。
 * 迁移过渡期可改为 OR 语义。
 *
 * @param hybrid_pub  混合公钥
 * @param hybrid_pub_len  公钥长度
 * @param msg         消息
 * @param msg_len     消息长度
 * @param hybrid_sig  混合签名
 * @param hybrid_sig_len 签名长度
 * @return 0=验证通过, -1=失败
 */
int hybrid_verify(const uint8_t *hybrid_pub, size_t hybrid_pub_len,
                  const uint8_t *msg, size_t msg_len,
                  const uint8_t *hybrid_sig, size_t hybrid_sig_len);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_SIGNATURE_H */