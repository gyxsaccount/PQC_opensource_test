package pqc.sasl;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

/**
 * 迁移点 P2：PQC-SIGN SASL 客户端（ML-DSA 挑战-响应认证）。
 * 服务器下发随机挑战，客户端用 ML-DSA-65 私钥对 "PQC-SIGN || 挑战 || 用户名" 签名，
 * 服务器用预注册的公钥验签，完成后量子身份认证（替代 CRAM-MD5/DIGEST-MD5 的弱哈希口令方案）。
 */
public final class PqcSaslClient implements SaslClient {

    private final String authorizationId;
    private final byte[] privateKey;
    private boolean complete;

    public PqcSaslClient(String authorizationId, byte[] privateKey) {
        this.authorizationId = authorizationId;
        this.privateKey = privateKey;
    }

    @Override
    public String getMechanismName() {
        return "PQC-SIGN";
    }

    @Override
    public boolean hasInitialResponse() {
        return false;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        try {
            String user = authorizationId != null ? authorizationId : "anonymous";
            byte[] input = ("PQC-SIGN\0" + new String(challenge, StandardCharsets.ISO_8859_1) + "\0" + user)
                    .getBytes(StandardCharsets.UTF_8);
            KeyFactory kf = KeyFactory.getInstance("ML-DSA");
            PrivateKey pk = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            Signature sig = Signature.getInstance("ML-DSA");
            sig.initSign(pk);
            sig.update(input);
            String resp = user + ":" + Base64.getEncoder().encodeToString(sig.sign());
            complete = true;
            return resp.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new SaslException("ML-DSA 签名失败: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean isComplete() {
        return complete;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) {
        throw new UnsupportedOperationException("PQC-SIGN 不提供安全层封装");
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) {
        throw new UnsupportedOperationException("PQC-SIGN 不提供安全层封装");
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        return null;
    }

    @Override
    public void dispose() {
        complete = true;
    }
}
