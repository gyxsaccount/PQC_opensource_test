package pqc.sasl;

import java.security.Provider;

/**
 * 迁移点 P2：注册 PQC-SIGN SASL 机制的 JCA Provider。
 * JDK 的 Sasl.createSaslClient 通过 Security.getProviders() 查找类型为
 * "SaslClientFactory"、算法名为机制名的服务，因此必须用 Provider 注册（META-INF/services 不生效）。
 */
public final class PqcSaslProvider extends Provider {

    public PqcSaslProvider() {
        super("PqcSasl", 1.0, "PQC-SIGN (ML-DSA challenge-response) SASL provider");
        put("SaslClientFactory.PQC-SIGN", PqcSaslClientFactory.class.getName());
    }
}
