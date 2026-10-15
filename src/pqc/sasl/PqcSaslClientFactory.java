package pqc.sasl;

import java.security.Security;
import java.util.Base64;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

/**
 * 迁移点 P2：PQC-SIGN SaslClientFactory。
 * 通过 META-INF/services/javax.security.sasl.SaslClientFactory 注册，
 * Angus Mail SMTPTransport 用标准 Sasl API 按服务端 AUTH 列表自动发现本工厂。
 * ML-DSA 私钥通过会话属性 mail.smtp.sasl.pqc.privateKey（Base64）注入。
 */
public final class PqcSaslClientFactory implements SaslClientFactory {

    @Override
    public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol,
            String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
        for (String m : mechanisms) {
            if ("PQC-SIGN".equals(m)) {
                byte[] priv = null;
                if (props != null && props.get("mail.smtp.sasl.pqc.privateKey") != null) {
                    priv = Base64.getDecoder().decode(
                            String.valueOf(props.get("mail.smtp.sasl.pqc.privateKey")));
                }
                if (priv == null && Security.getProperty("pqc.sasl.mldsa.privateKey") != null) {
                    priv = Base64.getDecoder().decode(
                            Security.getProperty("pqc.sasl.mldsa.privateKey"));
                }
                return new PqcSaslClient(authorizationId, priv);
            }
        }
        return null;
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
        return new String[]{"PQC-SIGN"};
    }
}
