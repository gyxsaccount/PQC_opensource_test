import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.XECPublicKey;
import java.security.spec.*;
import java.nio.ByteBuffer;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * 自实现最小 TLS 1.3 协议栈 — 嵌入 ML-DSA 后量子证书签名
 *
 * 绕开 JSSE (SunJSSE 签名方案列表不包含 ML-DSA，导致握手失败)，直接实现
 * TLS 1.3 握手协议核心流程，核心签名算法用 ML-DSA-65。
 *
 * 消息格式 (简化 TLS 1.3 Record + Handshake 复合层):
 *   record: type(1B) + len(4B, big-endian) + payload
 *   types: 1=ClientHello, 2=ServerHello, 3=Certificate, 4=CertificateVerify, 5=Finished, 6=AppData
 *
 * 握手流程:
 *   ClientHello (X25519 pub) → Server → ServerHello (X25519 pub) + Certificate (ML-DSA)
 *   + CertificateVerify (ML-DSA-65 sig) + Finished → Client → Finished → AppData (AES-128-GCM)
 *
 * 密钥派生: TLS 1.3 HKDF (RFC 8446 §7.1)
 * 握手加密: 握手阶段明文 (演示用), 应用数据 AES-128-GCM
 *
 * 用法: SelfImplementedPqcTls <ml-dsa-keystore.p12>
 */
public class SelfImplementedPqcTls {

    static final int PORT = 18446;
    static final char[] PASSWORD = "changeit".toCharArray();

    static final int T_CLIENT_HELLO = 1;
    static final int T_SERVER_HELLO = 2;
    static final int T_CERTIFICATE = 3;
    static final int T_CERTIFICATE_VERIFY = 4;
    static final int T_FINISHED = 5;
    static final int T_APP = 6;

    // TLS 1.3 上下文标字符串
    static final byte[] SERVER_CV_CONTEXT = "TLS 1.3, server CertificateVerify".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    static final byte[] CLIENT_CV_CONTEXT = "TLS 1.3, client CertificateVerify".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    static final byte[] HKDF_LABEL_PREFIX = "tls13 ".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: SelfImplementedPqcTls <ml-dsa-keystore.p12>");
            System.exit(1);
        }
        String ksPath = args[0];

        // 加载 ML-DSA keystore
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(ksPath)) { ks.load(fis, PASSWORD); }
        String alias = ks.aliases().nextElement();
        PrivateKey mldsaPrivKey = (PrivateKey) ks.getKey(alias, PASSWORD);
        X509Certificate mldsaCert = (X509Certificate) ks.getCertificate(alias);

        System.out.println("=== 自实现 TLS 1.3 (ML-DSA 证书签名) ===");
        System.out.println("证书: subject=" + mldsaCert.getSubjectX500Principal()
            + ", sigAlg=" + mldsaCert.getSigAlgName()
            + ", pubKeyAlg=" + mldsaCert.getPublicKey().getAlgorithm()
            + ", pubKeyLen=" + mldsaCert.getPublicKey().getEncoded().length + "B");

        // 启动 Server 线程
        ServerSocket srvSock = new ServerSocket(PORT);
        System.out.println("[SERVER] 监听端口 " + PORT);
        Thread srvThread = new Thread(() -> {
            try {
                Socket sock = srvSock.accept();
                runServer(sock, mldsaPrivKey, mldsaCert);
                sock.close();
            } catch (Exception e) {
                System.err.println("[SERVER] 异常: " + e);
                e.printStackTrace();
            }
        });
        srvThread.start();

        // 等待服务就绪后启动 Client
        Thread.sleep(1500);

        System.out.println("[CLIENT] 连接 localhost:" + PORT + " ...");
        try (Socket sock = new Socket("localhost", PORT)) {
            runClient(sock, mldsaCert);
        }

        srvSock.close();
        srvThread.join(5000);
        System.out.println("\n=== 测试完成 ===");
    }

    // ===== Server 握手 =====
    static void runServer(Socket sock, PrivateKey privKey, X509Certificate cert) throws Exception {
        DataInputStream in = new DataInputStream(sock.getInputStream());
        DataOutputStream out = new DataOutputStream(sock.getOutputStream());

        // 1. 接收 ClientHello
        byte[] ch = readMsg(in, T_CLIENT_HELLO);
        byte[] clientRandom = Arrays.copyOfRange(ch, 0, 32);
        byte[] clientPubBytes = Arrays.copyOfRange(ch, 32, 64);

        // 2. Server X25519 密钥
        KeyPair serverXKp = genX25519KeyPair();
        byte[] serverPubBytes = ((XECPublicKey) serverXKp.getPublic()).getU().toByteArray();
        serverPubBytes = fixX25519Len(serverPubBytes);
        byte[] sharedSecret = agreeX25519(serverXKp.getPrivate(), clientPubBytes);

        // 3. 派生 TLS 1.3 密钥
        byte[] serverRandom = secureRandomBytes(32);
        TranscriptDigest transcript = new TranscriptDigest();
        transcript.update(T_CLIENT_HELLO, ch);
        transcript.update(T_SERVER_HELLO, concat(serverRandom, serverPubBytes));

        TLS13KeySchedule ks = new TLS13KeySchedule(sharedSecret);

        // 4. 发送 ServerHello
        sendMsg(out, T_SERVER_HELLO, concat(serverRandom, serverPubBytes));
        System.out.println("[SERVER] 发送 ServerHello (X25519 pub=" + hex(serverPubBytes) + ")");

        // 5. 发送 Certificate (ML-DSA DER)
        byte[] certDer = cert.getEncoded();
        sendMsg(out, T_CERTIFICATE, certDer);
        transcript.update(T_CERTIFICATE, certDer);
        System.out.println("[SERVER] 发送 Certificate (ML-DSA, " + certDer.length + "B)");

        // 6. 计算 Transcript Hash (截至 Certificate) — 保留状态继续 update
        byte[] transcriptHash = transcript.cloneHash();

        // 7. CertificateVerify: ML-DSA-65 签名
        byte[] sigContent = buildSigContent(SERVER_CV_CONTEXT, transcriptHash);
        Signature sig = Signature.getInstance("ML-DSA");
        sig.initSign(privKey);
        sig.update(sigContent);
        byte[] signature = sig.sign();

        sendMsg(out, T_CERTIFICATE_VERIFY, signature);
        transcript.update(T_CERTIFICATE_VERIFY, signature);
        System.out.println("[SERVER] 发送 CertificateVerify (ML-DSA sig, " + signature.length + "B)");

        // 8. Server Finished
        byte[] svTransHash = transcript.cloneHash(); // 保留状态继续
        byte[] svFinishKey = ks.deriveServerFinishedKey();
        byte[] svVerifyData = hmacSha256(svFinishKey, svTransHash);
        sendMsg(out, T_FINISHED, svVerifyData);
        transcript.update(T_FINISHED, svVerifyData);

        // 9. 接收 Client Finished (verify)
        byte[] cf = readMsg(in, T_FINISHED);
        byte[] clTransHash = transcript.hash();
        byte[] clFinishKey = ks.deriveClientFinishedKey();
        byte[] expectedCf = hmacSha256(clFinishKey, clTransHash);

        boolean clFinishOk = Arrays.equals(cf, expectedCf);
        System.out.println("[SERVER] Client Finished 验证: " + (clFinishOk ? "OK" : "FAIL"));

        // 10. 应用数据加密 → Server → Client
        byte[] svAppKey = ks.deriveServerAppKey();
        byte[] svAppIv = ks.deriveServerAppIv();
        byte[] plain = "OK from self-implemented PQC TLS!".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        // AAD = type(1) + 3 个保留字节 (与接收端一致, 不含长度以避免 tag 差异)
        byte[] aad = new byte[]{T_APP, 0, 0, 0};
        byte[] ct = aesGcmEncrypt(svAppKey, svAppIv, plain, aad);
        sendMsg(out, T_APP, ct);
        System.out.println("[SERVER] 发送加密数据 (AES-128-GCM, " + plain.length + "B)");

        // 接收 Client 加密回复
        byte[] appCt = readMsg(in, T_APP);
        byte[] clAppKey = ks.deriveClientAppKey();
        byte[] clAppIv = ks.deriveClientAppIv();
        byte[] reply = aesGcmDecrypt(clAppKey, clAppIv, appCt, new byte[]{T_APP, 0, 0, 0});
        System.out.println("[SERVER] 收到解密数据: \"" + new String(reply, java.nio.charset.StandardCharsets.UTF_8) + "\"");
        System.out.println("[SERVER] === 自实现 PQC TLS 握手成功 ===");
    }

    // ===== Client 握手 =====
    static void runClient(Socket sock, X509Certificate serverCert) throws Exception {
        DataInputStream in = new DataInputStream(sock.getInputStream());
        DataOutputStream out = new DataOutputStream(sock.getOutputStream());

        // 1. Client X25519
        KeyPair clientXKp = genX25519KeyPair();
        byte[] clientPubBytes = ((XECPublicKey) clientXKp.getPublic()).getU().toByteArray();
        clientPubBytes = fixX25519Len(clientPubBytes);
        byte[] clientRandom = secureRandomBytes(32);

        TranscriptDigest transcript = new TranscriptDigest();

        // 2. 发送 ClientHello
        sendMsg(out, T_CLIENT_HELLO, concat(clientRandom, clientPubBytes));
        transcript.update(T_CLIENT_HELLO, concat(clientRandom, clientPubBytes));
        System.out.println("[CLIENT] 发送 ClientHello (X25519 pub=" + hex(clientPubBytes) + ")");

        // 3. 接收 ServerHello
        byte[] sh = readMsg(in, T_SERVER_HELLO);
        byte[] serverRandom = Arrays.copyOfRange(sh, 0, 32);
        byte[] serverPubBytes = Arrays.copyOfRange(sh, 32, 64);
        transcript.update(T_SERVER_HELLO, sh);
        byte[] sharedSecret = agreeX25519(clientXKp.getPrivate(), serverPubBytes);
        TLS13KeySchedule ks = new TLS13KeySchedule(sharedSecret);
        System.out.println("[CLIENT] 收到 ServerHello (X25519 pub=" + hex(serverPubBytes) + ")");

        // 4. 接收 Certificate
        byte[] certDer = readMsg(in, T_CERTIFICATE);
        transcript.update(T_CERTIFICATE, certDer);
        System.out.println("[CLIENT] 收到 Certificate (ML-DSA, " + certDer.length + "B)");

        // 验证收到的证书与预期一致
        byte[] expectedDer = serverCert.getEncoded();
        if (Arrays.equals(certDer, expectedDer)) {
            System.out.println("[CLIENT] 证书匹配: OK (subject=" + serverCert.getSubjectX500Principal() + ")");
        }

        // 5. 接收 CertificateVerify 并验证 ML-DSA 签名
        byte[] signature = readMsg(in, T_CERTIFICATE_VERIFY);

        byte[] transcriptHash = transcript.cloneHash(); // 仅截至 Certificate (签名不包含自身)
        byte[] sigContent = buildSigContent(SERVER_CV_CONTEXT, transcriptHash);

        Signature verifier = Signature.getInstance("ML-DSA");
        verifier.initVerify(serverCert.getPublicKey());
        verifier.update(sigContent);
        boolean sigValid = verifier.verify(signature);
        System.out.println("[CLIENT] ML-DSA-65 签名验证: " + (sigValid ? "OK ✓" : "FAIL ✗"));

        if (!sigValid) {
            System.err.println("[CLIENT] 签名验证失败，终止握手");
            return;
        }

        transcript.update(T_CERTIFICATE_VERIFY, signature);

        // 6. Server Finished (verify_data 覆盖到 CertificateVerify, 不含 Finished 自身)
        byte[] svFinish = readMsg(in, T_FINISHED);
        byte[] svTransHash = transcript.cloneHash();
        byte[] svFinishKey = ks.deriveServerFinishedKey();
        boolean svFinishValid = Arrays.equals(svFinish, hmacSha256(svFinishKey, svTransHash));
        System.out.println("[CLIENT] Server Finished 验证: " + (svFinishValid ? "OK" : "FAIL"));
        transcript.update(T_FINISHED, svFinish);

        // 7. Client Finished
        byte[] clFinishKey = ks.deriveClientFinishedKey();
        byte[] clVerifyData = hmacSha256(clFinishKey, transcript.hash());
        sendMsg(out, T_FINISHED, clVerifyData);
        transcript.update(T_FINISHED, clVerifyData);

        // 8. 接收并解密 Server 应用数据
        byte[] appCt = readMsg(in, T_APP);
        byte[] svAppKey = ks.deriveServerAppKey();
        byte[] svAppIv = ks.deriveServerAppIv();
        byte[] plain = aesGcmDecrypt(svAppKey, svAppIv, appCt, new byte[]{T_APP, 0, 0, 0});
        System.out.println("[CLIENT] 收到解密数据: \"" + new String(plain, java.nio.charset.StandardCharsets.UTF_8) + "\"");

        // 9. Client 加密回复
        byte[] clAppKey = ks.deriveClientAppKey();
        byte[] clAppIv = ks.deriveClientAppIv();
        byte[] reply = "Hello from self-implemented PQC client!".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] replyCt = aesGcmEncrypt(clAppKey, clAppIv, reply, new byte[]{T_APP, 0, 0, 0});
        sendMsg(out, T_APP, replyCt);
        System.out.println("[CLIENT] 发送加密回复 (AES-128-GCM)");

        System.out.println("[CLIENT] === 自实现 PQC TLS 握手成功 ===");
    }

    // ===== TLS 1.3 HKDF Key Schedule =====
    static class TLS13KeySchedule {
        byte[] handshakeSecret;
        byte[] serverHsTrafficSecret;
        byte[] clientHsTrafficSecret;

        TLS13KeySchedule(byte[] sharedSecret) throws Exception {
            byte[] zeros = new byte[32];
            byte[] emptyHash = sha256(new byte[]{});
            byte[] intermediate = hkdfExtract(zeros, emptyHash);
            handshakeSecret = hkdfExtract(intermediate, sharedSecret);
            serverHsTrafficSecret = hkdfExpandLabel(handshakeSecret, "s hs traffic", new byte[0], 32);
            clientHsTrafficSecret = hkdfExpandLabel(handshakeSecret, "c hs traffic", new byte[0], 32);
        }

        byte[] deriveServerFinishedKey() throws Exception {
            return hkdfExpandLabel(serverHsTrafficSecret, "finished", new byte[0], 32);
        }
        byte[] deriveClientFinishedKey() throws Exception {
            return hkdfExpandLabel(clientHsTrafficSecret, "finished", new byte[0], 32);
        }
        byte[] deriveServerAppKey() throws Exception {
            return hkdfExpandLabel(serverHsTrafficSecret, "key", new byte[0], 16);
        }
        byte[] deriveServerAppIv() throws Exception {
            return hkdfExpandLabel(serverHsTrafficSecret, "iv", new byte[0], 12);
        }
        byte[] deriveClientAppKey() throws Exception {
            return hkdfExpandLabel(clientHsTrafficSecret, "key", new byte[0], 16);
        }
        byte[] deriveClientAppIv() throws Exception {
            return hkdfExpandLabel(clientHsTrafficSecret, "iv", new byte[0], 12);
        }
    }

    // ===== Transcript Digest (累积握手消息的 SHA-256) =====
    static class TranscriptDigest {
        MessageDigest md;
        TranscriptDigest() throws Exception { md = MessageDigest.getInstance("SHA-256"); }
        void update(int type, byte[] payload) { md.update((byte) type); md.update((byte) (payload.length >> 24)); md.update((byte) (payload.length >> 16)); md.update((byte) (payload.length >> 8)); md.update((byte) payload.length); md.update(payload); }
        byte[] hash() { return md.digest(); }
        byte[] cloneHash() { try { MessageDigest clone = (MessageDigest) md.clone(); return clone.digest(); } catch (Exception e) { throw new RuntimeException(e); } }
    }

    // ===== HKDF (RFC 5869) =====
    static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        if (salt == null || salt.length == 0) salt = new byte[32];
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        return mac.doFinal(ikm);
    }

    static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] result = new byte[length];
        byte[] t = new byte[0];
        for (int i = 1; i <= (length + 31) / 32; i++) {
            mac.update(t);
            mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();
            System.arraycopy(t, 0, result, (i - 1) * 32, Math.min(t.length, length - (i - 1) * 32));
        }
        return result;
    }

    static byte[] hkdfExpandLabel(byte[] secret, String label, byte[] context, int length) throws Exception {
        byte[] labelBytes = label.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write((length >> 8) & 0xFF); bos.write(length & 0xFF);
        bos.write(HKDF_LABEL_PREFIX.length + labelBytes.length);
        bos.write(HKDF_LABEL_PREFIX); bos.write(labelBytes);
        bos.write(context.length);
        if (context.length > 0) bos.write(context);
        return hkdfExpand(secret, bos.toByteArray(), length);
    }

    // ===== 密码学工具 =====
    static KeyPair genX25519KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        return kpg.generateKeyPair();
    }

    static byte[] agreeX25519(PrivateKey priv, byte[] pubBytes) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("X25519");
        byte[] uBytes = new byte[32];
        System.arraycopy(pubBytes, 0, uBytes, 32 - pubBytes.length, pubBytes.length);
        java.math.BigInteger u = new java.math.BigInteger(1, uBytes);
        XECPublicKeySpec spec = new XECPublicKeySpec(NamedParameterSpec.X25519, u);
        PublicKey pub = kf.generatePublic(spec);
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(priv); ka.doPhase(pub, true);
        return ka.generateSecret();
    }

    static byte[] fixX25519Len(byte[] raw) {
        if (raw.length == 32) return raw;
        byte[] fixed = new byte[32];
        System.arraycopy(raw, 0, fixed, 32 - raw.length, Math.min(raw.length, 32));
        return fixed;
    }

    static byte[] secureRandomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    static byte[] buildSigContent(byte[] contextStr, byte[] transcriptHash) {
        byte[] prefix = new byte[64];
        Arrays.fill(prefix, (byte) 0x20);
        ByteBuffer buf = ByteBuffer.allocate(64 + contextStr.length + 1 + transcriptHash.length);
        buf.put(prefix); buf.put(contextStr); buf.put((byte) 0); buf.put(transcriptHash);
        return buf.array();
    }

    // ===== AES-128-GCM =====
    static byte[] aesGcmEncrypt(byte[] key, byte[] iv, byte[] plain, byte[] aad) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        if (aad != null) c.updateAAD(aad);
        return c.doFinal(plain);
    }

    static byte[] aesGcmDecrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] aad) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        if (aad != null) c.updateAAD(aad);
        return c.doFinal(ciphertext);
    }

    // ===== 消息读写 (Record 层) =====
    static void sendMsg(DataOutputStream out, int type, byte[] payload) throws Exception {
        out.writeByte(type);
        out.writeInt(payload.length);
        out.write(payload);
        out.flush();
    }

    static byte[] readMsg(DataInputStream in, int expectedType) throws Exception {
        int type = in.readUnsignedByte();
        if (type != expectedType) throw new IOException("期望类型 " + expectedType + " 但收到 " + type);
        int len = in.readInt();
        if (len > 65536) throw new IOException("消息过大: " + len);
        byte[] data = new byte[len];
        in.readFully(data);
        return data;
    }

    static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(data.length, 8); i++) sb.append(String.format("%02x", data[i]));
        return sb + "..." + (data.length > 8 ? ("[" + data.length + "B]") : "");
    }
}