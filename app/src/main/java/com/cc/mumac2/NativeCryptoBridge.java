package com.cc.mumac2;

/**
 * 原生加密桥接 — 加载 libnative.so 并通过 JNI 调用 AES-128-ECB
 *
 * 密钥仅存在于 native 层（.so 中），Java 字节码反编译后不可见，
 * 需逆向 .so 文件才能提取密钥，提升反反编译能力。
 */
public class NativeCryptoBridge {

    static {
        System.loadLibrary("native");
    }

    /**
     * 原生 AES-128-ECB 加密
     *
     * @param plaintext 明文 byte 数组
     * @return 加密后的 byte 数组（含 PKCS7 填充），失败返回 null
     */
    public static native byte[] encrypt(byte[] plaintext);

    /**
     * 原生 AES-128-ECB 解密（自动去 PKCS7 填充）
     *
     * @param ciphertext 密文 byte 数组（16 字节对齐）
     * @return 解密后的明文 byte 数组，失败返回 null
     */
    public static native byte[] decrypt(byte[] ciphertext);
}
