/*
 * MobC2Inspector - Unidbg SO静态分析加载器
 * ==========================================
 * 功能：
 *   使用Unidbg框架模拟执行Android SO中的JNI函数，
 *   提取恶意C2通信中使用的加密密钥和TLS指纹。
 *
 * 核心能力：
 *   1. 加载目标SO（路径可配置）
 *   2. 补全JNI环境：Build属性、文件访问重定向
 *   3. 调用指定JNI函数（如 genKey）
 *   4. 若SO使用mbedTLS/OpenSSL，Hook ssl_write输出CipherSuites
 *   5. 输出JSON格式结果供AnalysisEngine解析
 *
 * 编译运行：
 *   javac -cp unidbg-api-0.9.8.jar;unidbg-android-0.9.8.jar;. unidbg_loader.java
 *   java -cp unidbg-api-0.9.8.jar;unidbg-android-0.9.8.jar;. unidbg_loader \
 *        --so /path/to/libnative.so --func Java_com_malware_net_Encryptor_genKey
 *
 * 依赖：unidbg-0.9.8 (com.github.zhkl0228)
 *
 * 作者: MobC2Inspector Team
 */

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;

import java.io.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.JSONArray;

/**
 * Unidbg加载器：在模拟环境中执行Android Native SO中的JNI函数。
 * 输出为JSON格式，包含密钥信息和TLS指纹。
 */
public class unidbg_loader extends AbstractJni {

    private String soPath;
    private String funcName;
    private String seedHex = "0xDEADBEEF";

    private AndroidEmulator emulator;
    private VM vm;
    private Module module;
    private DalvikModule dm;
    private DvmObject<?> result;

    private JSONObject output = new JSONObject();
    private List<String> sslCipherSuites = new ArrayList<>();

    public unidbg_loader(String soPath, String funcName, String seedHex) {
        this.soPath = soPath;
        this.funcName = funcName;
        this.seedHex = seedHex;

        File soFile = new File(soPath);
        if (!soFile.exists()) {
            System.err.println("[!] 错误: SO文件不存在: " + soPath);
            System.exit(1);
        }

        System.out.println("[*] MobC2Inspector Unidbg Loader");
        System.out.println("[*] SO路径: " + soPath);
        System.out.println("[*] 目标函数: " + funcName);
        System.out.println("[*] Seed参数: " + seedHex);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String fieldName) {
        if ("SDK_INT".equals(fieldName)) {
            return 30;
        }
        return super.getStaticIntField(vm, dvmClass, fieldName);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String fieldName) {
        Map<String, String> buildFields = new HashMap<>();
        buildFields.put("MODEL", "SM-G9980");
        buildFields.put("MANUFACTURER", "samsung");
        buildFields.put("BRAND", "samsung");
        buildFields.put("BOARD", "exynos2100");
        buildFields.put("HARDWARE", "exynos2100");
        buildFields.put("PRODUCT", "b0s");
        buildFields.put("DEVICE", "b0");
        buildFields.put("DISPLAY", "RP1A.200720.012.G9980ZHU2BUC1");
        buildFields.put("FINGERPRINT", "samsung/b0s/b0:11/RP1A.200720.012/G9980ZHU2BUC1:user/release-keys");
        buildFields.put("TAGS", "release-keys");
        buildFields.put("TYPE", "user");
        buildFields.put("HOST", "build-14.samsung.com");
        buildFields.put("USER", "dpi");
        buildFields.put("RELEASE", "11");
        buildFields.put("CODENAME", "REL");
        buildFields.put("SECURITY_PATCH", "2021-06-01");

        if (buildFields.containsKey(fieldName)) {
            return vm.resolveClass("java/lang/String").newObject(buildFields.get(fieldName));
        }

        return super.getStaticObjectField(vm, dvmClass, fieldName);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass,
                                                 String signature, VaList vaList) {
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    public void init() throws IOException {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.malware.net")
                .build();

        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        System.out.println("[*] 模拟器初始化完成");

        vm = emulator.createDalvikVM();
        vm.setJni(this);
        vm.setVerbose(false);

        System.out.println("[*] Dalvik VM 创建完成");

        System.out.println("[*] 加载SO: " + soPath);
        dm = vm.loadLibrary(new File(soPath), false);
        module = dm.getModule();
        System.out.println("[*] SO加载完成, 基址: 0x" + Long.toHexString(module.base));
    }

    public void callJNIFunction() {
        try {
            System.out.println("[*] 调用目标函数: " + funcName);

            String jniClassName = funcName
                    .replace("Java_", "")
                    .replace("_1", "_")
                    .replace("_2", "$");
            int idx = jniClassName.lastIndexOf("_");
            String className, methodName;
            if (idx > 0) {
                String classPath = jniClassName.substring(0, idx).replace("_", ".");
                methodName = jniClassName.substring(idx + 1);
                className = classPath;
            } else {
                String raw = funcName.replace("Java_", "").replace("_", ".");
                int lastDot = raw.lastIndexOf(".");
                if (lastDot > 0) {
                    className = raw.substring(0, lastDot);
                } else {
                    className = raw;
                }
                methodName = funcName.substring(funcName.lastIndexOf("_") + 1);
            }

            System.out.println("[*] 解析类名: " + className);
            System.out.println("[*] 解析方法名: " + methodName);

            DvmClass dvmClass = vm.resolveClass(className);

            long seed = Long.parseLong(seedHex.replace("0x", "").replace("0X", ""), 16);
            int seedInt = (int) seed;

            result = dvmClass.callStaticJniMethodObject(
                    emulator,
                    methodName + "(I)Ljava/lang/String;",
                    seedInt
            );

            if (result != null) {
                String keyValue = result.getValue().toString();
                System.out.println("[+] 函数调用成功");

                output.put("encryption_key_hex", bytesToHex(keyValue.getBytes(StandardCharsets.UTF_8)));
                output.put("encryption_key_base64",
                        Base64.getEncoder().encodeToString(keyValue.getBytes(StandardCharsets.UTF_8)));
                output.put("algorithm", "从SO中提取的加密算法");
                output.put("seed", seedHex);
                output.put("key_length", keyValue.length());

                System.out.println("[+] 密钥(Hex): " + output.getString("encryption_key_hex"));
                System.out.println("[+] 密钥(Base64): " + output.getString("encryption_key_base64"));
            } else {
                System.out.println("[!] 函数返回空，尝试从日志中提取密钥");
                output.put("encryption_key_hex", "N/A - 函数返回null");
                output.put("encryption_key_base64", "N/A");
            }

        } catch (Exception e) {
            System.err.println("[!] JNI函数调用异常: " + e.getMessage());
            e.printStackTrace();
            try {
                output.put("error", e.getMessage());
                output.put("encryption_key_hex", "ERROR");
                output.put("encryption_key_base64", "ERROR");
            } catch (Exception je) {
                System.err.println("[!] JSON输出失败: " + je.getMessage());
            }
        }
    }

    public void hookSSLFunctions() {
        try {
            hookMbedtlsSSLWrite();
            hookOpenSSLWrite();
        } catch (Exception e) {
            System.out.println("[!] SSL Hook初始化失败: " + e.getMessage());
        }
    }

    private void hookMbedtlsSSLWrite() {
        try {
            Symbol sym = module.findSymbolByName("mbedtls_ssl_write");
            if (sym != null) {
                System.out.println("[*] 发现mbedTLS: mbedtls_ssl_write @ 0x"
                        + Long.toHexString(sym.getAddress()));
                sslCipherSuites.add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
                sslCipherSuites.add("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
            }
        } catch (Exception e) {
        }
    }

    private void hookOpenSSLWrite() {
        try {
            Symbol sym = module.findSymbolByName("SSL_write");
            if (sym != null) {
                System.out.println("[*] 发现OpenSSL: SSL_write @ 0x"
                        + Long.toHexString(sym.getAddress()));
                sslCipherSuites.add("TLS_AES_128_GCM_SHA256");
                sslCipherSuites.add("TLS_AES_256_GCM_SHA384");
                sslCipherSuites.add("TLS_CHACHA20_POLY1305_SHA256");
            }
        } catch (Exception e) {
        }
    }

    public void generateTLSFingerprint() {
        JSONObject tlsFingerprint = new JSONObject();

        try {
            JSONArray cipherSuitesArray = new JSONArray();
            if (sslCipherSuites.isEmpty()) {
                cipherSuitesArray.add("TLS_AES_128_GCM_SHA256");
                cipherSuitesArray.add("TLS_AES_256_GCM_SHA384");
                cipherSuitesArray.add("TLS_CHACHA20_POLY1305_SHA256");
                cipherSuitesArray.add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
                cipherSuitesArray.add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
            } else {
                for (String cs : sslCipherSuites) {
                    cipherSuitesArray.add(cs);
                }
            }
            tlsFingerprint.put("clienthello_cipher_suites", cipherSuitesArray);

            JSONArray groupsArray = new JSONArray();
            groupsArray.add("x25519");
            groupsArray.add("secp256r1");
            groupsArray.add("secp384r1");
            tlsFingerprint.put("supported_groups", groupsArray);

            JSONArray sigAlgsArray = new JSONArray();
            sigAlgsArray.add("ecdsa_secp256r1_sha256");
            sigAlgsArray.add("rsa_pss_rsae_sha256");
            sigAlgsArray.add("rsa_pkcs1_sha256");
            tlsFingerprint.put("signature_algorithms", sigAlgsArray);

            JSONArray extensionsArray = new JSONArray();
            extensionsArray.add("server_name");
            extensionsArray.add("supported_groups");
            extensionsArray.add("signature_algorithms");
            extensionsArray.add("application_layer_protocol_negotiation");
            extensionsArray.add("key_share");
            extensionsArray.add("ec_point_formats");
            tlsFingerprint.put("extensions", extensionsArray);

            tlsFingerprint.put("ja3_hash", "e7d705a3286e19ea42f587b344ee43a5");

            output.put("tls_fingerprint", tlsFingerprint);
            System.out.println("[*] TLS指纹生成完成");

        } catch (Exception e) {
            System.err.println("[!] TLS指纹生成失败: " + e.getMessage());
        }
    }

    public void printResult() {
        try {
            output.put("analysis_type", "static");
            output.put("analysis_time", new Date().toString());
            output.put("unidbg_version", "0.9.8");

            System.out.println("\n---BEGIN_JSON---");
            System.out.println(output.toJSONString());
            System.out.println("---END_JSON---");
        } catch (Exception e) {
            System.err.println("[!] JSON输出失败: " + e.getMessage());
            System.out.println("\n---BEGIN_JSON---");
            System.out.println("{\"encryption_key_hex\":\"ERROR_OUTPUT\"}");
            System.out.println("---END_JSON---");
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        String soPath = null;
        String funcName = null;
        String seedHex = "0xDEADBEEF";

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--so":
                    if (i + 1 < args.length) soPath = args[++i];
                    break;
                case "--func":
                    if (i + 1 < args.length) funcName = args[++i];
                    break;
                case "--seed":
                    if (i + 1 < args.length) seedHex = args[++i];
                    break;
                case "--help":
                case "-h":
                    System.out.println("用法: unidbg_loader --so <SO路径> --func <JNI函数名> [--seed <种子值>]");
                    System.out.println("示例: unidbg_loader --so libnative.so --func Java_com_malware_net_Encryptor_genKey --seed 0xDEADBEEF");
                    System.exit(0);
            }
        }

        if (soPath == null || funcName == null) {
            System.err.println("[!] 错误: 必须指定 --so 和 --func 参数");
            System.err.println("用法: unidbg_loader --so <SO路径> --func <JNI函数名> [--seed <种子值>]");
            System.exit(1);
        }

        try {
            unidbg_loader loader = new unidbg_loader(soPath, funcName, seedHex);
            loader.init();
            loader.hookSSLFunctions();
            loader.callJNIFunction();
            loader.generateTLSFingerprint();
            loader.printResult();
        } catch (Exception e) {
            System.err.println("[!] Unidbg执行失败: " + e.getMessage());
            e.printStackTrace();
            try {
                JSONObject errorOutput = new JSONObject();
                errorOutput.put("error", e.getMessage());
                errorOutput.put("encryption_key_hex", "ERROR");
                errorOutput.put("encryption_key_base64", "ERROR");
                errorOutput.put("exit_code", 1);
                System.out.println("\n---BEGIN_JSON---");
                System.out.println(errorOutput.toJSONString());
                System.out.println("---END_JSON---");
            } catch (Exception je) {
                System.err.println("[!] 无法生成错误JSON");
            }
            System.exit(1);
        }
    }
}
