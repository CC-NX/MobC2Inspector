package com.cc.mumac2;

import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

/**
 * 反检测检查 - 检测模拟器、调试器、Frida等分析环境
 */
public class EvasionCheck {
    private static final String TAG = "EvasionCheck";

    /**
     * 检测当前是否在模拟器中运行
     *
     * 检查项：
     * - Build.FINGERPRINT 是否以 "generic" 开头
     * - Build.TAGS 是否包含 "test-keys"
     * - 模拟器特有设备文件是否存在
     */
    public static boolean isEmulator() {
        // 检查Build属性
        String fingerprint = Build.FINGERPRINT;
        String tags = Build.TAGS;

        if (fingerprint != null && fingerprint.startsWith("generic")) {
            Log.w(TAG, "检测到模拟器特征: FINGERPRINT=" + fingerprint);
            return true;
        }
        if (tags != null && tags.contains("test-keys")) {
            Log.w(TAG, "检测到模拟器特征: TAGS=" + tags);
            return true;
        }

        // 检查模拟器特有文件
        String[] emulatorFiles = {
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/system/bin/qemu-props"
        };
        for (String path : emulatorFiles) {
            if (new File(path).exists()) {
                Log.w(TAG, "检测到模拟器文件: " + path);
                return true;
            }
        }

        return false;
    }

    /**
     * 检测是否有调试器附加
     */
    public static boolean isDebugged() {
        return android.os.Debug.isDebuggerConnected();
    }

    /**
     * 检测Frida/Linjector等动态分析框架是否正在运行
     *
     * 通过读取 /proc/self/maps 搜索已知的注入标记
     */
    public static boolean isFridaRunning() {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("frida") ||
                    line.contains("gum-js-loop") ||
                    line.contains("linjector") ||
                    line.contains("frida-agent") ||
                    line.contains("gadget") ||
                    line.contains("re.frida")) {
                    Log.w(TAG, "检测到动态分析框架: " + line);
                    return true;
                }
            }
        } catch (Exception e) {
            // /proc/self/maps 可能无法读取，忽略
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (Exception ignored) {}
            }
        }
        return false;
    }

    /**
     * 若检测到分析环境（模拟器/调试器/Frida），立即退出进程
     *
     * 在开始任何网络行为前调用
     */
    public static void exitIfAnalyzed() {
        if (isEmulator()) {
            Log.e(TAG, "检测到模拟器环境，安全退出");
            System.exit(0);
        }
        if (isDebugged()) {
            Log.e(TAG, "检测到调试器附加，安全退出");
            System.exit(0);
        }
        if (isFridaRunning()) {
            Log.e(TAG, "检测到Frida/Linjector，安全退出");
            System.exit(0);
        }
    }
}
