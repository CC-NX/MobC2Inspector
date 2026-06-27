package com.cc.mumac2;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.telephony.TelephonyManager;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

/**
 * 设备信息收集器 - 收集设备信息并序列化为JSON
 */
public class DeviceInfoCollector {

    /**
     * 收集设备信息并返回JSON字符串
     *
     * @param context 应用上下文
     * @return JSON格式的设备信息字符串
     */
    public static String collect(Context context) {
        try {
            JSONObject info = new JSONObject();
            info.put("device_model", Build.MODEL);
            info.put("manufacturer", Build.MANUFACTURER);
            info.put("android_version", Build.VERSION.RELEASE);
            info.put("sdk_int", Build.VERSION.SDK_INT);
            info.put("brand", Build.BRAND);
            info.put("is_rooted", isRooted());
            info.put("network_type", getNetworkType(context));
            info.put("timestamp", System.currentTimeMillis());
            return info.toString();
        } catch (Exception e) {
            return "{\"error\":\"" + e.getMessage() + "\"}";
        }
    }

    /**
     * 检测设备是否已ROOT
     *
     * 检查常见su文件路径以及尝试执行which su命令
     */
    private static boolean isRooted() {
        String[] rootPaths = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        };
        for (String path : rootPaths) {
            if (new File(path).exists()) {
                return true;
            }
        }

        // 尝试执行which su命令
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", "which su"});
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line = reader.readLine();
            if (line != null && !line.isEmpty()) {
                return true;
            }
        } catch (Exception ignored) {
        }

        return false;
    }

    /**
     * 获取当前网络类型描述
     */
    private static String getNetworkType(Context context) {
        ConnectivityManager cm = (ConnectivityManager)
            context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return "Unknown";

        NetworkInfo activeNetwork = cm.getActiveNetworkInfo();
        if (activeNetwork == null || !activeNetwork.isConnected()) {
            return "NoConnection";
        }

        int type = activeNetwork.getType();
        if (type == ConnectivityManager.TYPE_WIFI) {
            return "WiFi";
        }
        if (type == ConnectivityManager.TYPE_MOBILE) {
            TelephonyManager tm = (TelephonyManager)
                context.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm == null) return "Mobile";

            int networkType = tm.getNetworkType();
            switch (networkType) {
                case TelephonyManager.NETWORK_TYPE_NR:
                    return "5G";
                case TelephonyManager.NETWORK_TYPE_LTE:
                    return "4G/LTE";
                case TelephonyManager.NETWORK_TYPE_UMTS:
                case TelephonyManager.NETWORK_TYPE_HSDPA:
                case TelephonyManager.NETWORK_TYPE_HSUPA:
                case TelephonyManager.NETWORK_TYPE_HSPA:
                case TelephonyManager.NETWORK_TYPE_HSPAP:
                    return "3G";
                case TelephonyManager.NETWORK_TYPE_EDGE:
                case TelephonyManager.NETWORK_TYPE_GPRS:
                    return "2G";
                default:
                    return "Mobile(" + networkType + ")";
            }
        }
        return "Other(" + type + ")";
    }
}
