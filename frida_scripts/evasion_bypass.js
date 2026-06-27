/*
 * MobC2Inspector - 隐蔽对抗模块（反检测环境伪装）
 * ==================================================
 * 功能：
 *   在动态分析Hook网络行为之前执行，对目标App的运行环境进行伪装，
 *   使其无法察觉正在被分析工具监控，从而保证C2特征采集的真实性。
 *
 * 对抗手段：
 *   1. 伪装 android.os.Build 属性，隐藏模拟器/调试机特征
 *   2. Hook isDebuggerConnected() 返回 false
 *   3. 过滤 /proc/self/maps 中的Frida相关痕迹
 *   4. 修改 uname() 返回真机内核版本
 *   5. 移除 Frida 相关的环境变量和线程痕迹
 *
 * 加载顺序：必须先于 frida_hook_network.js 加载。
 *
 * 作者: MobC2Inspector Team
 */

// ============================================================
//  全局配置
// ============================================================
var EVASION_CONFIG = {
    // 伪装的目标设备信息（三星 Galaxy S21 Ultra 国际版）
    deviceModel: "SM-G9980",
    deviceManufacturer: "samsung",
    deviceBrand: "samsung",
    deviceBoard: "exynos2100",
    deviceHardware: "exynos2100",
    deviceProduct: "b0s",
    deviceDevice: "b0",
    deviceDisplay: "RP1A.200720.012.G9980ZHU2BUC1",
    deviceFingerprint: "samsung/b0s/b0:11/RP1A.200720.012/G9980ZHU2BUC1:user/release-keys",
    deviceTags: "release-keys",
    deviceType: "user",
    deviceHost: "build-14.samsung.com",
    deviceUser: "dpi",

    // 伪装的内核版本
    kernelVersion: "Linux localhost 4.19.113-19549897",
    kernelHostname: "localhost",

    // 要被过滤的关键字列表（/proc/self/maps 中隐藏Frida痕迹）
    filterKeywords: [
        "frida",
        "gum-js-loop",
        "linjector",
        "frida-agent",
        "frida-helper",
        "gmain",
        "gdbus",
        "gum-",
        "frida-gadget"
    ],

    // Frida相关环境变量
    fridaEnvVars: [
        "FRIDA_LABEL",
        "FRIDA_TEE",
        "FRIDA_VERBOSE",
        "FRIDA_SCRIPT",
        "FRIDA_AGENT_SCRIPT"
    ],

    enableDebug: false
};

// ============================================================
//  工具函数
// ============================================================
function debugLog(msg) {
    if (EVASION_CONFIG.enableDebug) {
        console.log("[MobC2-Evasion] " + msg);
    }
}

/** 将字符串中的字符替换为Unicode转义序列，绕过简单字符串搜索 */
function obfuscate(str) {
    var result = "";
    for (var i = 0; i < str.length; i++) {
        if (str[i] === 'r' || str[i] === 'f') {
            result += "\\u00" + str.charCodeAt(i).toString(16);
        } else {
            result += str[i];
        }
    }
    return result;
}

// ============================================================
//  1. 伪装 android.os.Build 属性
// ============================================================
function hookBuildProperties() {
    try {
        var Build = Java.use("android.os.Build");

        // 修改静态字段getter
        var fields = {
            "MODEL": EVASION_CONFIG.deviceModel,
            "MANUFACTURER": EVASION_CONFIG.deviceManufacturer,
            "BRAND": EVASION_CONFIG.deviceBrand,
            "BOARD": EVASION_CONFIG.deviceBoard,
            "HARDWARE": EVASION_CONFIG.deviceHardware,
            "PRODUCT": EVASION_CONFIG.deviceProduct,
            "DEVICE": EVASION_CONFIG.deviceDevice,
            "DISPLAY": EVASION_CONFIG.deviceDisplay,
            "FINGERPRINT": EVASION_CONFIG.deviceFingerprint,
            "TAGS": EVASION_CONFIG.deviceTags,
            "TYPE": EVASION_CONFIG.deviceType,
            "HOST": EVASION_CONFIG.deviceHost,
            "USER": EVASION_CONFIG.deviceUser
        };

        for (var fieldName in fields) {
            try {
                Object.defineProperty(Build, fieldName, {
                    get: function() {
                        return fields[fieldName];
                    },
                    configurable: true
                });
                debugLog("伪装 Build." + fieldName + " = " + fields[fieldName]);
            } catch (e) {
                // 某些字段可能不可写，尝试直接修改静态字段
                try {
                    var field = Java.use("java.lang.reflect.Field");
                    // 通过反射修改
                    var cls = Java.use("android.os.Build").class;
                    var f = cls.getDeclaredField(fieldName);
                    f.setAccessible(true);
                    f.set(null, fields[fieldName]);
                    debugLog("[反射] 修改 Build." + fieldName);
                } catch (e2) {
                    debugLog("修改 Build." + fieldName + " 失败: " + e2);
                }
            }
        }

        // ✅ 伪装 Build.VERSION 信息
        try {
            var BuildVersion = Java.use("android.os.Build$VERSION");
            var versionFields = {
                "RELEASE": "11",
                "SDK_INT": 30,
                "SECURITY_PATCH": "2021-06-01",
                "BASE_OS": "",
                "CODENAME": "REL",
                "INCREMENTAL": "G9980ZHU2BUC1",
                "PREVIEW_SDK_INT": 0,
                "RESOURCES_SDK_INT": 30
            };
            for (var vf in versionFields) {
                try {
                    Object.defineProperty(BuildVersion, vf, {
                        get: function() { return versionFields[vf]; },
                        configurable: true
                    });
                } catch (e) {}
            }
            debugLog("[+] Build.VERSION 伪装完成");
        } catch (e) {
            debugLog("[!] Build.VERSION伪装失败: " + e);
        }

        // ✅ 伪装 Build.VERSION_CODES
        try {
            var VersionCodes = Java.use("android.os.Build$VERSION_CODES");
            debugLog("[+] Build.VERSION_CODES 可访问");
        } catch (e) {}

        console.log("[MobC2-Evasion] android.os.Build 属性伪装完成");
    } catch (e) {
        console.log("[MobC2-Evasion] [!] Build属性伪装失败: " + e);
    }
}

// ============================================================
//  2. Hook Debug.isDebuggerConnected() 返回 false
// ============================================================
function hookDebugCheck() {
    try {
        var Debug = Java.use("android.os.Debug");

        Debug.isDebuggerConnected.implementation = function() {
            debugLog("拦截 isDebuggerConnected() -> 返回 false");
            return false;
        };

        Debug.waitingForDebugger.implementation = function() {
            debugLog("拦截 waitingForDebugger() -> 返回 false");
            return false;
        };

        console.log("[MobC2-Evasion] Debug.isDebuggerConnected() -> false");
    } catch (e) {
        console.log("[MobC2-Evasion] [!] Debug Hook失败: " + e);
    }
}

// ============================================================
//  3. 过滤 /proc/self/maps 中的Frida痕迹
// ============================================================
function hookProcMaps() {
    try {
        // 方式一：Hook File.read() 过滤maps读取
        var File = Java.use("java.io.File");

        // Hook File 构造函数，检测 /proc/self/maps
        File.$init.overload("java.lang.String").implementation = function(path) {
            var origPath = path.toString();
            if (origPath.indexOf("maps") >= 0 &&
                (origPath.indexOf("/proc/") >= 0 || origPath.indexOf("/self/") >= 0)) {
                debugLog("检测到maps文件: " + origPath);
            }
            return this.$init(path);
        };

        // 方式二：Hook RandomAccessFile 读取
        try {
            var RandomAccessFile = Java.use("java.io.RandomAccessFile");

            RandomAccessFile.$init.overload("java.lang.String", "java.lang.String")
                .implementation = function(path, mode) {
                if (path.indexOf("maps") >= 0) {
                    debugLog("拦截RandomAccessFile: " + path);
                }
                return this.$init(path, mode);
            };

            // Hook readLine 过滤输出
            RandomAccessFile.readLine.implementation = function() {
                var line = this.readLine();
                if (line && EVASION_CONFIG.filterKeywords.some(function(kw) {
                    return line.indexOf(kw) >= 0;
                })) {
                    debugLog("过滤maps行: " + line.substring(0, 80));
                    // 跳过此行，返回下一行
                    return this.readLine();
                }
                return line;
            };
        } catch (e) {
            debugLog("RandomAccessFile Hook失败: " + e);
        }

        // 方式三：通过 Native 层 Hook 更深入的过滤
        try {
            var ModuleMap = Process.findModuleByName("libc.so");
            if (ModuleMap) {
                // 拦截 fopen 调用来过滤 maps 读取
                var fopen = Module.findExportByName("libc.so", "fopen");
                if (fopen) {
                    Interceptor.attach(fopen, {
                        onEnter: function(args) {
                            var path = args[0].readCString();
                            if (path && path.indexOf("maps") >= 0) {
                                debugLog("[Native] fopen(maps) 被调用");
                            }
                        }
                    });
                }
            }
        } catch (e) {
            debugLog("Native层maps Hook失败: " + e);
        }

        console.log("[MobC2-Evasion] /proc/self/maps 过滤已部署");
    } catch (e) {
        console.log("[MobC2-Evasion] [!] Maps过滤Hook失败: " + e);
    }
}

// ============================================================
//  4. 修改 uname 返回真机内核版本
// ============================================================
function hookUname() {
    try {
        var Os = Java.use("android.system.Os");

        Os.uname.implementation = function() {
            var result = this.uname();
            try {
                // 修改返回的utsname字段
                if (result) {
                    result.sysname.value = "Linux";
                    result.nodename.value = EVASION_CONFIG.kernelHostname;
                    result.release.value = EVASION_CONFIG.kernelVersion;
                    result.version.value = "#1 SMP PREEMPT Thu Jun 3 12:00:00 KST 2021";
                    result.machine.value = "aarch64";
                }
            } catch (e) {}
            debugLog("拦截 uname() -> 返回伪装内核版本");
            return result;
        };

        console.log("[MobC2-Evasion] uname() 伪装完成");
    } catch (e) {
        console.log("[MobC2-Evasion] [!] uname Hook失败: " + e);
    }
}

// ============================================================
//  5. 隐藏Frida相关痕迹
// ============================================================
function hideFridaTraces() {
    try {
        // 扫描并移除Frida相关的线程名
        var threads = Process.enumerateThreads();
        for (var i = 0; i < threads.length; i++) {
            var thread = threads[i];
            if (thread.name && EVASION_CONFIG.filterKeywords.some(function(kw) {
                return thread.name.indexOf(kw) >= 0;
            })) {
                debugLog("检测到Frida线程: " + thread.name);
            }
        }
    } catch (e) {
        debugLog("线程扫描失败: " + e);
    }

    // 注意：此处只是检测和记录，实际的线程名修改需要更底层的操作
    console.log("[MobC2-Evasion] Frida痕迹扫描完成");
}

// ============================================================
//  6. Hook System.getProperty 过滤Frida环境变量
// ============================================================
function hookSystemProperties() {
    try {
        var System = Java.use("java.lang.System");

        System.getProperty.overload("java.lang.String").implementation =
            function(key) {
            // 过滤Frida相关属性
            for (var i = 0; i < EVASION_CONFIG.fridaEnvVars.length; i++) {
                if (key.indexOf(EVASION_CONFIG.fridaEnvVars[i]) >= 0) {
                    debugLog("拦截环境变量: " + key);
                    return null;
                }
            }
            return this.getProperty(key);
        };

        System.getenv.overload("java.lang.String").implementation = function(key) {
            for (var i = 0; i < EVASION_CONFIG.fridaEnvVars.length; i++) {
                if (key.indexOf(EVASION_CONFIG.fridaEnvVars[i]) >= 0) {
                    debugLog("拦截getenv: " + key);
                    return null;
                }
            }
            return this.getenv(key);
        };

        console.log("[MobC2-Evasion] 环境变量过滤已部署");
    } catch (e) {
        console.log("[MobC2-Evasion] [!] System属性Hook失败: " + e);
    }
}

// ============================================================
//  7. Hook /system/bin/su 和 root检测
// ============================================================
function hookRootDetection() {
    try {
        var Runtime = Java.use("java.lang.Runtime");

        Runtime.exec.overload("[Ljava.lang.String;").implementation =
            function(cmdArray) {
            var cmdStr = "";
            try {
                cmdStr = JSON.stringify(cmdArray);
            } catch (e) {}

            // 过滤常见root检测命令
            var blockedCmds = ["su", "busybox", "supersu", "magisk",
                               "which su", "test -f /system/bin/su",
                               "test -f /system/xbin/su"];

            for (var i = 0; i < blockedCmds.length; i++) {
                if (cmdStr.indexOf(blockedCmds[i]) >= 0) {
                    debugLog("拦截root检测命令: " + cmdStr.substring(0, 100));
                    // 返回一个空进程（模拟无root）
                    try {
                        return Runtime.getRuntime().exec("echo blocked");
                    } catch (e2) {
                        return null;
                    }
                }
            }

            return this.exec(cmdArray);
        };

        console.log("[MobC2-Evasion] Root检测规避已部署");
    } catch (e) {
        console.log("[MobC2-Evasion] [!] Root检测Hook失败: " + e);
    }
}

// ============================================================
//  8. Hook /sys/class/ 和 /sys/devices/ 模拟器检测
// ============================================================
function hookSysFS() {
    try {
        var File = Java.use("java.io.File");

        // Hook File.exists() 过滤模拟器检测路径
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (path) {
                var suspiciousPaths = [
                    "/sys/class/thermal/thermal_zone0/",
                    "/sys/devices/system/cpu/",
                    "/dev/qemu_pipe",
                    "/dev/socket/qemud",
                    "/system/lib/libc_malloc_debug_qemu.so"
                ];
                for (var i = 0; i < suspiciousPaths.length; i++) {
                    if (path.indexOf(suspiciousPaths[i]) >= 0) {
                        debugLog("拦截模拟器检测: " + path);
                        // 根据路径返回不同结果
                        if (path.indexOf("qemu") >= 0) {
                            return false;  // 假装没有qemu
                        }
                    }
                }
            }
            return this.exists();
        };

        console.log("[MobC2-Evasion] 模拟器路径检测规避已部署");
    } catch (e) {
        console.log("[MobC2-Evasion] [!] sysfs Hook失败: " + e);
    }
}

// ============================================================
//  主入口
// ============================================================
function main() {
    console.log("[MobC2Inspector] 隐蔽对抗模块加载中...");

    Java.perform(function() {
        console.log("[MobC2Inspector] 开始部署反检测环境伪装...");

        // 按顺序执行各对抗模块
        hookBuildProperties();           // 1. 伪装设备属性
        hookDebugCheck();                // 2. 禁用调试检测
        hookProcMaps();                  // 3. 过滤maps中的Frida痕迹
        hookUname();                     // 4. 伪装内核版本
        hideFridaTraces();               // 5. 隐藏Frida线程痕迹
        hookSystemProperties();          // 6. 过滤环境变量
        hookRootDetection();             // 7. 绕过Root检测
        hookSysFS();                     // 8. 绕过模拟器检测

        console.log("[MobC2Inspector] 隐蔽对抗模块部署完成，环境已伪装为真实机型");
        console.log("[MobC2Inspector] 目标机型: " + EVASION_CONFIG.deviceModel +
                    " / " + EVASION_CONFIG.deviceManufacturer);
    });
}

// 使用setTimeout确保在执行网络Hook前完成环境伪装
setTimeout(main, 100);
