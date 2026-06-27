# MobC2Inspector

> **基于Frida+Unidbg的跨平台Android恶意C2通信自动化检测与评估平台**
> **扩展支持: Windows EXE木马PCAP流量分析**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![Frida](https://img.shields.io/badge/Frida-16.x-red)](https://frida.re)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## 项目背景

本项目借鉴 **HITCON 2026 "AI Agent × 恶意程式C2通訊辨識"** 的前沿探索思路，结合 MCP (Model Context Protocol) 协议实现自动化恶意C2通信检测分析。

**核心创新点：**
- 将Frida动态Hook + Unidbg静态模拟相结合的全链路C2分析
- 隐蔽对抗模块确保在具备反沙箱、反Frida、反抓包能力的恶意样本前仍能采集真实特征
- **跨平台C2检测**：不仅支持Android恶意APK，还可直接分析Windows EXE木马捕获的PCAP流量，使用同一套检测模型输出结果
- 通过MCP协议将检测能力封装为标准工具，使LLM可以编排调度完整分析流程
- 量化评估体系（准确率、召回率、F1、ROC-AUC、误报率）

---

## 环境依赖

### Python 依赖

```bash
pip install frida frida-tools pandas numpy scikit-learn matplotlib joblib pyshark
# 或降级使用scapy
pip install scapy
```

| 包名 | 用途 | 最低版本 |
|------|------|---------|
| frida | 动态Hook框架 | 16.0.0 |
| frida-tools | Frida命令行工具 | 12.0.0 |
| pandas | 数据处理 | 1.5.0 |
| numpy | 数值计算 | 1.24.0 |
| scikit-learn | 机器学习模型 | 1.2.0 |
| matplotlib | 特征重要性可视化 | 3.7.0 |
| joblib | 模型序列化 | 1.2.0 |
| pyshark | PCAP解析（推荐） | 0.4.3 |
| scapy | PCAP解析（降级） | 2.5.0 |

### Android 环境（可选，用于真实设备分析）

- **Android SDK/NDK**：用于编译测试样本
- **Frida-server**：运行在Android设备端（与PC frida版本匹配）
- **ADB**：Android Debug Bridge
- **tcpdump**：可选，用于流量抓包
- **Unidbg**：Java静态模拟执行SO（可选，用于密钥提取）

### Unidbg 安装

```bash
git clone https://github.com/zhkl0228/unidbg
cd unidbg
mvn clean package -DskipTests
# 将 unidbg-android/target/unidbg-android-*.jar 复制到 unidbg/lib/
```

---

## 项目结构

```
MobC2Inspector/
├── mcp_server.py              # MCP Server主程序 (stdio JSON-RPC, 7个工具)
├── engine/
│   ├── __init__.py            # 引擎包初始化
│   └── engine.py              # AnalysisEngine 核心分析引擎
├── pcap_analyzer.py           # PCAP跨平台C2流量分析模块（新增）
├── frida_scripts/
│   ├── frida_hook_network.js  # 网络行为Hook脚本
│   └── evasion_bypass.js      # 隐蔽对抗（反检测伪装）脚本
├── unidbg/
│   └── unidbg_loader.java     # Unidbg SO静态加载器
├── train_model.py             # 机器学习模型训练脚本
├── data/
│   ├── sample_features.csv    # 示例特征数据集 (120条，含Windows样本)
│   └── feature_importance.png # 特征重要性柱状图（训练生成）
├── models/
│   └── c2_model.joblib        # 预训练随机森林模型（训练生成）
├── reports/                   # 分析报告输出目录
├── logs/                      # 日志输出目录
└── README.md                  # 项目文档
```

---

## 安装与配置

### 1. 克隆项目

```bash
git clone https://github.com/your-org/MobC2Inspector.git
cd MobC2Inspector
```

### 2. Python环境

```bash
python -m venv venv
source venv/bin/activate   # Linux/macOS
# 或
.\venv\Scripts\activate    # Windows

pip install -r requirements.txt
```

### 3. 创建依赖清单

```bash
pip freeze > requirements.txt
```

### 4. 验证安装

```bash
python mcp_server.py --test
```

---


### 快速演示

所有功能均支持 `demo_mode=True`，无需连接Android设备即可演示完整流程。

#### Step 1: 运行自测试

```bash
python mcp_server.py --test
```

输出包括6个工具的调用结果，覆盖全部功能。

#### Step 2: 训练检测模型

```bash
python train_model.py
```

输出5折交叉验证指标和特征重要性图。

#### Step 3: 单工具调用

```bash
# 列出样本
python mcp_server.py --tool list_samples

# 静态分析
python mcp_server.py --tool static_analysis --params '{"apk_id": "sample_001"}'

# 动态分析（启用隐蔽对抗）
python mcp_server.py --tool dynamic_analysis --params '{"apk_id": "sample_001", "bypass_evasion": true}'

# 流量捕获
python mcp_server.py --tool traffic_capture --params '{"apk_id": "sample_001", "duration_sec": 60}'

# 检测评估
python mcp_server.py --tool evaluate_detection

# 生成报告
python mcp_server.py --tool generate_report --params '{"apk_id": "sample_001"}'
```

#### Step 4: 启动MCP Server（供LLM调度）

```bash
python mcp_server.py
```

通过stdin/stdout接收JSON-RPC请求。LLM可使用标准MCP协议与其交互：

```json
// 工具发现
{"jsonrpc": "2.0", "method": "tools/list", "id": 1}

// 调用工具
{"jsonrpc": "2.0", "method": "tools/call", "params": {
    "name": "static_analysis",
    "arguments": {"apk_id": "sample_001"}
}, "id": 2}
```

### 真实设备分析

```bash
# 连接设备
adb devices

# 启动frida-server
adb shell /data/local/tmp/frida-server-16.x.x-android-arm64 &

# 运行MCP Server（关闭demo模式）
python mcp_server.py --demo false --adb "C:\Android\platform-tools\adb.exe" --device "emulator-5554"
```

---

## 隐蔽对抗模块

### 设计思路

恶意样本常使用以下反分析技术：
1. **反Frida**：检测 `/proc/self/maps` 中的 `frida`、`gum-js-loop` 字符串
2. **反沙箱**：检测 `Build.MODEL`、`Build.TAGS`、`Debug.isDebuggerConnected()`
3. **反抓包**：检测 `tcpdump` 进程、代理设置
4. **环境指纹**：检查内核版本、设备属性、Root状态

### 对抗手段

| 对抗技术 | 实现方式 | Frida脚本 |
|---------|---------|----------|
| Build伪装 | Hook `android.os.Build` 静态字段getter，返回三星真机值 | `evasion_bypass.js:1` |
| 调试检测绕过 | `isDebuggerConnected()` 强制返回false | `evasion_bypass.js:2` |
| maps过滤 | Hook File/RandomAccessFile读取，过滤Frida关键字行 | `evasion_bypass.js:3` |
| 内核伪装 | Hook `android.system.Os.uname()` 返回真机内核 | `evasion_bypass.js:4` |
| Root检测绕过 | Hook `Runtime.exec()` 拦截su/root检测命令 | `evasion_bypass.js:7` |
| 模拟器检测绕过 | Hook `File.exists()` 过滤QEMU路径 | `evasion_bypass.js:8` |
| 环境变量过滤 | Hook `System.getProperty()` 过滤Frida环境变量 | `evasion_bypass.js:6` |
| 抓包降级 | 无tcpdump时使用Frida内存抓取明文 | `engine.py:_memory_capture_fallback` |

### 启用方法

```python
# 通过MCP接口启用
# 设置 bypass_evasion=true（默认）
python mcp_server.py --tool dynamic_analysis --params '{"apk_id": "sample_001", "bypass_evasion": true}'

# 或通过引擎直接调用
engine = AnalysisEngine(demo_mode=True)
result = engine.dynamic_analysis("sample_001", bypass_evasion=True)
```

---

## 检测评估指标

### 指标含义

| 指标 | 缩写 | 含义 | 理想值 |
|------|------|------|--------|
| 准确率 | Accuracy | (TP+TN)/(TP+TN+FP+FN) | >0.95 |
| 精确率 | Precision | TP/(TP+FP) | >0.90 |
| 召回率 | Recall | TP/(TP+FN) | >0.90 |
| F1分数 | F1 | 2×P×R/(P+R) | >0.90 |
| AUC-ROC | AUC | ROC曲线下面积 | >0.95 |
| 误报率 | FPR | FP/(FP+TN) | <0.05 |

### 评估结果示例

```json
{
  "accuracy": 0.9640,
  "precision": 0.9562,
  "recall": 0.9783,
  "f1_score": 0.9671,
  "roc_auc": 0.9941,
  "false_positive_rate": 0.0541,
  "true_positive": 47,
  "false_positive": 2,
  "true_negative": 48,
  "false_negative": 1
}
```

### 特征重要性

Top 5 区分C2通信的关键特征：
1. **packet_length_entropy** — C2通信载荷经过加密，熵值显著高于正常流量
2. **interval_variance** — 恶意C2通信间隔通常固定或有规律，方差小
3. **dns_query_entropy** — DGA生成的域名熵值高
4. **unique_destinations** — C2通信目标固定（1-3个），正常App连接多台服务器
5. **connection_count** — C2通信频率密集

---

## MCP协议接口

### tools/list

返回7个可用分析工具及其参数Schema。

### tools/call

MCP Server 通过 stdin/stdout 接收 JSON-RPC 2.0 请求。支持两种调用方式：

**方式一：MCP 标准协议（LLM/Agent 使用）**
```json
{"jsonrpc": "2.0", "method": "tools/list", "id": 1}
{"jsonrpc": "2.0", "method": "tools/call", "params": {
    "name": "static_analysis",
    "arguments": {"apk_id": "sample_001"}
}, "id": 2}
```

**方式二：命令行单工具模式（人类使用）**
```bash
python mcp_server.py --tool static_analysis --params '{"apk_id": "sample_001"}'
```

### MCP 工具详细参考

#### 1. list_samples — 列出可用样本

| 项目 | 说明 |
|------|------|
| 用途 | 扫描 `samples/` 目录中的 APK/SO/PCAP 文件，返回可用样本列表 |
| 参数 | 无 |
| 返回值 | `list[dict]` |

返回字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| apk_id | string | 样本标识符（文件名去扩展名） |
| type | string | 样本类型: `apk` / `so` / `pcap` |
| available | bool | 是否可用 |
| path | string | 文件相对路径 |
| package_name | string | (APK 类型) Android 包名 |
| description | string | (APK 类型) 样本描述 |
| so_count | int | (APK 类型) 内部 SO 数量 |

#### 2. static_analysis — 静态分析

| 项目 | 说明 |
|------|------|
| 用途 | 对目标 APK/SO 执行 Unidbg 静态模拟，提取加密密钥和 TLS ClientHello 指纹（JA3） |
| 参数 | `apk_id: string`（必需） |
| 返回值 | `dict` |

返回字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| apk_id | string | 样本标识符 |
| package_name | string | Android 包名 |
| analysis_type | string | `"static"` |
| key_info.encryption_key_hex | string | 提取到的密钥 Hex |
| key_info.encryption_key_base64 | string | 密钥 Base64 |
| key_info.algorithm | string | 加密算法（如 AES-256-CBC） |
| key_info.iv_hex | string | IV 向量 Hex |
| tls_fingerprint.clienthello_cipher_suites | string[] | TLS 密码套件列表 |
| tls_fingerprint.supported_groups | string[] | 支持的椭圆曲线 |
| tls_fingerprint.signature_algorithms | string[] | 签名算法 |
| tls_fingerprint.extensions | string[] | TLS 扩展 |
| tls_fingerprint.ja3_hash | string | JA3 指纹哈希 |
| source | string | `"unidbg"` / `"mock_demo"` |

示例：
```json
{"apk_id": "sample_001", "package_name": "com.malware.banking", "key_info": {
  "encryption_key_hex": "A1B2C3D4E5F60718293A4B5C6D7E8F90",
  "algorithm": "AES-256-CBC"}, "tls_fingerprint": {"ja3_hash": "e7d705a3286e19ea42f587b344ee43a5"},
  "source": "unidbg"}
```

#### 3. dynamic_analysis — 动态分析

| 项目 | 说明 |
|------|------|
| 用途 | 使用 Frida 动态 Hook 目标 App 网络层，采集 C2 通信特征。支持 spawn（启动注入）和 attach（附加已有进程）两种模式 |
| 参数 | 见下表 |
| 返回值 | `dict` |

参数：

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| apk_id | string | — | **必需** 样本标识符 |
| bypass_evasion | bool | true | 是否启用隐蔽对抗（反 Frida 检测、反沙箱伪装） |
| attach | bool | false | attach 模式（附加到已在运行的 App）vs spawn 模式（启动 App） |
| process_name | string | null | 目标进程名。attach 模式下用于定位进程，spawn 模式下覆盖 `-f` 参数 |
| timeout_sec | int | 120 | 最大采集等待时间（秒） |

返回值关键字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| status | string | `"success"` / `"no_data"` / `"install_failed"` |
| connections | array | 每条连接的特征记录（ip, port, domain, tls_sni, cipher_suites, entropy, interval_ms, packet_len 等） |
| features | dict | 聚合特征（见下表） |
| source | string | `"mock_demo"`（仅 demo 模式） |

features 聚合字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| unique_ips | int | 不重复目标 IP 数 |
| unique_domains | int | 不重复域名数 |
| domain_entropy | float | 域名平均熵值（DGA 检测） |
| port_diversity | int | 端口多样性 |
| avg_interval_ms | float | 通信平均间隔（毫秒） |
| interval_variance | float | 通信间隔方差（心跳特征） |
| avg_payload_entropy | float | 载荷平均信息熵 |
| max_payload_entropy | float | 载荷最大信息熵 |
| total_connections | int | 总连接数 |
| tls_connection_count | int | TLS 连接数 |
| dns_query_count | int | DNS 查询次数 |
| has_sni | bool | 是否包含 SNI |

#### 4. traffic_capture — 流量抓包

| 项目 | 说明 |
|------|------|
| 用途 | 在设备后台执行网络抓包（tcpdump 或 Frida 内存抓取降级） |
| 参数 | `apk_id: string`（必需）, `duration_sec: int`（默认 60） |
| 返回值 | `dict`（capture_method, pcap_path, packet_count, protocols 等） |

#### 5. analyze_pcap — PCAP 跨平台 C2 分析

| 项目 | 说明 |
|------|------|
| 用途 | 分析 Windows EXE 木马等非 Android 平台的 PCAP 流量文件，提取 C2 特征并调用 ML 模型预测 |
| 参数 | `pcap_path: string`（必需）, `label: int`（可选 0/1 真实标签） |
| 返回值 | prediction, confidence, features 字典 |

#### 6. evaluate_detection — 检测模型评估

| 项目 | 说明 |
|------|------|
| 用途 | 使用标记数据集评估 C2 检测模型性能，输出量化指标 |
| 参数 | `ground_truth_csv: string`（默认 data/sample_features.csv）, `pcap_list: array`（可选） |
| 返回值 | accuracy, precision, recall, f1_score, roc_auc, false_positive_rate |

#### 7. generate_report — 生成分析报告

| 项目 | 说明 |
|------|------|
| 用途 | 自动执行完整分析链（静态+动态+流量+ML），生成 Markdown 格式的综合分析报告 |
| 参数 | `target_id: string`（必需，APK ID 或 .pcap 文件路径） |
| 返回值 | report_path, judgment (malicious_c2/benign), confidence, summary |

示例：
```json
{"target_id": "sample_001", "report_path": "reports/report_sample_001_20260626_202213.md",
 "judgment": "malicious_c2", "confidence": 0.9941,
 "summary": "检测到 5 条连接, 1 个域名, 平均载荷熵 4.12, 判定为恶意C2"}
```

---

## AnalysisEngine 引擎 API

`engine/engine.py` 中的 `AnalysisEngine` 类提供 7 个公有方法：

| 方法 | 签名 | 返回值 | 说明 |
|------|------|--------|------|
| `list_samples()` | `(self) -> list` | `list[dict]` | 扫描 samples/ 目录，返回可用样本列表 |
| `static_analysis(apk_id)` | `(apk_id: str) -> dict` | `dict` | 静态分析（Unidbg SO 模拟） |
| `dynamic_analysis(apk_id, bypass_evasion, timeout_sec, attach, process_name)` | `(apk_id: str, bypass_evasion: bool = True, timeout_sec: int = 120, attach: bool = False, process_name: str = None) -> dict` | `dict` | 动态分析（Frida Hook） |
| `traffic_capture(apk_id, duration_sec, use_tcpdump)` | `(apk_id: str, duration_sec: int = 60, use_tcpdump: bool = True) -> dict` | `dict` | 流量抓包 |
| `analyze_pcap(pcap_path, label)` | `(pcap_path: str, label: int = None) -> dict` | `dict` | PCAP 跨平台 C2 分析 |
| `evaluate_detection(ground_truth_csv, pcap_list)` | `(ground_truth_csv: str = None, pcap_list: list = None) -> dict` | `dict` | ML 模型评估 |
| `generate_report(target_id)` | `(target_id: str) -> dict` | `dict` | 生成综合 Markdown 报告 |

```python
from engine.engine import AnalysisEngine

# 初始化引擎（默认非演示模式）
engine = AnalysisEngine()

# 列出样本
samples = engine.list_samples()

# 静态分析（Unidbg 模拟执行 SO）
result = engine.static_analysis("sample_001")

# 动态分析（spawn 模式，无隐蔽对抗）
result = engine.dynamic_analysis("sample_001", bypass_evasion=False)

# 动态分析（attach 模式，指定进程名）
result = engine.dynamic_analysis("base", attach=True, process_name="TestC2")

# 生成完整报告
report = engine.generate_report("sample_001")

# 切换演示模式（无真实设备）
engine_demo = AnalysisEngine(demo_mode=True)
```

---

## Frida Hook 脚本参考

`frida_scripts/frida_hook_network.js` 包含 8 组 Hook，覆盖 Java 层和 Native 层网络调用：

### Java 层 Hook

| # | 函数 | 目标方法 | 捕获特征 |
|---|------|---------|---------|
| 1 | `hookSocket()` | `java.net.Socket.connect(SocketAddress)` + `connect(SocketAddress, int)`（两个重载） | `ip, port, interval_ms` |
| 2 | `hookSSLSocket()` | `javax.net.ssl.SSLSocket` + 4 个具体实现类的 `connect()`（两个重载）+ `startHandshake()` | `ip, port, domain, tls_sni, cipher_suites, interval_ms` |
| 3 | `hookHttpsURLConnection()` | `getOutputStream()`, `getInputStream()`, `getResponseCode()`, `connect()` | `url, domain, port, tls_sni, interval_ms` |
| 4 | `hookOkHttp()` | `okhttp3.OkHttpClient.newCall()` | `url, domain, tls_sni, interval_ms` |
| 5 | `hookDatagramSocket()` | `java.net.DatagramSocket.send()` | `ip, port, packet_len, entropy, interval_ms` |
| 6 | `hookDNS()` | `java.net.InetAddress.getAllByName(String)` | `dns_query, interval_ms` |
| 7 | `hookURL()` | `java.net.URL.openConnection()` + `openConnection(Proxy)`（两个重载） | `url, domain, port, interval_ms` |

### Native 层 Hook

| # | libc 函数 | 捕获特征 |
|---|----------|---------|
| 8 | `connect` | `ip, port, protocol: "tcp"` |
| 9 | `send` | `packet_len, entropy, protocol: "tcp"` |
| 10 | `sendto` | `ip, port, packet_len, entropy, protocol: "udp"` |
| 11 | `recv` | `packet_len, entropy, protocol: "tcp"` |
| 12 | `getaddrinfo` | `dns_query` |

### 隐蔽对抗脚本

`frida_scripts/evasion_bypass.js` 提供 8 种反检测伪装：

| # | 技术 | 实现 |
|---|------|------|
| 1 | Build 伪装 | Hook 13 个 `android.os.Build` 字段，返回三星 Galaxy S21 真机值 |
| 2 | 调试检测绕过 | `isDebuggerConnected()` / `waitingForDebugger()` 强制返回 false |
| 3 | maps 过滤 | 拦截 `/proc/self/maps` 读取，过滤 frida/gum-js-loop 等关键字行 |
| 4 | 内核伪装 | Hook `android.system.Os.uname()` 返回假内核版本 |
| 5 | Frida 线程隐藏 | 枚举线程，记录 Frida 相关线程名 |
| 6 | 环境变量过滤 | Hook `System.getProperty()` / `getenv()` 过滤 Frida 环境变量 |
| 7 | Root 检测绕过 | Hook `Runtime.exec()` 拦截 su/busybox/magisk 命令 |
| 8 | 模拟器检测绕过 | Hook `File.exists()` 拦截 QEMU 路径检测 |

### 数据回传机制

```
Hook 回调（任意线程）
  sendFeature(data) → push JSON 到 _sendQueue
                        ↓
setInterval(250ms) → _flushQueue()
  → 所有队列数据批量为 JSON 数组
  → 同步 XMLHttpRequest POST → http://127.0.0.1:8888/data_collect
  → 失败时数据放回队首，下次重试
```

---

## 高级用法

### Attach 模式 vs Spawn 模式

```bash
# spawn 模式（默认）：启动 App → 注入 Hook → 恢复执行
python mcp_server.py --tool dynamic_analysis --params '{"apk_id": "base"}'
# → frida -U --no-pause -f com.example.app -l script.js

# attach 模式：附加到已在运行的进程
python mcp_server.py --tool dynamic_analysis --params '{"apk_id": "base", "attach": true, "process_name": "TestC2"}'
# → frida -U TestC2 -l script.js（跳过 APK 安装）
```

attach 模式典型场景：手动打开 App 并登录到关键页面后，再 attach 上去 Hook 网络层，避免反调试逻辑在启动阶段触发。

### 自定义进程名

当进程名与包名不同（如 `com.example.app:push`），或 attach 模式需要指定不同名称时：

```bash
python mcp_server.py --tool dynamic_analysis \
  --params '{"apk_id": "base", "attach": true, "process_name": "com.example.app:remote"}'
```

### 演示模式

```bash
# 无真实设备时可使用演示模式
python mcp_server.py --demo --tool static_analysis --params '{"apk_id": "sample_001"}'
python mcp_server.py --demo --tool dynamic_analysis --params '{"apk_id": "sample_001"}'
```

### 真实设备分析

```bash
# 1. 连接设备
adb devices

# 2. 启动 frida-server
adb shell /data/local/tmp/frida-server-16.x.x-android-arm64 &

# 3. 启动 MCP Server（非演示模式）
python mcp_server.py --adb "C:\Android\platform-tools\adb.exe"

# 4. 自动建立 ADB reverse（设备 127.0.0.1:8888 → 主机:8888）
python mcp_server.py --tool dynamic_analysis --params '{"apk_id": "base"}'
```

---

## 跨平台C2检测：PCAP流量分析

本平台不仅支持Android恶意C2检测，还可直接分析Windows木马捕获的pcap流量，使用**相同检测模型**输出结果，实现了平台无关的C2通信检测。

### 架构设计

```
Windows EXE木马抓包 → .pcap文件
         ↓
  pcap_analyzer.py (新增独立模块)
         ↓
  提取与动态Hook同构的特征:
    TLS SNI, CipherSuites, 包长度熵,
    通信间隔方差, DNS查询域名熵, 证书信息
         ↓
  加载 c2_model.joblib → predict_proba
         ↓
  {"prediction": "malicious", "confidence": 0.97}
```

### 解析引擎选择

| 优先级 | 引擎 | 安装方式 |
|--------|------|---------|
| 首选 | pyshark | `pip install pyshark` |
| 降级 | scapy | `pip install scapy` |
| 兜底 | 内置模拟数据 | 无需安装（仅演示） |

### 核心能力

1. **TLS ClientHello解析**：纯Python实现，不依赖外部库即可从TCP载荷中提取SNI、密码套件列表、TLS扩展
2. **DNS查询检测**：从DNS应答/请求中提取查询域名，计算域名Shannon熵值
3. **流量时序特征**：计算数据包到达间隔的均值和方差（心跳特征）
4. **包长度熵**：计算包长度序列的Shannon熵（加密流量特征）
5. **证书信息提取**：若有完整TLS握手，提取服务器证书的Issuer和Subject

### 使用方法

```bash
# 通过MCP接口分析PCAP
python mcp_server.py --tool analyze_pcap --params '{"pcap_path": "capture_malware.pcap", "label": 1}'

# 分析PCAP并生成报告（自动识别.pcap后缀）
python mcp_server.py --tool generate_report --params '{"target_id": "capture_malware.pcap"}'

# 合并PCAP评估
python mcp_server.py --tool evaluate_detection --params '{
  "pcap_list": [
    {"pcap_path": "malware1.pcap", "label": 1},
    {"pcap_path": "normal1.pcap", "label": 0}
  ]
}'
```

### 特征同构性

PCAP分析提取的特征字段名与Frida动态Hook完全一致：

| 特征字段 | 动态Hook来源 | PCAP分析来源 |
|---------|-------------|-------------|
| tls_sni | SSLSocket.getHostName() | TLS ClientHello解析 |
| cipher_suites | getEnabledCipherSuites() | ClientHello Cipher Suites |
| packet_length_entropy | Socket数据长度统计 | IP包长度序列熵 |
| interval_variance | 连续连接时间戳差 | 包到达时间间隔方差 |
| dns_query_entropy | InetAddress.getAllByName | DNS查询域名熵 |
| cert_issuer | 证书解析 | 服务器证书Issuer |

---

## 关键技术实现

### 静态分析 — Unidbg

```
APK → 提取libnative.so → Unidbg模拟执行 → JNI环境补全
  → 调用JNI函数(genKey) → 提取密钥(Hex/Base64)
  → Hook SSL_write → TLS CipherSuites → JA3指纹
```

### 动态分析 — Frida

```
启动HTTP数据接收服务器 → [隐蔽对抗脚本加载]
  → 网络Hook脚本注入 → 追踪Socket/TLS/OkHttp/DNS
  → 实时计算熵值和间隔 → HTTP POST回传特征
  → 聚合分析 → C2判定
```

### 流量捕获

```
[ADB tcpdump] → 有root: 设备后台tcpdump抓包 → 拉取pcap
  ↓ tcpdump不可用/反抓包检测
[Frida内存抓取] → 无root/安全检测: 内存拦截Socket数据
```

### 机器学习检测

```
特征CSV → 标准化 → 随机森林(5折交叉验证)
  → 输出: 准确率/召回率/F1/AUC/FPR
  → 特征重要性排序 → 保存模型 joblib
```

---

## 注意事项

1. **合法使用**：本工具仅用于安全研究、教学和授权的渗透测试
2. **模拟数据**：`demo_mode=True` 时所有分析返回模拟数据，仅演示流程
3. **Frida版本**：确保PC端的frida版本与设备端的frida-server版本一致
4. **Root权限**：tcpdump需要Root权限；Frida Hook不需要Root
5. **中文错误**：所有异常提示使用中文

---

## 参考资源

- [Frida官方文档](https://frida.re/docs/)
- [Unidbg - Android SO模拟执行](https://github.com/zhkl0228/unidbg)
- [MCP协议规范](https://modelcontextprotocol.io/)
- [HITCON 2026 Conference](https://hitcon.org/)
- [scikit-learn 随机森林](https://scikit-learn.org/stable/modules/ensemble.html#forest)

---

**CC Team © 2026**
