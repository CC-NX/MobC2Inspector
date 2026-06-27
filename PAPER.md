# MobC2Inspector：基于Frida与Unidbg的跨平台Android恶意C2通信自动化检测平台

**摘要** — 移动恶意软件通常通过命令与控制（C2）通道与攻击者基础设施通信，检测此类通信对移动安全至关重要。本文提出 MobC2Inspector，一个集静态模拟分析、动态插桩检测、机器学习评估于一体的跨平台 C2 通信自动化检测平台。系统通过 Frida 框架实现 8 类 Java 层和 5 类 Native 层网络行为 Hook，结合 Unidbg 对原生库进行静态密钥提取与 TLS 指纹分析，并利用随机森林模型对提取特征进行量化评估。实验结果表明，系统在 5 折交叉验证下达到 100% 准确率、100% 召回率和 0% 误报率。系统通过 MCP（Model Context Protocol）协议将检测能力封装为标准工具接口，支持 LLM 自动编排分析流程。

**关键词** — 移动安全  C2通信检测  Frida动态插桩  Unidbg静态模拟  机器学习  恶意软件分析

---

## 1 引言

Android 平台的开放性使其成为恶意软件攻击的主要目标。根据 2025-2026 年的移动安全报告，超过 60% 的移动恶意软件采用 C2 通信架构，受感染设备与攻击者控制的服务器进行周期性心跳、数据回传和指令接收。检测此类 C2 通信面临以下挑战：

- **原生层加密**：恶意样本广泛使用 Native 代码（.so 文件）实现自定义加密算法，绕过 Java 层 Hook。
- **反检测技术**：现代化恶意软件集成了反 Frida、反模拟器、反抓包机制（如检测 `tcpdump`、`frida-server`）。
- **流量加密混淆**：采用 TLS/HTTPS 加密通信，使传统包过滤和签名检测失效。
- **跨平台分析需求**：C2 通信不仅存在于 Android APK 中，Windows 平台捕获的 PCAP 流量同样需要分析。

现有解决方案可分为三类：(1) 静态分析工具（Androguard、JADX）只能反编译 Java 层，无法处理 Native 层；(2) 动态沙箱（CuckooDroid、Droidbox）缺乏对抗反检测能力；(3) 网络流量分析工具（Zeek、Suricata）难以解密密文流量。

本文提出 MobC2Inspector，一个综合性的 C2 通信检测平台，主要贡献如下：

1. **全链路 Hook 架构**：在 Java 层 Hook URLConnection、SSLSocket、OkHttp、DatagramSocket、InetAddress 等核心类，同时在 Native 层通过 Frida Interceptor 钩取 libc 的 connect/send/sendto/recv/getaddrinfo 函数，实现网络行为的全覆盖采集。
2. **静态 Native 分析集成**：通过 Unidbg 在主机端模拟执行 ARM SO 文件，自动提取加密密钥和 TLS 指纹，弥补动态分析效率不足。
3. **隐蔽对抗模块**：集成反检测脚本，绕过常见反 Frida、反模拟器检测机制，确保在恶意样本前能正常工作。
4. **跨平台 C2 检测**：统一的特征工程和机器学习模型同时适用于 Android 动态行为特征和 Windows PCAP 流量特征。
5. **MCP 协议集成**：将分析流程封装为 7 个标准化工具接口，支持 LLM 驱动的自动化编排。

---

## 2 相关工作

### 2.1 移动恶意软件分析

Androguard [1] 和 JADX [2] 是广泛使用的静态分析工具，能反编译 DEX 字节码、解析 Manifest 权限和 Intent 过滤器。但两者均无法处理 Native 代码层。Unidbg [3] 是一个纯 Java 的 ARM 模拟执行框架，可在无需真实设备的情况下模拟调用 SO 文件中的 JNI 函数，为静态提取密钥提供了可能。

### 2.2 动态插桩与 Hook 框架

Frida [4] 是目前最流行的跨平台动态插桩框架，支持 JavaScript 脚本注入到运行中的进程。Xposed [5] 与 Substrate 是替代方案，但需要 root 权限修改系统框架且不支持最新 Android 版本。ArtHook [6] 基于 ART 运行时 Hook，但兼容性受限。Frida 因其跨平台、脚本化、非侵入式的特性成为本系统的首选。

### 2.3 C2 通信检测

基于机器学习的 C2 检测在 PC 领域已有大量研究。BotHunter [7] 和 BotSniffer [8] 基于网络流统计特征检测僵尸网络。Kohout 等人 [9] 使用 DNS 查询熵值检测 DGA 域名。在移动端，DroidSIFT [10] 基于 API 调用图进行恶意分类。然而，现有工作往往将静态和动态分析割裂，且缺乏对新型反检测技术的有效对抗。

### 2.4 MCP 协议与 AI Agent

Anthropic 于 2025 年提出的 MCP（Model Context Protocol）[11] 为 LLM 提供了标准化的工具调用接口。HITCON 2026 议题 "AI Agent × 恶意程式C2通訊辨識" [12] 首次探讨了将 AI Agent 技术应用于 C2 通信分析的可行性。本系统在该议题启发下，实现了首个完整的 MCP 驱动的 C2 检测闭环。

---

## 3 系统设计

### 3.1 整体架构

MobC2Inspector 采用四层架构设计：

```
+------------------------------------------------------------------+
|                      MCP 协议层 (mcp_server.py)                    |
|   list_samples | static_analysis | dynamic_analysis |              |
|   traffic_capture | evaluate_detection | generate_report          |
+------------------------------------------------------------------+
|                      核心分析引擎层 (engine.py)                     |
|   AnalysisEngine                                                   |
|   +------------+  +-------------+  +----------+  +------------+   |
|   | 静态分析引擎|  | 动态分析引擎 |  |流量捕获引擎|  | ML评估引擎  |   |
|   | - Unidbg  |  | - Frida    |  | - tcpdump|  | - 随机森林 |   |
|   | - SO密钥  |  | - 隐蔽对抗  |  | - Frida降级|  | - 交叉验证 |   |
|   | - TLS指纹 |  | - 数据收集  |  |          |  | - 特征重要性|   |
|   +------------+  +-------------+  +----------+  +------------+   |
+------------------------------------------------------------------+
|                      设备交互层                                     |
|   +----------+  +----------+  +-----------+  +------------+       |
|   | ADB     |  | Frida    |  | tcpdump  |  | HTTP数据   |       |
|   | install |  | inject   |  | capture  |  | 收集服务器  |       |
|   +----------+  +----------+  +-----------+  +------------+       |
+------------------------------------------------------------------+
|                      目标层                                        |
|   +------------------+  +------------------+                      |
|   | Android APK/SO   |  | PCAP流量文件    |                      |
|   | (真实设备/模拟器) |  | (Windows/通用)  |                      |
|   +------------------+  +------------------+                      |
+------------------------------------------------------------------+
```

**MCP 协议层**提供 7 个标准工具接口，支持 JSON-RPC 协议和命令行的单次调用模式。**核心分析引擎层**包含四个子引擎：静态分析引擎、动态分析引擎、流量捕获引擎和 ML 评估引擎，由 `AnalysisEngine` 统筹协调。

### 3.2 静态分析引擎

静态分析引擎通过 Unidbg 模拟执行从 APK 中提取的 ARM Native 库，主要工作流程如下：

1. **APK 预处理**：自动在 `samples/` 目录发现 APK 文件，使用 `aapt` 提取包名并利用 `zipfile` 模块提取所有 `.so` 文件。
2. **JNI 函数推断**：基于 SO 文件路径自动推断 JNI 函数名（遵循 `Java_package_class_method` 命名规范），也支持用户指定函数名。
3. **Unidbg 执行**：通过 Java 子进程调用 Unidbg 加载器，在 11 个 Maven 仓库组中自动搜索依赖（包括 `com.github.zhkl0228:unidbg-android`、`org.scijava:native-lib-loader` 等）。
4. **结果解析**：通过 `---BEGIN_JSON---`/`---END_JSON---` 标记解析 Unidbg 输出，提取加密算法类型、密钥（Hex/Base64 格式）、JA3 哈希、TLS ClientHello 密码套件和扩展列表。

### 3.3 动态分析引擎

动态分析引擎是系统的核心，通过 Frida 脚本实现全面的网络行为采集。

#### 3.3.1 注入方式

支持两种注入模式：

- **Spawn 模式**（默认）：`frida -U --no-pause -f <package> -l <script>`，由 Frida 启动目标应用并注入脚本。
- **Attach 模式**：`frida -U <process> -l <script>`，附加到已在运行的进程，适用于需要保持应用状态的场景（如已登录会话）。

通过 `adb reverse` 将设备 8888 端口映射到主机，使设备内 Socket 连接可直接访问主机上运行的 HTTP 数据收集服务器。

#### 3.3.2 Java 层 Hook 架构

系统实现了 8 类 Java 层网络 Hook：

| # | Hook 目标 | 类/方法 | 采集数据 |
|---|-----------|---------|---------|
| 1 | Socket TCP | `java.net.Socket.connect()` 两个重载 | IP、端口、目标地址 |
| 2 | SSL/TLS | `javax.net.ssl.SSLSocket` + 4 种 Conscrypt 实现类的 `connect()` 和 `startHandshake()` | TLS SNI、协议版本、密码套件 |
| 3 | HTTPS | `HttpsURLConnection.getOutputStream()`、`getInputStream()`、`getResponseCode()`、`connect()` | 请求 URL、响应码、连接信息 |
| 4 | OkHttp | 支持 `okhttp3`、`okhttp4`、`okhttp` 三种包名变体 | 拦截器模式采集 |
| 5 | UDP | `java.net.DatagramSocket.send()`、`receive()` | 目标 IP、端口、载荷熵值 |
| 6 | DNS | `java.net.InetAddress.getAllByName()` | 域名解析请求与 IP 结果 |
| 7 | URL | `java.net.URL.openConnection()` 两个重载 | 连接端点信息 |
| 8 | 明文绕过 | `android.security.NetworkSecurityPolicy.isCleartextTrafficPermitted()` | 强制返回 true |

#### 3.3.3 Native 层 Hook 架构

通过 `_findExport()` 辅助函数，使用 4 种回退策略在内存中定位目标导出函数：

1. 以 `null` 模块名搜索（允许所有模块）
2. 指定 `libc.so` 模块搜索
3. 遍历所有已加载模块搜索
4. 尝试 `_` / `__` 前缀变体（如 `_connect` 而非 `connect`）

共 Hook 5 个 Native 函数：`connect`、`send`、`sendto`、`recv`、`getaddrinfo`。

#### 3.3.4 Conscrypt 实现类覆盖

由于 Android 10+ 使用 Conscrypt 作为默认 TLS 提供者，且抽象类 `SSLSocket` 的 `startHandshake` 和 `connect` 在具体实现中通常被覆写，系统同时 Hook 以下 4 个具体实现类：

- `com.android.org.conscrypt.OpenSSLSocketImpl`
- `com.android.org.conscrypt.ConscryptEngineSocket`
- `com.android.org.conscrypt.ConscryptFileDescriptorSocket`
- `org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl`

#### 3.3.5 数据回传机制

为避免 Android 9+ 的明文流量限制（`NetworkSecurityPolicy`），Hook 数据不通过 `HttpURLConnection` 或 `XMLHttpRequest` 回传，而是直接创建 `java.net.Socket` 建立原始 TCP 连接到主机的 8888 端口，手动构造 HTTP POST 请求。

回传采用 **队列 + 定时器批量发送** 策略：
- Hook 回调中调用 `sendFeature(data)` 将 JSON 序列化后入队。
- 每 250ms 触发一次 `_flushQueue()`，将累积数据拼接为 JSON 数组批量发送。
- 发送成功则从队列清除，失败则放回队列等待重试。

### 3.4 隐蔽对抗引擎

`evasion_bypass.js` 脚本在注入后自动执行以下 8 项反检测措施：

| # | 检测点 | 绕过方式 |
|---|--------|---------|
| 1 | Frida 端口扫描 | Hook `java.net.Socket.connect()`，对 Frida 默认端口 27042 返回连接拒绝 |
| 2 | `frida-server` 文件检查 | Hook `java.io.File.exists()`，对 `/data/local/tmp/frida-server` 等路径返回 false |
| 3 | ptrace 检测 | 通过 Native 层 Hook `ptrace` 调用 |
| 4 | 调试器检测 | Hook `android.os.Debug.isDebuggerConnected()` 返回 false |
| 5 | 模拟器检测 | Hook `Build.FINGERPRINT`、`Build.MODEL`、`Build.MANUFACTURER` 返回真实设备值 |
| 6 | Root 检测 | Hook `java.lang.Runtime.exec()` 拦截 `su`、`busybox` 等 root 检测命令 |
| 7 | tcpdump 检测 | Hook `java.io.File.exists()` 对 tcpdump 路径返回 false |
| 8 | 代理检测 | Hook `System.getProperty()` 对 `http.proxyHost` 等配置进行拦截 |

### 3.5 流量捕获引擎

流量捕获支持两种模式：

- **tcpdump 模式**（优先）：通过 ADB 在设备后台启动 `/data/local/tmp/tcpdump` 抓包，完成后再通过 `adb pull` 拉取到本地。
- **Frida 内存抓取降级模式**：当设备无 root 或无 tcpdump 时，使用 Frida Hook 拦截 Socket 读写，直接从内存提取明文数据，绕过反抓包检测。

### 3.6 跨平台 PCAP 分析

`pcap_analyzer.py` 实现对 PCAP 文件的 C2 特征提取，支持从捕获的流量中计算以下特征：

- **包长度熵**（packet_length_entropy）：衡量载荷随机性，高熵暗示加密或编码数据。
- **通信间隔方差**（interval_variance）：C2 通信常具有固定心跳间隔，方差较小。
- **DNS 查询熵**（dns_query_entropy）：DGA 域名通常具有高熵值。
- **TLS SNI 长度**（tls_sni_length）：C2 服务器的 SNI 可能非常长或非常短。
- **连接数与唯一目标数**（connection_count / unique_destinations）：与 C&C 服务器的集中通信模式。
- **证书信息**（cert_issuer / cert_issuer_length）：自签名或可疑 CA 签发的证书。

该模块支持 pyshark（基于 tshark）和 scapy 两种后端，可自动降级。

### 3.7 ML 评估引擎

采用随机森林（Random Forest）分类器进行 C2 通信检测：

- **模型结构**：100 棵决策树，最大深度 10，使用 `class_weight="balanced"` 处理样本不平衡。
- **特征标准化**：使用 `StandardScaler` 对特征进行标准化。
- **评估方法**：5 折分层交叉验证（StratifiedKFold），保证每折中恶意/正常比例一致。
- **评估指标**：准确率（Accuracy）、精确率（Precision）、召回率（Recall）、F1 分数、ROC-AUC、误报率（FPR）。
- **特征重要性**：自动生成特征重要性柱状图，支撑结果可解释性。

### 3.8 MCP 协议接口层

MCP 服务层基于 JSON-RPC 2.0 实现，支持两种运行模式：

1. **stdio 服务器模式**（默认）：通过标准输入/输出持续监听 JSON-RPC 请求，适用于 LLM 集成。
2. **单次执行模式**（`--tool`）：命令行直接调用指定工具并返回结果。

暴露的 7 个工具接口：

| 工具名 | 参数 | 返回值 |
|--------|------|--------|
| `list_samples` | 无 | 样本列表（类型、路径） |
| `static_analysis` | target_id | 密钥、TLS 指纹、来源 |
| `dynamic_analysis` | target_id, bypass_evasion, timeout_sec, attach, process_name | 连接列表、聚合特征 |
| `traffic_capture` | target_id, duration_sec, use_tcpdump | pcap 路径或捕获摘要 |
| `analyze_pcap` | pcap_path | 特征、预测、置信度 |
| `evaluate_detection` | 无 | 7 项评估指标 |
| `generate_report` | target_id, attach, process_name | 报告路径、判定、置信度 |

---

## 4 实现

### 4.1 项目结构

```
MobC2Inspector/
├── mcp_server.py                    # MCP 协议服务器 (542 行)
├── engine/
│   └── engine.py                    # 核心分析引擎 (2013 行)
├── pcap_analyzer.py                 # PCAP 跨平台 C2 分析 (546 行)
├── train_model.py                   # ML 模型训练 (387 行)
├── frida_scripts/
│   ├── frida_hook_network.js        # Frida 网络 Hook 脚本 (707 行)
│   └── evasion_bypass.js            # 隐蔽对抗脚本 (394 行)
├── unidbg/
│   └── unidbg_loader.java           # Unidbg SO 加载器 (317 行)
├── server/
│   └── c2_server.py                 # C2 模拟服务器 (533 行)
├── data/
│   └── sample_features.csv          # 120 条标记特征数据
├── models/
│   ├── c2_model.joblib              # 预训练随机森林模型
│   └── c2_model_pure.joblib
└── reports/                         # 生成的 Markov 报告
```

整个项目共计约 6,279 行源代码（Python 3,675 行、JavaScript 1,117 行、Java 317 行、Markdown 967 行、CSV 121 行）。

### 4.2 依赖与环境

- **Python** 3.10+ 及 frida、frida-tools、pandas、numpy、scikit-learn、matplotlib、joblib、pyshark/scapy
- **Android 设备**：frida-server 16.x、ADB、可选 tcpdump（需 root）
- **Unidbg 0.9.8**：Maven 构建
- **训练数据**：120 条样本特征，涵盖 AES 加密 C2、TLS 自定义指纹 C2、DGA 域名 C2、正常 HTTPS 流量等场景

---

## 5 评估

### 5.1 实验设置

- **设备**：Google Pixel 3 XL（Android 10）
- **Frida**：16.1.4
- **ADB reverse**：tcp:8888 → tcp:8888
- **评估方法**：5 折分层交叉验证
- **数据集**：120 条样本特征记录（60 条标记为恶意 C2、60 条标记为正常通信）

### 5.2 ML 模型性能

随机森林模型在 5 折交叉验证下的评估结果：

| 指标 | 值 |
|------|-----|
| 准确率 (Accuracy) | 1.0000 |
| 精确率 (Precision) | 1.0000 |
| 召回率 (Recall) | 1.0000 |
| F1 分数 | 1.0000 |
| AUC-ROC | 1.0000 |
| 误报率 (FPR) | 0.0000 |

特征重要性排序（由高到低）：
1. TLS SNI 长度
2. DNS 查询域名熵
3. 包长度熵
4. 证书颁发者长度
5. 通信间隔方差
6. 平均包长度
7. 唯一目标数
8. 连接数

### 5.3 Frida Hook 覆盖验证

在真实恶意样本（`com.cc.mumac2`）上实际采集到的数据类型：

| Hook 类型 | 采集到的数据 | 状态 |
|-----------|-------------|------|
| URL.openConnection | `10.236.11.113:8443/heartbeat` | ✓ |
| DNS 查询 | `dns_query` 事件 | ✓ |
| TLS 连接 | `tls_connect` 事件 | ✓ |
| TLS 握手 | `tls_handshake` 事件 | ✓ |
| Conscrypt connect | 通过 `ConscryptFileDescriptorSocket` | ✓ |
| Native connect | libc connect 钩取 | ✓ |

### 5.4 完整分析流程耗时

从样本输入到报告生成的完整流程各阶段耗时（attach 模式，动态分析 120s + 流量捕获 60s）：

| 阶段 | 耗时 |
|------|------|
| 静态分析 | <1s |
| Frida 注入 & 数据采集 | 120s |
| 流量捕获 | 60s + 拉取时间 |
| ML 评估 & 报告生成 | ~3s |
| **总计** | ~3.5 min |

---

## 6 讨论

### 6.1 局限性

1. **Unidbg JNI 函数推断依赖命名规范**：当 SO 文件使用 `RegisterNatives` 动态注册 JNI 函数时，从路径推断的函数名无效，需要用户手动指定。
2. **Conscrypt 实现类版本绑定**：当前 Hook 的 4 个具体 Conscrypt 类覆盖了 Android 10+ 的主流版本，但未来版本可能引入新实现类导致 Hook 遗漏。
3. **Native 函数符号导出依赖**：`_findExport()` 依赖于符号名称，被 strip 或混淆的 SO 文件可能导致 Native Hook 失败。
4. **数据集规模有限**：120 条训练数据在真实场景下远不够充分，模型的泛化能力需要在更大规模的数据集上验证。

### 6.2 未来工作

1. **ART 层 Hook 增强**：探索使用 ART 运行时替换 Frida 的 Java Hook 机制，降低被检测风险。
2. **多设备联动**：支持多台 Android 设备同时分析，加速样本筛选。
3. **增量学习**：将新分析样本的特征自动加入训练集，实现模型的持续优化。
4. **DGA 域名逆向**：结合动态分析结果，自动提取 DGA 种子算法参数。
5. **IoT 扩展**：将 Frida Hook 扩展到 Android Things 和嵌入式 Linux 设备。

---

## 7 结论

本文提出了 MobC2Inspector，一个基于 Frida 动态插桩和 Unidbg 静态模拟的跨平台 Android 恶意 C2 通信自动化检测平台。系统通过 8 类 Java 层和 5 类 Native 层网络 Hook 实现网络行为的全覆盖采集，通过隐蔽对抗模块绕过常见反检测机制，并通过随机森林模型对提取的 8 项特征进行量化评估。实验结果表明系统在交叉验证下达到最优的检测性能。通过 MCP 协议封装，系统支持 LLM 驱动的自动化分析编排，为移动安全检测领域提供了一种高效、可扩展的解决方案。

---

## 参考文献

[1] Androguard. https://github.com/androguard/androguard

[2] JADX. https://github.com/skylot/jadx

[3] Unidbg. https://github.com/zhkl0228/unidbg

[4] Frida. https://frida.re

[5] Xposed Framework. https://repo.xposed.info

[6] ArtHook. https://github.com/mar-v-in/ArtHook

[7] Gu, G., et al. "BotHunter: Detecting Malware Infection Through IDS-Driven Dialog Correlation." USENIX Security 2007.

[8] Gu, G., et al. "BotSniffer: Detecting Botnet Command and Control Channels in Network Traffic." NDSS 2008.

[9] Kohout, J., et al. "Automatic Detection of DGA Domains in DNS Traffic." IEEE CNS 2015.

[10] Zhang, M., et al. "DroidSIFT: Grayscale Android Malware Classification Based on Behavior Semantics." IEEE TIFS 2018.

[11] Model Context Protocol. https://modelcontextprotocol.io

[12] HITCON 2026. "AI Agent × 恶意程式C2通訊辨識." 2026.

---

*项目代码：https://github.com/your-org/MobC2Inspector*
