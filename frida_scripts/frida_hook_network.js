/*
 * MobC2Inspector - Frida网络行为Hook脚本
 * ==========================================
 * 功能：
 *   - Hook Java层关键网络类，提取C2通信特征
 *   - 监控Socket / HttpsURLConnection / OkHttp / DatagramSocket
 *   - 识别TLS连接，解析ClientHello中的SNI、CipherSuites、Extensions
 *   - 检测DNS查询，提取查询域名
 *   - 计算数据包长度信息熵和通信间隔
 *   - 通过Java Socket将特征数据发送到Engine内部服务器
 *
 * 目标C2特征字段：
 *   ip, port, domain, timestamp, interval_ms, entropy,
 *   tls_sni, cipher_suites, dns_query, packet_len
 *
 * 作者: MobC2Inspector Team
 */

// ============================================================
//  全局配置
// ============================================================
var CONFIG = {
    serverUrl: "http://127.0.0.1:8888/data_collect",
    maxPayloadCapture: 512,     // 捕获前512字节的载荷
    attachDelay: 500,           // 注入延迟（ms）
    enableDebug: true           // 调试日志开关（正式使用可改为 false）
};

// ============================================================
//  工具函数
// ============================================================

/** 调试日志（仅在enableDebug时输出） */
function debugLog(msg) {
    if (CONFIG.enableDebug) {
        console.log("[MobC2-Hook] " + msg);
    }
}

/** 当前时间戳（毫秒） */
function now() {
    return Date.now();
}

/** 计算字节数组的Shannon信息熵 */
function calcEntropy(data) {
    if (!data || data.byteLength === 0) return 0.0;

    var freq = {};
    var len = data.byteLength;
    for (var i = 0; i < len; i++) {
        var b = data[i];
        freq[b] = (freq[b] || 0) + 1;
    }

    var entropy = 0.0;
    for (var key in freq) {
        var p = freq[key] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

/** 将字节数组转为Hex字符串 */
function bytesToHex(data) {
    if (!data) return "";
    var hex = "";
    for (var i = 0; i < data.byteLength && i < CONFIG.maxPayloadCapture; i++) {
        var b = data[i] & 0xFF;
        hex += (b < 0x10 ? "0" : "") + b.toString(16);
    }
    return hex;
}

/** 发送队列 + 定时批量回传（使用 Java 原生 Socket，绕开 HttpURLConnection 明文限制） */
var _sendQueue = [];
var _sendTimer = null;

function _flushQueue() {
    if (_sendQueue.length === 0) return;
    var batch = _sendQueue.splice(0, _sendQueue.length);
    var body = "[" + batch.join(",") + "]";
    console.log("[MobC2-FLUSH] 发送 batch: count=" + batch.length + " body=" + body.substring(0, 500));

    Java.perform(function() {
        try {
            var Socket = Java.use("java.net.Socket");
            var InetSocketAddress = Java.use("java.net.InetSocketAddress");
            var socket = Socket.$new();
            socket.connect(InetSocketAddress.$new("127.0.0.1", 8888));
            var os = socket.getOutputStream();
            var httpReq = [
                "POST /data_collect HTTP/1.1",
                "Host: 127.0.0.1:8888",
                "Content-Type: application/json",
                "Content-Length: " + body.length,
                "Connection: close",
                "",
                body
            ].join("\r\n");
            var bytes = Java.array('byte', httpReq.split('').map(function(c) { return c.charCodeAt(0); }));
            os.write(bytes);
            os.flush();
            os.close();
            socket.close();
            console.log("[MobC2-FLUSH] Java Socket 发送成功: count=" + batch.length);
        } catch (e) {
            console.log("[MobC2-FLUSH] Java Socket 失败: " + e);
            _sendQueue = batch.concat(_sendQueue);
        }
    });
}

/** 发送特征数据到Engine服务器（入队，定时器统一回传） */
function sendFeature(data) {
    data.timestamp = now();
    data.hook_version = "1.0.0";
    var jsonStr = JSON.stringify(data);
    console.log("[MobC2-SEND] 入队: type=" + data.type + " data=" + jsonStr.substring(0, 300));
    _sendQueue.push(jsonStr);

    if (!_sendTimer) {
        _sendTimer = setInterval(function() {
            _flushQueue();
            if (_sendQueue.length === 0) {
                clearInterval(_sendTimer);
                _sendTimer = null;
                debugLog("发送队列已清空，定时器停止");
            }
        }, 250);  // 每 250ms 批量回传一次
    }
}

// ============================================================
//  0. 绕过明文流量限制（Android 9+ 默认禁止 HTTP）
// ============================================================
function hookCleartext() {
    try {
        var NSP = Java.use("android.security.NetworkSecurityPolicy");
        NSP.isCleartextTrafficPermitted.overload().implementation = function() {
            return true;
        };
        NSP.isCleartextTrafficPermitted.overload("java.lang.String").implementation = function(host) {
            debugLog("isCleartextTrafficPermitted(" + host + ") -> true (bypassed)");
            return true;
        };
        debugLog("[+] NetworkSecurityPolicy 明文绕过成功");
    } catch (e) {
        console.log("[!] Hook NetworkSecurityPolicy失败: " + e);
    }
}

// ============================================================
//  连接追踪（计算通信间隔）
// ============================================================
var connectionTimestamps = {};

function trackConnection(key) {
    var nowTs = now();
    var lastTs = connectionTimestamps[key] || nowTs;
    var interval = nowTs - lastTs;
    connectionTimestamps[key] = nowTs;
    return interval;
}

// ============================================================
//  1. Hook java.net.Socket（底层TCP连接）
// ============================================================
function _hookSocketConnect(clazz, prefix) {
    var tag = prefix || "socket";

    // 1-arg: connect(SocketAddress)
    try {
        clazz.connect.overload("java.net.SocketAddress").implementation =
            function(address) {
                var ip = "", port = 0;
                try {
                    if (address) {
                        var parts = address.toString().split(":");
                        if (parts.length >= 2) {
                            ip = parts[0].replace("/", "");
                            port = parseInt(parts[parts.length - 1]);
                        }
                    }
                } catch (e) {}
                // 过滤内部回传连接（不记录，不发送特征）
                if (ip === "127.0.0.1" && port === 8888) {
                    return this.connect(address);
                }
                debugLog("[" + tag + "] connect(addr): " + ip + ":" + port);
                var result = this.connect(address);
                sendFeature({
                    type: tag + "_connect", ip: ip, port: port,
                    interval_ms: trackConnection(tag + ":" + ip + ":" + port)
                });
                return result;
            };
    } catch (e) {
        console.log("[!] " + tag + ".connect(SocketAddress) Hook失败: " + e);
    }

    // 2-arg: connect(SocketAddress, int)
    try {
        clazz.connect.overload("java.net.SocketAddress", "int").implementation =
            function(address, timeout) {
                var ip = "", port = 0;
                try {
                    if (address) {
                        var parts = address.toString().split(":");
                        if (parts.length >= 2) {
                            ip = parts[0].replace("/", "");
                            port = parseInt(parts[parts.length - 1]);
                        }
                    }
                } catch (e) {}
                // 过滤内部回传连接
                if (ip === "127.0.0.1" && port === 8888) {
                    return this.connect(address, timeout);
                }
                debugLog("[" + tag + "] connect(addr,timeout): " + ip + ":" + port);
                var result = this.connect(address, timeout);
                sendFeature({
                    type: tag + "_connect", ip: ip, port: port,
                    interval_ms: trackConnection(tag + ":" + ip + ":" + port)
                });
                return result;
            };
    } catch (e) {
        console.log("[!] " + tag + ".connect(SocketAddress,int) Hook失败: " + e);
    }
}

function hookSocket() {
    try {
        var Socket = Java.use("java.net.Socket");
        _hookSocketConnect(Socket, "socket");

        // Hook getOutputStream（发送数据追踪）
        try {
            Socket.getOutputStream.implementation = function() {
                return this.getOutputStream();
            };
        } catch (e) {}

        debugLog("[+] java.net.Socket Hook成功");
    } catch (e) {
        console.log("[!] Hook Socket失败: " + e);
    }
}

// ============================================================
//  2. Hook javax.net.ssl.SSLSocket（TLS连接）
// ============================================================
function _hookStartHandshake(clazz, tag) {
    try {
        clazz.startHandshake.implementation = function() {
            var host = "", port = 0, cipherSuites = [];
            try {
                host = this.getHostName() || "";
                port = this.getPort();
                cipherSuites = this.getEnabledCipherSuites() || [];
            } catch (e) {}

            debugLog("[" + tag + "] TLS握手: " + host + ":" + port);
            sendFeature({
                type: "tls_handshake",
                ip: this.getInetAddress() ? this.getInetAddress().getHostAddress() : "",
                domain: host, port: port,
                tls_sni: host,
                cipher_suites: cipherSuites.slice(0, 10),
                interval_ms: trackConnection("tls:" + host + ":" + port)
            });

            return this.startHandshake();
        };
        debugLog("[+] " + tag + ".startHandshake Hook成功");
    } catch (e) {
        debugLog("[!] " + tag + ".startHandshake Hook失败: " + e);
    }
}

function hookSSLSocket() {
    try {
        // 抽象父类: javax.net.ssl.SSLSocket
        var SSLSocket = Java.use("javax.net.ssl.SSLSocket");
        _hookSocketConnect(SSLSocket, "tls");
        _hookStartHandshake(SSLSocket, "SSLSocket");

        // 具体实现类（覆盖各 Android 版本的 Conscrypt / Harmony 实现）
        var concreteClasses = [
            "com.android.org.conscrypt.OpenSSLSocketImpl",
            "com.android.org.conscrypt.ConscryptEngineSocket",
            "com.android.org.conscrypt.ConscryptFileDescriptorSocket",
            "org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl"
        ];
        for (var i = 0; i < concreteClasses.length; i++) {
            var cname = concreteClasses[i];
            try {
                var impl = Java.use(cname);
                var shortName = cname.split(".").pop();
                console.log("[MobC2-CONSCRYPT] 找到具体实现: " + cname);
                _hookSocketConnect(impl, shortName);
                _hookStartHandshake(impl, shortName);
            } catch (e) {
                console.log("[MobC2-CONSCRYPT] 未找到 " + cname + ": " + e);
            }
        }

        debugLog("[+] javax.net.ssl.SSLSocket 全路径 Hook 完成");
    } catch (e) {
        console.log("[!] Hook SSLSocket失败: " + e);
    }
}

// ============================================================
//  3. Hook HttpsURLConnection（高层HTTPS — 终极捕获点）
// ============================================================
function hookHttpsURLConnection() {
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");

        function captureUrl(conn) {
            var url = "", host = "", port = 0;
            try {
                var u = conn.getURL();
                if (u) {
                    url = u.toString();
                    host = u.getHost();
                    port = u.getPort();
                    if (port === -1) port = u.getDefaultPort();
                }
            } catch (e) {}
            if (!url) { url = String(conn); }
            return { url: url, host: host, port: port };
        }

        function sendHttpsConnect(info) {
            debugLog("HttpsURLConnection: " + info.url);
            sendFeature({
                type: "https_connect",
                url: info.url,
                domain: info.host,
                port: info.port,
                tls_sni: info.host,
                interval_ms: trackConnection("https:" + info.url)
            });
        }

        // Hook getOutputStream() — 隐式连接主要触发点
        try {
            HttpsURLConnection.getOutputStream.implementation = function() {
                var info = captureUrl(this);
                sendHttpsConnect(info);
                return this.getOutputStream();
            };
            debugLog("[+] HttpsURLConnection.getOutputStream Hook成功");
        } catch (e) {
            console.log("[!] Hook HttpsURLConnection.getOutputStream失败: " + e);
        }

        // Hook getInputStream() — 触发连接、接收响应
        try {
            HttpsURLConnection.getInputStream.implementation = function() {
                var info = captureUrl(this);
                sendHttpsConnect(info);
                return this.getInputStream();
            };
            debugLog("[+] HttpsURLConnection.getInputStream Hook成功");
        } catch (e) {
            console.log("[!] Hook HttpsURLConnection.getInputStream失败: " + e);
        }

        // Hook getResponseCode() — 也隐式触发连接
        try {
            HttpsURLConnection.getResponseCode.implementation = function() {
                var info = captureUrl(this);
                sendHttpsConnect(info);
                return this.getResponseCode();
            };
            debugLog("[+] HttpsURLConnection.getResponseCode Hook成功");
        } catch (e) {
            console.log("[!] Hook HttpsURLConnection.getResponseCode失败: " + e);
        }

        // 保留原 connect() 直调路径
        try {
            HttpsURLConnection.connect.implementation = function() {
                var info = captureUrl(this);
                sendHttpsConnect(info);
                return this.connect();
            };
            debugLog("[+] HttpsURLConnection.connect Hook成功");
        } catch (e) {
            console.log("[!] Hook HttpsURLConnection.connect失败: " + e);
        }

        debugLog("[+] HttpsURLConnection 全路径 Hook 完成");
    } catch (e) {
        console.log("[!] Hook HttpsURLConnection失败: " + e);
    }
}

// ============================================================
//  4. Hook OkHttp（常用第三方网络库）
// ============================================================
function hookOkHttp() {
    var okHttpClasses = [
        "okhttp3.OkHttpClient",
        "okhttp3.RealCall",
        "okhttp3.internal.connection.RealConnection"
    ];

    for (var i = 0; i < okHttpClasses.length; i++) {
        try {
            var clazz = Java.use(okHttpClasses[i]);
            if (okHttpClasses[i] === "okhttp3.OkHttpClient") {
                clazz.newCall.implementation = function(request) {
                    var url = "";
                    var host = "";
                    try {
                        url = request.url() ? request.url().toString() : "";
                        host = request.url() ? request.url().host() : "";
                    } catch (e) {}
                    debugLog("OkHttp请求: " + url);
                    sendFeature({
                        type: "okhttp_request",
                        url: url,
                        domain: host,
                        tls_sni: host,
                        interval_ms: trackConnection("okhttp:" + url)
                    });
                    return this.newCall(request);
                };
            }
            debugLog("[+] " + okHttpClasses[i] + " Hook成功");
        } catch (e) {
            debugLog("[!] Hook " + okHttpClasses[i] + "失败: " + e);
        }
    }
}

// ============================================================
//  5. Hook DatagramSocket（UDP通信）
// ============================================================
function hookDatagramSocket() {
    try {
        var DatagramSocket = Java.use("java.net.DatagramSocket");
        DatagramSocket.send.implementation = function(packet) {
            var ip = "";
            var port = 0;
            var packetLen = 0;
            try {
                if (packet) {
                    var addr = packet.getAddress();
                    if (addr) {
                        ip = addr.getHostAddress();
                    }
                    port = packet.getPort();
                    packetLen = packet.getLength();
                }
            } catch (e) {}
            debugLog("UDP发送: " + ip + ":" + port + " len=" + packetLen);
            var entropy = 0.0;
            try {
                var data = packet.getData();
                if (data) {
                    entropy = calcEntropy(data);
                }
            } catch (e) {}
            sendFeature({
                type: "udp_send",
                ip: ip,
                port: port,
                packet_len: packetLen,
                entropy: entropy,
                interval_ms: trackConnection("udp:" + ip + ":" + port)
            });
            return this.send(packet);
        };
        debugLog("[+] java.net.DatagramSocket Hook成功");
    } catch (e) {
        console.log("[!] Hook DatagramSocket失败: " + e);
    }
}

// ============================================================
//  6. Hook DNS查询 (InetAddress)
// ============================================================
function hookDNS() {
    try {
        var InetAddress = Java.use("java.net.InetAddress");
        InetAddress.getAllByName.overload("java.lang.String").implementation =
            function(host) {
                debugLog("DNS查询: " + host);
                sendFeature({
                    type: "dns_query",
                    dns_query: host,
                    interval_ms: trackConnection("dns:" + host)
                });
                return this.getAllByName(host);
            };
        debugLog("[+] DNS查询 Hook成功");
    } catch (e) {
        console.log("[!] Hook DNS失败: " + e);
    }
}

// ============================================================
//  7. Hook java.net.URL（URL连接追踪）
// ============================================================
function hookURL() {
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            var urlStr = "", host = "", port = 0;
            try {
                urlStr = this.toString();
                host = this.getHost();
                port = this.getPort();
                if (port === -1) {
                    port = this.getDefaultPort();
                }
            } catch (e) {}
            debugLog("URL.openConnection(): " + urlStr);
            sendFeature({
                type: "url_connection",
                url: urlStr,
                domain: host,
                port: port,
                interval_ms: trackConnection("url:" + urlStr)
            });
            return this.openConnection();
        };
        URL.openConnection.overload("java.net.Proxy").implementation = function(proxy) {
            var urlStr = "", host = "", port = 0;
            try {
                urlStr = this.toString();
                host = this.getHost();
                port = this.getPort();
                if (port === -1) {
                    port = this.getDefaultPort();
                }
            } catch (e) {}
            debugLog("URL.openConnection(Proxy): " + urlStr);
            sendFeature({
                type: "url_connection",
                url: urlStr,
                domain: host,
                port: port,
                interval_ms: trackConnection("url:" + urlStr)
            });
            return this.openConnection(proxy);
        };
        debugLog("[+] java.net.URL Hook成功");
    } catch (e) {
        console.log("[!] Hook URL失败: " + e);
    }
}

// ============================================================
//  8. Native层 Hook（libc 网络函数）
// ============================================================
var nativeHooks = [];

/** 跨 Android 版本鲁棒查找导出符号 */
function _findExport(symbol) {
    var ptr = null;
    try { ptr = Module.findExportByName(null, symbol); } catch (e) {}
    if (ptr) return ptr;
    try { ptr = Module.findExportByName("libc.so", symbol); } catch (e) {}
    if (ptr) return ptr;
    try {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            var n = mods[i].name.toLowerCase();
            if (n.indexOf("libc") !== -1) {
                ptr = Module.findExportByName(mods[i].name, symbol);
                if (ptr) return ptr;
            }
        }
    } catch (e) {}
    var altNames = ["_" + symbol, "__" + symbol];
    for (var i = 0; i < altNames.length; i++) {
        try { ptr = Module.findExportByName(null, altNames[i]); } catch (e) {}
        if (ptr) return ptr;
        try { ptr = Module.findExportByName("libc.so", altNames[i]); } catch (e) {}
        if (ptr) return ptr;
    }
    return null;
}

function hookNativeNetwork() {
    console.log("[+] 开始注册 Native 层网络 Hook...");

    var connectPtr = _findExport("connect");
    if (connectPtr) {
        try {
            var connectId = Interceptor.attach(connectPtr, {
                onEnter: function(args) {
                    var family = args[1].readU16();
                    if (family === 2) {
                        var p = (args[1].readU8(2) << 8 | args[1].readU8(3));
                        var ip = "";
                        for (var i = 0; i < 4; i++) {
                            ip += args[1].readU8(4 + i);
                            if (i < 3) ip += ".";
                        }
                        this.ip = ip;
                        this.port = p;
                        this.key = "native_connect:" + ip + ":" + p;
                        debugLog("[Native] connect(" + ip + ":" + p + ")");
                    }
                },
                onLeave: function(retval) {
                    if (this.ip && retval.toInt32() === 0) {
                        sendFeature({
                            type: "native_connect", layer: "native",
                            ip: this.ip, port: this.port,
                            protocol: "tcp",
                            interval_ms: trackConnection(this.key)
                        });
                    }
                }
            });
            nativeHooks.push(connectId);
            console.log("[+] connect Hook成功");
        } catch (e) { console.log("[!] Hook connect执行失败: " + e); }
    } else { console.log("[!] connect 符号未找到，跳过"); }

    var sendPtr = _findExport("send");
    if (sendPtr) {
        try {
            var sendId = Interceptor.attach(sendPtr, {
                onEnter: function(args) {
                    var len = args[2].toInt32();
                    if (len > 0 && len < 65536) {
                        var data = args[1].readByteArray(len);
                        this.dataLen = len;
                        this.entropy = data ? calcEntropy(data) : 0;
                        this.key = "native_send:" + now();
                    }
                },
                onLeave: function(retval) {
                    if (this.dataLen && retval.toInt32() > 0) {
                        sendFeature({
                            type: "native_send", layer: "native",
                            protocol: "tcp",
                            packet_len: this.dataLen,
                            entropy: this.entropy,
                            interval_ms: trackConnection(this.key)
                        });
                    }
                }
            });
            nativeHooks.push(sendId);
            console.log("[+] send Hook成功");
        } catch (e) { console.log("[!] Hook send执行失败: " + e); }
    } else { console.log("[!] send 符号未找到，跳过"); }

    var sendtoPtr = _findExport("sendto");
    if (sendtoPtr) {
        try {
            var sendtoId = Interceptor.attach(sendtoPtr, {
                onEnter: function(args) {
                    var len = args[2].toInt32();
                    var sa = args[4];
                    var family = sa.readU16();
                    var ip = "";
                    var port = 0;
                    if (family === 2) {
                        port = (sa.readU8(2) << 8 | sa.readU8(3));
                        for (var i = 0; i < 4; i++) {
                            ip += sa.readU8(4 + i);
                            if (i < 3) ip += ".";
                        }
                    }
                    var data = (len > 0 && len < 65536) ? args[1].readByteArray(len) : null;
                    this.ip = ip;
                    this.port = port;
                    this.dataLen = len;
                    this.entropy = data ? calcEntropy(data) : 0;
                    this.key = "native_sendto:" + ip + ":" + port;
                    if (ip) debugLog("[Native] sendto(" + ip + ":" + port + ") len=" + len);
                },
                onLeave: function(retval) {
                    if (this.ip && retval.toInt32() > 0) {
                        sendFeature({
                            type: "native_sendto", layer: "native",
                            ip: this.ip, port: this.port,
                            protocol: "udp",
                            packet_len: this.dataLen,
                            entropy: this.entropy,
                            interval_ms: trackConnection(this.key)
                        });
                    }
                }
            });
            nativeHooks.push(sendtoId);
            console.log("[+] sendto Hook成功");
        } catch (e) { console.log("[!] Hook sendto执行失败: " + e); }
    } else { console.log("[!] sendto 符号未找到，跳过"); }

    var recvPtr = _findExport("recv");
    if (recvPtr) {
        try {
            var recvId = Interceptor.attach(recvPtr, {
                onEnter: function(args) { this.buf = args[1]; this.len = args[2].toInt32(); },
                onLeave: function(retval) {
                    var bytesRead = retval.toInt32();
                    if (bytesRead > 0 && this.buf && bytesRead < 65536) {
                        var data = this.buf.readByteArray(bytesRead);
                        sendFeature({
                            type: "native_recv", layer: "native",
                            protocol: "tcp",
                            packet_len: bytesRead,
                            entropy: data ? calcEntropy(data) : 0,
                            interval_ms: trackConnection("native_recv:" + now())
                        });
                    }
                }
            });
            nativeHooks.push(recvId);
            console.log("[+] recv Hook成功");
        } catch (e) { console.log("[!] Hook recv执行失败: " + e); }
    } else { console.log("[!] recv 符号未找到，跳过"); }

    var gaiPtr = _findExport("getaddrinfo");
    if (gaiPtr) {
        try {
            var gaiId = Interceptor.attach(gaiPtr, {
                onEnter: function(args) {
                    var nodePtr = args[0];
                    if (nodePtr) {
                        this.node = nodePtr.readCString();
                        if (this.node && this.node.indexOf(".") > 0) {
                            debugLog("[Native] getaddrinfo(" + this.node + ")");
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.node && this.node.indexOf(".") > 0 && retval.toInt32() === 0) {
                        sendFeature({
                            type: "native_dns", layer: "native",
                            dns_query: this.node,
                            interval_ms: trackConnection("native_dns:" + this.node)
                        });
                    }
                }
            });
            nativeHooks.push(gaiId);
            console.log("[+] getaddrinfo Hook成功");
        } catch (e) { console.log("[!] Hook getaddrinfo执行失败: " + e); }
    } else { console.log("[!] getaddrinfo 符号未找到，跳过"); }
}

// ============================================================
//  主入口
// ============================================================
function main() {
    console.log("[MobC2Inspector] Frida网络Hook脚本加载中...");

    hookNativeNetwork();

    Java.perform(function() {
        console.log("[MobC2Inspector] Java环境就绪，开始Hook网络类...");

        hookCleartext();
        hookSocket();
        hookSSLSocket();
        hookHttpsURLConnection();
        hookOkHttp();
        hookDatagramSocket();
        hookDNS();
        hookURL();

        console.log("[MobC2Inspector] 所有网络Hook已注册，开始采集C2特征...");
        console.log("[MobC2Inspector] 数据发送至: " + CONFIG.serverUrl);
        console.log("[MobC2Inspector] enableDebug=" + CONFIG.enableDebug + " 队列定时器已启动");
    });
}

setTimeout(main, CONFIG.attachDelay);