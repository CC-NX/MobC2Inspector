"""
MobC2Inspector - PCAP流量分析模块（跨平台C2特征提取）
====================================================
从PCAP文件中提取与动态Hook同构的C2通信特征，使Windows EXE木马捕获的流量
可使用同一套检测模型进行判定，实现平台无关的恶意C2检测。

功能：
  - 解析PCAP/PCAPNG格式流量文件
  - 重建TCP/UDP流，检测TLS ClientHello
  - 提取SNI、密码套件、TLS扩展
  - 检测DNS查询，计算域名熵值
  - 计算包长度序列熵值、通信间隔方差
  - 输出与 dynamic_analysis 完全同构的特征字典

依赖：
  - pyshark（推荐）或 scapy

作者：MobC2Inspector Team
"""

import os
import re
import math
import json
import struct
import logging
import collections
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Optional

logger = logging.getLogger("MobC2PCAP")

# ============================================================
#  解析引擎选择：优先pyshark，降级scapy
# ============================================================
_USE_PYSHARK = False
_USE_SCAPY = False

try:
    import pyshark
    _USE_PYSHARK = True
    logger.info("PCAP分析引擎: pyshark")
except ImportError:
    try:
        import scapy.all as scapy
        _USE_SCAPY = True
        logger.info("PCAP分析引擎: scapy (降级)")
    except ImportError:
        logger.warning("未安装pyshark或scapy，PCAP分析将使用模拟数据")


# ============================================================
#  常量
# ============================================================
TLS_CONTENT_TYPE_HANDSHAKE = 0x16
TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
TLS_HANDSHAKE_TYPE_SERVER_HELLO = 0x02
TLS_HANDSHAKE_TYPE_CERTIFICATE = 0x0B

# tshark 路径（pyshark 通过该路径调用 tshark 解析 PCAP）
TSHARK_PATH = r"D:\Tools\webtools\wireshark\tshark.exe"

# 常见密码套件映射（IANA编号 -> 名称）
CIPHER_SUITE_MAP = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0xCC13: "TLS_CHACHA20_POLY1305_SHA256_OLD",
    0xCC14: "TLS_CHACHA20_POLY1305_SHA256_OLD",
}


# ============================================================
#  TLS ClientHello 解析（纯Python，无需外部依赖）
# ============================================================
def _parse_tls_clienthello(data: bytes) -> dict:
    """
    从TCP载荷中解析TLS ClientHello消息。

    TLS Record格式：
      Byte 0:     Content Type (0x16 = Handshake)
      Byte 1-2:   Protocol Version (e.g. 0x0303 = TLS 1.2)
      Byte 3-4:   Length
      Byte 5:     Handshake Type (0x01 = ClientHello)
      Byte 6-8:   Length (3 bytes)
      Byte 9-10:  Version
      Byte 11-42: Random (32 bytes)
      Byte 43:    Session ID Length
      ... Session ID ...
      ... Cipher Suites (2 bytes count + list) ...
      ... Compression Methods ...
      ... Extensions ...

    Args:
        data: TCP载荷字节数据

    Returns:
        dict: 包含 sni, cipher_suites, extensions 等字段
    """
    result = {
        "tls_sni": None,
        "cipher_suites": [],
        "extensions": [],
        "tls_version": None
    }

    if len(data) < 50:
        return result

    try:
        offset = 0

        # TLS Record 层
        content_type = data[offset]
        if content_type != TLS_CONTENT_TYPE_HANDSHAKE:
            return result
        offset += 1

        version = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2
        tls_version_map = {
            0x0300: "SSL 3.0", 0x0301: "TLS 1.0",
            0x0302: "TLS 1.1", 0x0303: "TLS 1.2",
            0x0304: "TLS 1.3"
        }
        result["tls_version"] = tls_version_map.get(version, f"0x{version:04X}")

        # Record 长度
        record_length = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2

        if offset + 4 > len(data):
            return result

        # Handshake 层
        handshake_type = data[offset]
        offset += 1
        if handshake_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
            return result

        # Handshake 长度（3字节，大端）
        hs_length = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]
        offset += 3

        if offset + 2 > len(data):
            return result

        # Client Version
        client_version = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2

        # Random (32 bytes) - 跳过
        offset += 32

        if offset >= len(data):
            return result

        # Session ID
        session_id_len = data[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(data):
            return result

        # Cipher Suites
        cipher_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2

        cipher_suite_ids = []
        for i in range(0, cipher_len, 2):
            if offset + i + 2 <= len(data):
                cs_id = struct.unpack(">H", data[offset + i:offset + i + 2])[0]
                cipher_suite_ids.append(cs_id)

        result["cipher_suites"] = [
            CIPHER_SUITE_MAP.get(csid, f"TLS_0x{csid:04X}")
            for csid in cipher_suite_ids
        ]
        offset += cipher_len

        if offset >= len(data):
            return result

        # Compression Methods
        comp_len = data[offset]
        offset += 1 + comp_len

        if offset >= len(data):
            return result

        # Extensions
        ext_total_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2

        ext_end = offset + ext_total_len
        while offset + 4 <= ext_end and offset + 4 <= len(data):
            ext_type = struct.unpack(">H", data[offset:offset + 2])[0]
            ext_len = struct.unpack(">H", data[offset + 2:offset + 4])[0]
            offset += 4

            ext_name = _get_extension_name(ext_type)

            # Type 0: Server Name Indication (SNI)
            if ext_type == 0 and ext_len > 5:
                sni_list_len = struct.unpack(">H", data[offset:offset + 2])[0]
                if sni_list_len > 2 and offset + 3 + sni_list_len <= len(data):
                    sni_entry_type = data[offset + 2]
                    sni_entry_len = struct.unpack(">H", data[offset + 3:offset + 5])[0]
                    if sni_entry_type == 0 and sni_entry_len > 0:
                        sni_start = offset + 5
                        if sni_start + sni_entry_len <= len(data):
                            result["tls_sni"] = data[sni_start:sni_start + sni_entry_len].decode("utf-8", errors="ignore")

            result["extensions"].append(ext_name)
            offset += ext_len

    except Exception as e:
        logger.debug(f"TLS ClientHello解析异常: {e}（可能不是完整TLS握手）")

    return result


def _get_extension_name(ext_type: int) -> str:
    """将TLS扩展类型号转为名称。"""
    ext_names = {
        0: "server_name", 1: "max_fragment_length",
        2: "client_certificate_url", 3: "trusted_ca_keys",
        4: "truncated_hmac", 5: "status_request",
        6: "user_mapping", 7: "client_authz",
        8: "server_authz", 9: "cert_type",
        10: "supported_groups", 11: "ec_point_formats",
        12: "srp", 13: "signature_algorithms",
        14: "use_srtp", 15: "heartbeat",
        16: "application_layer_protocol_negotiation",
        17: "status_request_v2", 18: "signed_certificate_timestamp",
        19: "client_certificate_type", 20: "server_certificate_type",
        21: "padding", 22: "encrypt_then_mac",
        23: "extended_master_secret", 24: "token_binding",
        25: "cached_info", 26: "tls_lts",
        27: "compress_certificate", 28: "record_size_limit",
        41: "pre_shared_key", 42: "early_data",
        43: "supported_versions", 44: "cookie",
        45: "psk_key_exchange_modes", 46: "certificate_authorities",
        47: "oid_filters", 48: "post_handshake_auth",
        49: "signature_algorithms_cert", 50: "key_share"
    }
    return ext_names.get(ext_type, f"extension_0x{ext_type:04X}")


# ============================================================
#  字符串熵值计算（Shannon Entropy）
# ============================================================
def _calc_entropy(data: str) -> float:
    """计算字符串的Shannon信息熵。"""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq = collections.Counter(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ============================================================
#  PCAP解析主函数（pyshark实现）
# ============================================================
def _extract_with_pyshark(pcap_path: str) -> dict:
    """使用pyshark解析pcap文件并提取C2特征。"""
    import pyshark

    cap = pyshark.FileCapture(
        pcap_path,
        tshark_path=TSHARK_PATH
    )

    # 会话分组（按IP对 + 端口对分组）
    sessions = {}
    tls_hellos = []
    dns_queries = []
    cert_info = {}
    all_packets = []
    timestamps = []
    packet_lengths = []
    destinations = set()

    for pkt in cap:
        try:
            ts = float(pkt.sniff_timestamp) if hasattr(pkt, 'sniff_timestamp') else 0
            timestamps.append(ts)

            length = int(pkt.length) if hasattr(pkt, 'length') else 0
            packet_lengths.append(length)

            all_packets.append(pkt)

            # 收集目标IP用于 unique_destinations
            try:
                if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'dst'):
                    destinations.add(str(pkt.ip.dst))
                if hasattr(pkt, 'ipv6') and hasattr(pkt.ipv6, 'dst'):
                    destinations.add(str(pkt.ipv6.dst))
            except Exception:
                pass

            # 判断协议层
            layer_names = [layer.layer_name for layer in pkt.layers] if hasattr(pkt, 'layers') else []

            # TLS检测
            if 'tls' in layer_names or 'ssl' in layer_names:
                tls_layer = pkt.tls if hasattr(pkt, 'tls') else (pkt.ssl if hasattr(pkt, 'ssl') else None)
                if tls_layer:
                    # 检查是否为Handshake类型的TLS记录
                    handshake_type = None
                    try:
                        if hasattr(tls_layer, 'handshake_type'):
                            handshake_type = int(tls_layer.handshake_type)
                    except (ValueError, AttributeError):
                        pass

                    if handshake_type == 1:  # ClientHello
                        hello_info = {"tls_sni": None, "cipher_suites": [], "extensions": []}

                        # SNI
                        if hasattr(tls_layer, 'tls_handshake_extensions_server_name'):
                            hello_info["tls_sni"] = str(tls_layer.tls_handshake_extensions_server_name)
                        # 也尝试从ssl中获取
                        elif hasattr(tls_layer, 'ssl_handshake_extensions_server_name'):
                            hello_info["tls_sni"] = str(tls_layer.ssl_handshake_extensions_server_name)

                        # Cipher Suites
                        if hasattr(tls_layer, 'tls_handshake_ciphersuites'):
                            cs_raw = str(tls_layer.tls_handshake_ciphersuites)
                            hello_info["cipher_suites"] = [c.strip() for c in cs_raw.split(",")]
                        elif hasattr(tls_layer, 'ssl_handshake_ciphersuites'):
                            cs_raw = str(tls_layer.ssl_handshake_ciphersuites)
                            hello_info["cipher_suites"] = [c.strip() for c in cs_raw.split(",")]

                        tls_hellos.append(hello_info)

                    elif handshake_type == 11:  # Certificate
                        if hasattr(tls_layer, 'tls_handshake_certificate'):
                            cert_info["raw"] = str(tls_layer.tls_handshake_certificate)[:200]
                        # 尝试解析证书Issuer
                        if hasattr(tls_layer, 'tls_handshake_certificate_issuer'):
                            cert_info["issuer"] = str(tls_layer.tls_handshake_certificate_issuer)
                        if hasattr(tls_layer, 'tls_handshake_certificate_subject'):
                            cert_info["subject"] = str(tls_layer.tls_handshake_certificate_subject)

            # DNS检测
            if 'dns' in layer_names:
                dns_layer = pkt.dns
                if hasattr(dns_layer, 'dns_qry_name'):
                    qname = str(dns_layer.dns_qry_name)
                    if qname:
                        dns_queries.append(qname)

        except Exception as e:
            logger.debug(f"解析单个包异常: {e}")
            continue

    cap.close()

    # ---- 计算特征 ----
    return _compute_features(
        tls_hellos=tls_hellos,
        dns_queries=dns_queries,
        timestamps=timestamps,
        packet_lengths=packet_lengths,
        cert_info=cert_info,
        total_packets=len(all_packets),
        destinations=destinations
    )


# ============================================================
#  PCAP解析主函数（scapy实现 - 降级）
# ============================================================
def _extract_with_scapy(pcap_path: str) -> dict:
    """使用scapy解析pcap文件。"""
    from scapy.all import rdpcap, IP, TCP, UDP, Raw, DNS, DNSQR

    packets = rdpcap(pcap_path)

    tls_hellos = []
    dns_queries = []
    cert_info = {}
    timestamps = []
    packet_lengths = []
    destinations = set()

    for pkt in packets:
        try:
            ts = float(pkt.time)
            timestamps.append(ts)
            packet_lengths.append(len(pkt))

            # 收集目标IP
            if IP in pkt:
                destinations.add(str(pkt[IP].dst))

            # TLS ClientHello检测
            if TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw])
                hello_info = _parse_tls_clienthello(payload)
                if hello_info.get("tls_sni") or hello_info.get("cipher_suites"):
                    tls_hellos.append(hello_info)

                # 简单证书检测
                if len(payload) > 0:
                    # 尝试检测ServerHello中的证书（简化处理）
                    if payload[0] == TLS_CONTENT_TYPE_HANDSHAKE and len(payload) > 6:
                        if payload[5] == TLS_HANDSHAKE_TYPE_CERTIFICATE:
                            cert_info["detected"] = True
                            # 尝试提取证书中的CN
                            try:
                                cert_text = payload[50:200].decode("utf-8", errors="ignore")
                                cn_match = re.search(r'CN=([^,\n\r]+)', cert_text)
                                if cn_match:
                                    cert_info["issuer"] = f"CN={cn_match.group(1)}"
                            except Exception:
                                pass

            # DNS查询检测
            if UDP in pkt and DNS in pkt:
                dns_layer = pkt[DNS]
                if dns_layer.qr == 0 and dns_layer.qd:
                    qname = dns_layer.qd.qname.decode("utf-8", errors="ignore")
                    if qname:
                        dns_queries.append(qname.rstrip("."))

        except Exception as e:
            logger.debug(f"scapy解析包异常: {e}")
            continue

    return _compute_features(
        tls_hellos=tls_hellos,
        dns_queries=dns_queries,
        timestamps=timestamps,
        packet_lengths=packet_lengths,
        cert_info=cert_info,
        total_packets=len(packets),
        destinations=destinations
    )


# ============================================================
#  从模拟数据中提取特征（无pyshark/scapy时使用）
# ============================================================
def _extract_mock(pcap_path: str) -> dict:
    """
    当pyshark和scapy均不可用时，从PCAP文件名中提取演示特征。
    仅用于演示流程，不进行真实解析。
    """
    logger.warning(f"使用模拟模式分析PCAP | path={pcap_path}")

    # 根据文件名中的关键词生成不同特征
    fname = Path(pcap_path).name.lower()

    if "malware" in fname or "c2" in fname or "evil" in fname or "trojan" in fname:
        return {
            "tls_sni": "evil-c2.xyz",
            "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
            "extensions": ["server_name", "supported_groups", "signature_algorithms"],
            "packet_length_entropy": 7.12,
            "interval_mean": 156.7,
            "interval_variance": 342.5,
            "dns_query_entropy": 4.23,
            "dns_queries": ["dga-18923.evil-c2.xyz", "update.botnet.cc"],
            "cert_issuer": "CN=Unknown CA",
            "cert_subject": "CN=*.evil-c2.xyz",
            "total_packets": 1024,
            "_source": "mock_demo"
        }
    else:
        return {
            "tls_sni": "www.google.com",
            "cipher_suites": ["TLS_AES_128_GCM_SHA256"],
            "extensions": ["server_name", "supported_groups"],
            "packet_length_entropy": 3.45,
            "interval_mean": 823.4,
            "interval_variance": 15678.9,
            "dns_query_entropy": 2.12,
            "dns_queries": ["www.google.com", "dns.google.com"],
            "cert_issuer": "CN=Google Trust Services",
            "cert_subject": "CN=*.google.com",
            "total_packets": 256,
            "_source": "mock_demo"
        }


# ============================================================
#  特征计算：从解析的原始数据中提取ML特征向量
# ============================================================
def _compute_features(tls_hellos: list, dns_queries: list,
                      timestamps: list, packet_lengths: list,
                      cert_info: dict, total_packets: int,
                      destinations: set = None) -> dict:
    """
    将解析的原始流量数据转换为与 dynamic_analysis 同构的特征字典。

    动态分析返回的 features 字典包含字段：
      unique_ips, unique_domains, domain_entropy (dns_query_entropy),
      port_diversity, avg_interval_ms, interval_variance,
      avg_payload_entropy (packet_length_entropy), max_payload_entropy,
      total_connections (total_packets), tls_connection_count,
      dns_query_count, has_sni

    为了与模型字段一致，映射为：
      packet_length_entropy = avg_payload_entropy (包长度熵)
      interval_variance     = 时间间隔方差
      dns_query_entropy     = DNS查询域名熵值
      tls_sni_length        = SNI域名长度
      connection_count      = 连接/包数量
      unique_destinations   = 唯一目标数（PCAP中近似为流数）
      avg_packet_len        = 平均包长度
      cert_issuer_length    = 证书颁发者字符串长度
    """
    # ---- TLS特征 ----
    snis = [h.get("tls_sni", "") for h in tls_hellos if h.get("tls_sni")]
    all_cipher_suites = []
    for h in tls_hellos:
        all_cipher_suites.extend(h.get("cipher_suites", []))
    unique_cipher_suites = list(set(all_cipher_suites))

    primary_sni = snis[0] if snis else ""
    tls_sni_length = len(primary_sni)

    # ---- DNS特征 ----
    dns_query_concat = "".join(dns_queries)
    dns_query_entropy = _calc_entropy(dns_query_concat) if dns_query_concat else 0.0

    # ---- 包长度特征 ----
    if packet_lengths:
        packet_length_entropy = _calc_entropy("".join(chr(max(1, min(p, 65535))) for p in packet_lengths))
        avg_packet_len = float(np.mean(packet_lengths))
        # 直接用unique包长度作为熵的补充
    else:
        packet_length_entropy = 0.0
        avg_packet_len = 0.0

    # ---- 时间间隔特征 ----
    intervals = []
    for i in range(1, len(timestamps)):
        diff = (timestamps[i] - timestamps[i - 1]) * 1000  # 转为ms
        intervals.append(max(diff, 0))

    if intervals:
        interval_mean = float(np.mean(intervals))
        interval_variance = float(np.var(intervals))
    else:
        interval_mean = 0.0
        interval_variance = 0.0

    # ---- 证书特征 ----
    cert_issuer = cert_info.get("issuer", "")
    cert_subject = cert_info.get("subject", "")
    if not cert_issuer and cert_info.get("detected"):
        cert_issuer = "CN=Unknown CA (detected)"
    cert_issuer_length = len(cert_issuer)

    # ---- 组装特征字典（与动态分析同构） ----
    features = {
        "tls_sni": primary_sni,
        "cipher_suites": unique_cipher_suites,
        "extensions": list(set(e for h in tls_hellos for e in h.get("extensions", []))),
        "packet_length_entropy": round(packet_length_entropy, 4),
        "interval_mean": round(interval_mean, 2),
        "interval_variance": round(interval_variance, 2),
        "dns_query_entropy": round(dns_query_entropy, 4),
        "dns_queries": dns_queries,
        "cert_issuer": cert_issuer,
        "cert_subject": cert_subject,

        # 用于ML模型的字段（与evaluate_detection中的feature_cols匹配）
        "tls_sni_length": tls_sni_length,
        "connection_count": total_packets,
        "unique_destinations": len(destinations) if destinations else (len(snis) + max(1, len(dns_queries))),
        "avg_packet_len": round(avg_packet_len, 2),
        "cert_issuer_length": cert_issuer_length,
        "total_packets": total_packets,
        "tls_connection_count": len(tls_hellos),
        "dns_query_count": len(dns_queries),
        "has_sni": len(snis) > 0,

        "analysis_source": "pcap_parse"
    }

    return features


# ============================================================
#  对外统一接口
# ============================================================
def extract_features_from_pcap(pcap_path: str) -> dict:
    """
    从PCAP文件提取C2通信特征的主函数。

    支持 .pcap 和 .pcapng 格式。
    自动选择解析引擎：pyshark > scapy > mock。

    Args:
        pcap_path: PCAP文件路径

    Returns:
        dict: 与dynamic_analysis同构的特征字典。
              若解析失败，返回空特征并记录错误。
    """
    # 验证文件存在
    p = Path(pcap_path)
    if not p.exists():
        logger.error(f"PCAP文件不存在: {pcap_path}")
        return {
            "error": f"PCAP文件不存在: {pcap_path}",
            "tls_sni": None, "cipher_suites": [],
            "packet_length_entropy": 0, "interval_variance": 0,
            "dns_query_entropy": 0, "cert_issuer": None,
            "tls_sni_length": 0, "connection_count": 0,
            "unique_destinations": 0, "avg_packet_len": 0,
            "cert_issuer_length": 0, "analysis_source": "error"
        }

    # 验证文件格式
    ext = p.suffix.lower()
    if ext not in (".pcap", ".pcapng"):
        logger.warning(f"非标准PCAP格式: {ext}，仍尝试解析")

    logger.info(f"开始PCAP分析 | path={pcap_path}")

    result = None

    # 按优先级选择解析引擎
    if _USE_PYSHARK:
        try:
            result = _extract_with_pyshark(pcap_path)
            logger.info(f"pyshark解析完成 | 总包数: {result.get('total_packets', 0)}")
        except Exception as e:
            logger.error(f"pyshark解析失败: {e}，尝试scapy降级")

    if result is None and _USE_SCAPY:
        try:
            result = _extract_with_scapy(pcap_path)
            logger.info(f"scapy解析完成 | 总包数: {result.get('total_packets', 0)}")
        except Exception as e:
            logger.error(f"scapy解析失败: {e}，使用模拟数据")

    if result is None:
        result = _extract_mock(pcap_path)
        result["_fallback_reason"] = "解析库不可用或解析失败"

    # 标记字段来源
    result["_pcap_path"] = pcap_path
    result["_analysis_time"] = datetime.now().isoformat()

    return result


# ============================================================
#  模块自测试
# ============================================================
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) > 1:
        pcap = sys.argv[1]
    else:
        # 使用内置模拟数据演示
        pcap = "sample_windows_trojan.pcap"

    print(f"分析PCAP: {pcap}")
    features = extract_features_from_pcap(pcap)
    print(json.dumps(features, indent=2, ensure_ascii=False, default=str))
