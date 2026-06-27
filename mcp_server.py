#!/usr/bin/env python3
"""
MobC2Inspector MCP Server
=========================
基于stdio JSON-RPC模式的MCP Server，将恶意C2通信检测分析能力以工具形式暴露。
LLM可通过MCP协议调度以下6个分析工具：

  1. list_samples       - 列出可用样本
  2. static_analysis    - 静态SO密钥与TLS指纹提取
  3. dynamic_analysis   - 动态Hook网络行为（支持隐蔽对抗）
  4. traffic_capture    - 后台抓包（tcpdump / Frida降级）
  5. evaluate_detection - ML模型评估检测指标
  6. generate_report    - 综合报告生成

MCP协议为胶水层，核心分析逻辑委托给 AnalysisEngine 类。

运行方式：
  python mcp_server.py          # 启动JSON-RPC stdio Server
  python mcp_server.py --tool list_samples  # 单次执行
  python mcp_server.py --test    # 自测试模式

依赖：
  - mcp 库（pip install mcp）
  - 或使用内置的简易JSON-RPC实现（无需额外安装）

"""

import os
import sys
import json
import logging
import argparse
import traceback
import numpy as np
from datetime import datetime
from pathlib import Path

# 将项目根目录加入Python路径
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine.engine import AnalysisEngine

# ============================================================
# 日志配置
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(PROJECT_ROOT / "logs" / "mcp_server.log", encoding="utf-8")
    ]
)
logger = logging.getLogger("MobC2MCP")


# ============================================================
# 简易JSON-RPC实现（避免额外依赖）
# ============================================================
class NumpyEncoder(json.JSONEncoder):
    """处理numpy类型的JSON编码器。"""
    def default(self, obj):
        if isinstance(obj, (np.integer,)):
            return int(obj)
        elif isinstance(obj, (np.floating,)):
            return float(obj)
        elif isinstance(obj, (np.ndarray,)):
            return obj.tolist()
        elif isinstance(obj, (np.bool_,)):
            return bool(obj)
        return super().default(obj)


class JSONRPCError(Exception):
    """JSON-RPC 协议错误。"""
    def __init__(self, code: int, message: str, data=None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"[{code}] {message}")


# JSON-RPC标准错误码
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class MCPHandler:
    """
    MCP请求处理器。
    使用简易JSON-RPC 2.0实现，通过stdin/stdout与LLM通信。
    """

    def __init__(self, engine: AnalysisEngine):
        self.engine = engine

        # 工具注册表：名称 -> (处理函数, 参数schema)
        self._tools = {
            "list_samples": (
                self._handle_list_samples,
                {
                    "type": "object",
                    "properties": {},
                    "description": "列出所有可用的恶意样本列表"
                }
            ),
            "static_analysis": (
                self._handle_static_analysis,
                {
                    "type": "object",
                    "properties": {
                        "apk_id": {
                            "type": "string",
                            "description": "样本标识符，如 sample_001"
                        }
                    },
                    "required": ["apk_id"],
                    "description": "对目标APK执行静态分析，提取SO层密钥和TLS ClientHello指纹"
                }
            ),
            "dynamic_analysis": (
                self._handle_dynamic_analysis,
                {
                    "type": "object",
                    "properties": {
                        "apk_id": {
                            "type": "string",
                            "description": "样本标识符"
                        },
                        "bypass_evasion": {
                            "type": "boolean",
                            "description": "是否启用隐蔽对抗预处理（反Frida检测、反沙箱）",
                            "default": True
                        },
                        "attach": {
                            "type": "boolean",
                            "description": "是否使用 attach 模式附加已运行的进程（默认 false 使用 spawn 模式）",
                            "default": False
                        },
                        "process_name": {
                            "type": "string",
                            "description": "目标进程名，覆盖默认从 APK 提取的包名（attach 模式定位进程，spawn 模式指定 -f 参数）",
                            "default": None
                        }
                    },
                    "required": ["apk_id"],
                    "description": "动态Hook目标App网络行为，采集C2通信特征。支持反检测绕过。"
                }
            ),
            "traffic_capture": (
                self._handle_traffic_capture,
                {
                    "type": "object",
                    "properties": {
                        "apk_id": {
                            "type": "string",
                            "description": "样本标识符"
                        },
                        "duration_sec": {
                            "type": "integer",
                            "description": "抓包持续时间（秒）",
                            "default": 60
                        }
                    },
                    "required": ["apk_id"],
                    "description": "在设备后台执行网络抓包。优先ADB tcpdump，降级Frida内存抓取。"
                }
            ),
            "analyze_pcap": (
                self._handle_analyze_pcap,
                {
                    "type": "object",
                    "properties": {
                        "pcap_path": {
                            "type": "string",
                            "description": "PCAP/PCAPNG文件路径（Windows EXE木马抓包）"
                        },
                        "label": {
                            "type": "integer",
                            "description": "可选，真实标签（0=正常, 1=恶意），提供后将追加到扩展数据集"
                        }
                    },
                    "required": ["pcap_path"],
                    "description": "分析Windows EXE木马等非Android平台的PCAP流量文件，提取C2特征并用模型预测"
                }
            ),
            "evaluate_detection": (
                self._handle_evaluate_detection,
                {
                    "type": "object",
                    "properties": {
                        "ground_truth_csv": {
                            "type": "string",
                            "description": "真实标签特征CSV路径",
                            "default": "data/sample_features.csv"
                        },
                        "pcap_list": {
                            "type": "array",
                            "description": "可选，PCAP文件列表用于合并评估",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "pcap_path": {"type": "string"},
                                    "label": {"type": "integer"}
                                }
                            }
                        }
                    },
                    "description": "评估C2检测模型的量化指标（准确率、召回率、F1、AUC、误报率等），支持合并PCAP特征"
                }
            ),
            "generate_report": (
                self._handle_generate_report,
                {
                    "type": "object",
                    "properties": {
                        "target_id": {
                            "type": "string",
                            "description": "目标标识符，可为APK_ID（如 sample_001）或PCAP文件路径（如 capture.pcap）"
                        },
                        "attach": {
                            "type": "boolean",
                            "description": "是否使用 attach 模式（App已在运行）进行动态分析",
                            "default": False
                        },
                        "process_name": {
                            "type": "string",
                            "description": "目标进程名，attach 模式下覆盖默认包名",
                            "default": None
                        }
                    },
                    "required": ["target_id"],
                    "description": "生成分析报告。自动识别目标类型：APK_ID生成Android分析报告（支持attach模式），.pcap路径生成PCAP流量分析报告"
                }
            )
        }

    # ----------------------------------------------------------
    #  工具处理函数
    # ----------------------------------------------------------
    def _handle_list_samples(self, params: dict) -> list:
        """处理 list_samples 请求。"""
        try:
            return self.engine.list_samples()
        except Exception as e:
            logger.error(f"list_samples失败: {e}")
            raise JSONRPCError(INTERNAL_ERROR, f"获取样本列表失败: {e}")

    def _handle_static_analysis(self, params: dict) -> dict:
        """处理 static_analysis 请求。"""
        apk_id = params.get("apk_id")
        if not apk_id:
            raise JSONRPCError(INVALID_PARAMS, "缺少必填参数: apk_id")
        try:
            return self.engine.static_analysis(apk_id)
        except Exception as e:
            logger.error(f"static_analysis失败: {e}")
            raise JSONRPCError(INTERNAL_ERROR, f"静态分析失败: {e}")

    def _handle_dynamic_analysis(self, params: dict) -> dict:
        """处理 dynamic_analysis 请求。"""
        apk_id = params.get("apk_id")
        if not apk_id:
            raise JSONRPCError(INVALID_PARAMS, "缺少必填参数: apk_id")
        bypass_evasion = params.get("bypass_evasion", True)
        attach = params.get("attach", False)
        process_name = params.get("process_name", None)
        try:
            return self.engine.dynamic_analysis(apk_id, bypass_evasion=bypass_evasion, attach=attach, process_name=process_name)
        except Exception as e:
            logger.error(f"dynamic_analysis失败: {e}")
            raise JSONRPCError(INTERNAL_ERROR, f"动态分析失败: {e}")

    def _handle_traffic_capture(self, params: dict) -> dict:
        """处理 traffic_capture 请求。"""
        apk_id = params.get("apk_id")
        if not apk_id:
            raise JSONRPCError(INVALID_PARAMS, "缺少必填参数: apk_id")
        duration_sec = params.get("duration_sec", 60)
        try:
            return self.engine.traffic_capture(apk_id, duration_sec=duration_sec)
        except Exception as e:
            logger.error(f"traffic_capture失败: {e}")
            raise JSONRPCError(INTERNAL_ERROR, f"流量捕获失败: {e}")

    def _handle_analyze_pcap(self, params: dict) -> dict:
        """处理 analyze_pcap 请求。"""
        pcap_path = params.get("pcap_path")
        if not pcap_path:
            raise JSONRPCError(INVALID_PARAMS, "缺少必填参数: pcap_path")
        label = params.get("label")
        try:
            return self.engine.analyze_pcap(pcap_path, label=label)
        except Exception as e:
            logger.error(f"analyze_pcap失败: {e}")
            raise JSONRPCError(INTERNAL_ERROR, f"PCAP分析失败: {e}")

    def _handle_evaluate_detection(self, params: dict) -> dict:
        """处理 evaluate_detection 请求。"""
        csv_path = params.get("ground_truth_csv")
        pcap_list = params.get("pcap_list")
        if pcap_list and not isinstance(pcap_list, list):
            raise JSONRPCError(INVALID_PARAMS, "pcap_list必须为列表")
        try:
            return self.engine.evaluate_detection(ground_truth_csv=csv_path, pcap_list=pcap_list)
        except Exception as e:
            logger.error(f"evaluate_detection失败: {e}")
            raise JSONRPCError(INTERNAL_ERROR, f"检测评估失败: {e}")

    def _handle_generate_report(self, params: dict) -> dict:
        """处理 generate_report 请求，自动识别目标类型。"""
        target_id = params.get("target_id")
        if not target_id:
            raise JSONRPCError(INVALID_PARAMS, "缺少必填参数: target_id（APK_ID或PCAP路径）")
        attach = params.get("attach", False)
        process_name = params.get("process_name", None)
        try:
            return self.engine.generate_report(target_id, attach=attach, process_name=process_name)
        except Exception as e:
            logger.error(f"generate_report失败: {e}")
            raise JSONRPCError(INTERNAL_ERROR, f"报告生成失败: {e}")

    # ----------------------------------------------------------
    #  JSON-RPC 协议处理
    # ----------------------------------------------------------
    def handle_request(self, request: dict) -> dict:
        """
        处理单条JSON-RPC请求，返回响应。

        Request format:
            {"jsonrpc": "2.0", "method": "tool_name", "params": {...}, "id": 1}
        Response format:
            {"jsonrpc": "2.0", "result": ..., "id": 1}
        Error format:
            {"jsonrpc": "2.0", "error": {"code": -32601, "message": "..."}, "id": 1}
        """
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        # 校验请求
        if request.get("jsonrpc") != "2.0":
            return self._error_response(PARSE_ERROR, "无效的JSON-RPC版本", req_id)
        if not method or not isinstance(method, str):
            return self._error_response(INVALID_REQUEST, "缺少method字段", req_id)

        # 查找工具
        if method not in self._tools:
            logger.warning(f"未知方法: {method}")
            return self._error_response(
                METHOD_NOT_FOUND, f"未知方法: {method}。可用方法: {list(self._tools.keys())}", req_id
            )

        handler, schema = self._tools[method]

        # 验证参数
        required = schema.get("required", [])
        for param_name in required:
            if param_name not in params:
                return self._error_response(
                    INVALID_PARAMS, f"缺少必填参数: {param_name}", req_id
                )

        # 执行
        try:
            logger.info(f"执行工具: {method} | params={json.dumps(params, ensure_ascii=False)}")
            result = handler(params)
            return self._success_response(result, req_id)
        except JSONRPCError as e:
            logger.error(f"工具执行错误 [{method}]: {e}")
            return self._error_response(e.code, e.message, req_id, e.data)
        except Exception as e:
            logger.error(f"工具执行异常 [{method}]: {traceback.format_exc()}")
            return self._error_response(INTERNAL_ERROR, f"内部错误: {e}", req_id)

    def _success_response(self, result, req_id):
        return {"jsonrpc": "2.0", "result": result, "id": req_id}

    def _error_response(self, code: int, message: str, req_id, data=None):
        err = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "error": err, "id": req_id}

    # ----------------------------------------------------------
    #  MCP协议扩展：工具列表查询
    # ----------------------------------------------------------
    def list_tools_schema(self) -> list:
        """返回所有工具的JSON Schema描述，供MCP协议发现使用。"""
        tools = []
        for name, (_, schema) in self._tools.items():
            tools.append({
                "name": name,
                "description": schema.get("description", ""),
                "inputSchema": {
                    "type": "object",
                    "properties": schema.get("properties", {}),
                    "required": schema.get("required", [])
                }
            })
        return tools

    def handle_mcp_request(self, request: dict) -> dict:
        """
        处理MCP协议请求（兼容MCP标准协议格式）。
        MCP使用JSON-RPC 2.0，但方法名为资源/工具模式。

        支持的MCP方法：
          - tools/list : 列出可用工具
          - tools/call : 调用工具
          - ping       : 心跳检测
        """
        method = request.get("method", "")

        # ----- MCP工具发现 -----
        if method == "tools/list":
            return self._success_response(
                {"tools": self.list_tools_schema()},
                request.get("id")
            )

        # ----- MCP工具调用 -----
        if method == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})

            if not tool_name:
                return self._error_response(
                    INVALID_PARAMS, "tools/call 缺少 name 参数", request.get("id")
                )

            # 将MCP调用转为内部JSON-RPC调用
            inner_request = {
                "jsonrpc": "2.0",
                "method": tool_name,
                "params": tool_args,
                "id": request.get("id")
            }
            response = self.handle_request(inner_request)

            # 转换错误格式
            if "error" in response:
                return response

            return self._success_response(
                {"content": [{"type": "text", "text": json.dumps(
                    response.get("result", {}), ensure_ascii=False, indent=2,
                    cls=NumpyEncoder
                )}]},
                request.get("id")
            )

        # ----- 心跳 -----
        if method == "ping":
            return self._success_response("pong", request.get("id"))

        # ----- 回退：当作普通JSON-RPC方法调用（兼容单工具调用模式） -----
        # 如果方法名匹配已注册的工具，直接调用
        if method in self._tools:
            return self.handle_request(request)

        # ----- 未知MCP方法 -----
        return self._error_response(
            METHOD_NOT_FOUND,
            f"未知MCP方法: {method}。支持: tools/list, tools/call, ping, {list(self._tools.keys())}",
            request.get("id")
        )


# ============================================================
#  MCP Server主循环（stdio模式）
# ============================================================
class MCPServer:
    """
    MCP Server运行器。
    通过stdin读取JSON-RPC请求，处理后通过stdout输出响应。
    支持MCP标准协议及简易JSON-RPC两种模式。
    """

    def __init__(self, engine: AnalysisEngine):
        self.handler = MCPHandler(engine)

    def run_stdio(self):
        """
        通过stdio持续监听JSON-RPC请求。
        每条请求为单行JSON，响应为单行JSON。
        """
        logger.info("MCP Server 启动 (stdio模式)")
        logger.info("等待JSON-RPC请求...")

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                request = json.loads(line)
            except json.JSONDecodeError as e:
                logger.error(f"JSON解析失败: {e}")
                error_resp = {
                    "jsonrpc": "2.0",
                    "error": {"code": PARSE_ERROR, "message": f"JSON解析错误: {e}"},
                    "id": None
                }
                sys.stdout.write(json.dumps(error_resp, ensure_ascii=False, cls=NumpyEncoder) + "\n")
                sys.stdout.flush()
                continue

            # 处理请求（兼容MCP标准协议）
            response = self.handler.handle_mcp_request(request)

            # 输出响应
            sys.stdout.write(json.dumps(response, ensure_ascii=False, cls=NumpyEncoder) + "\n")
            sys.stdout.flush()

        logger.info("MCP Server 关闭 (stdin关闭)")

    def run_single(self, tool_name: str, params: dict = None):
        """
        单次执行模式：直接调用指定工具并打印结果。
        适合命令行调试和演示。

        Args:
            tool_name: 工具名
            params: 参数字典
        """
        params = params or {}
        request = {
            "jsonrpc": "2.0",
            "method": tool_name,
            "params": params,
            "id": 1
        }
        response = self.handler.handle_request(request)
        print(json.dumps(response, ensure_ascii=False, indent=2, cls=NumpyEncoder))


# ============================================================
#  入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="MobC2Inspector - MCP Server for Android Malicious C2 Detection"
    )
    parser.add_argument("--tool", type=str, help="单次执行指定工具")
    parser.add_argument("--params", type=str, default="{}", help="工具参数JSON")
    parser.add_argument("--test", action="store_true", help="运行自测试")
    parser.add_argument("--demo", action="store_true", default=False,
                        help="以演示模式运行（无真实设备时不报错，默认关闭）")
    parser.add_argument("--adb", type=str, default="adb", help="ADB路径")
    parser.add_argument("--device", type=str, help="设备序列号")
    parser.add_argument("--frida-port", type=int, default=27042, help="Frida端口")

    args = parser.parse_args()

    # 初始化引擎
    engine = AnalysisEngine(
        adb_path=args.adb,
        device_serial=args.device,
        frida_port=args.frida_port,
        demo_mode=args.demo
    )

    server = MCPServer(engine)

    # ----- 自测试模式 -----
    if args.test:
        print("=" * 60)
        print("MobC2Inspector 自测试")
        print("=" * 60)

        test_cases = [
            ("list_samples", {}),
            ("static_analysis", {"apk_id": "sample_001"}),
            ("dynamic_analysis", {"apk_id": "sample_001", "bypass_evasion": True}),
            ("traffic_capture", {"apk_id": "sample_001", "duration_sec": 10}),
            ("analyze_pcap", {"pcap_path": "sample_windows_trojan.pcap", "label": 1}),
            ("evaluate_detection", {}),
            ("generate_report", {"target_id": "sample_001"}),
            ("generate_report", {"target_id": "sample_windows_trojan.pcap"}),
        ]

        for tool_name, params in test_cases:
            print(f"\n--- 测试工具: {tool_name} ---")
            request = {
                "jsonrpc": "2.0",
                "method": tool_name,
                "params": params,
                "id": 1
            }
            response = server.handler.handle_mcp_request(request)
            result = response.get("result", response.get("error", {}))
            output = json.dumps(result, ensure_ascii=False, indent=2, cls=NumpyEncoder)
            # 截断过长的输出
            if len(output) > 1000:
                print(output[:1000] + "\n... (截断)")
            else:
                print(output)

        print("\n" + "=" * 60)
        print("自测试完成!")
        print("=" * 60)
        return

    # ----- 单次执行模式 -----
    if args.tool:
        raw = args.params.strip()
        # 兼容各 shell 传入的包裹引号
        while len(raw) >= 2 and raw[0] in ("'", '"') and raw[0] == raw[-1]:
            raw = raw[1:-1]
        try:
            params = json.loads(raw)
        except json.JSONDecodeError:
            print(f"参数解析失败，原因：PowerShell 会剥离内层双引号")
            print(f"PowerShell 中请在 --params 前加 --% 停止转义：")
            print(f'  python mcp_server.py --tool {args.tool} --% --params "{raw}"')
            print(f"实际收到的参数: {args.params!r}")
            sys.exit(1)
        server.run_single(args.tool, params)
        return

    # ----- Stdio服务器模式 -----
    try:
        server.run_stdio()
    except KeyboardInterrupt:
        logger.info("收到中断信号，MCP Server关闭")
    except Exception as e:
        logger.error(f"MCP Server异常: {traceback.format_exc()}")
        sys.exit(1)


if __name__ == "__main__":
    main()
