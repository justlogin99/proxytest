#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xarytesting.py -- 批量测试 PROXY_URL 中的节点连通性
依赖 proxy_handler.py（需在同目录）和 xray 可执行文件。

用法：
  PROXY_URL="vless://..." python xarytesting.py
  或通过 GitHub Actions 环境变量传入。
"""

import os
import sys
import json
import time
import signal
import socket
import subprocess
import threading
import urllib.request
import urllib.error
from pathlib import Path

# 确保能 import proxy_handler
sys.path.insert(0, str(Path(__file__).parent))
import proxy_handler

# ============================================================
# 配置
# ============================================================

XRAY_BIN        = os.environ.get("XRAY_BIN", "./xray")   # xray 可执行文件路径
LISTEN_HOST     = "127.0.0.1"
LISTEN_PORT     = 8080                                     # 必须与 proxy_handler 一致
TEST_URL        = "https://www.google.com"                 # 测试目标
CONNECT_TIMEOUT = 10                                       # 秒
HTTP_TIMEOUT    = 15                                       # 秒
XRAY_BOOT_WAIT  = 2.0                                      # xray 启动等待秒数
CONFIG_FILE     = "config.json"


# ============================================================
# 辅助函数
# ============================================================

def mask_ip(host: str) -> str:
    """
    将 IP / 域名最后一段替换为 ***
    123.233.232.1   -> 123.233.232.***
    104.17.156.251  -> 104.17.156.***
    hf.188086.xyz   -> hf.188086.***
    """
    if not host:
        return "***"
    parts = host.rsplit(".", 1)
    if len(parts) == 2:
        return parts[0] + ".***"
    return host[:max(len(host)//2, 3)] + "***"


def mask_addr(host: str, port) -> str:
    return f"{mask_ip(host)}:{port}"


def get_server_addr(outbound: dict):
    protocol = outbound.get("protocol", "")
    try:
        if protocol in ("vless", "vmess"):
            v = outbound["settings"]["vnext"][0]
            return v["address"], v["port"]
        if protocol in ("trojan", "socks", "http", "shadowsocks"):
            s = outbound["settings"]["servers"][0]
            return s["address"], s["port"]
    except Exception:
        pass
    return "unknown", 0


def wait_for_port(host, port, timeout=5.0):
    """等待本地端口监听就绪"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def test_via_proxy(proxy_host, proxy_port, target_url, timeout) -> tuple[bool, str]:
    """
    通过 HTTP 代理发起请求，返回 (success, detail)
    """
    proxy_handler_obj = urllib.request.ProxyHandler({
        "http":  f"http://{proxy_host}:{proxy_port}",
        "https": f"http://{proxy_host}:{proxy_port}",
    })
    opener = urllib.request.build_opener(proxy_handler_obj)
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": "curl/7.88"})
        t0 = time.time()
        with opener.open(req, timeout=timeout) as resp:
            elapsed = time.time() - t0
            code = resp.getcode()
            return True, f"HTTP {code}  {elapsed:.2f}s"
    except urllib.error.HTTPError as e:
        return False, f"HTTP Error {e.code}"
    except urllib.error.URLError as e:
        return False, f"URLError: {e.reason}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# ============================================================
# 单节点测试
# ============================================================

def test_node(index: int, outbound: dict) -> dict:
    host, port = get_server_addr(outbound)
    protocol   = outbound.get("protocol", "unknown")
    masked     = mask_addr(host, port)
    tag        = outbound.get("tag", f"proxy-{index}")

    print(f"\n{'='*55}")
    print(f"[{index}] {protocol}  {masked}")
    print(f"{'='*55}")

    # 1. 生成 config.json
    proxy_handler.generate_config(index, [outbound])

    # 重写 tag 为 proxy（generate_config 会处理，但此处 outbound 列表只有1个）
    # 实际调用方式：让 generate_config 接受 target_index=0，outbounds=[outbound]
    # 已在上面调用，config.json 已写好

    # 2. 启动 xray
    xray_proc = None
    result = {"index": index, "protocol": protocol, "addr": masked, "success": False, "detail": ""}

    try:
        xray_proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", CONFIG_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # 3. 等待端口就绪
        ready = wait_for_port(LISTEN_HOST, LISTEN_PORT, timeout=XRAY_BOOT_WAIT + 3)
        if not ready:
            result["detail"] = "xray 启动超时，端口未就绪"
            print(f"  ❌ {result['detail']}")
            return result

        print(f"  ⚡ xray 已就绪，测试 {TEST_URL} ...")

        # 4. 测试连通性
        success, detail = test_via_proxy(LISTEN_HOST, LISTEN_PORT, TEST_URL, HTTP_TIMEOUT)
        result["success"] = success
        result["detail"]  = detail

        icon = "✅" if success else "❌"
        print(f"  {icon} {detail}")

    except FileNotFoundError:
        result["detail"] = f"找不到 xray 可执行文件: {XRAY_BIN}"
        print(f"  ❌ {result['detail']}")

    except Exception as e:
        result["detail"] = str(e)
        print(f"  ❌ 异常: {e}")

    finally:
        if xray_proc:
            xray_proc.terminate()
            try:
                xray_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                xray_proc.kill()
            # 等端口释放
            time.sleep(0.5)

    return result


# ============================================================
# 主流程
# ============================================================

def main():
    print("=" * 55)
    print("  Xray 节点连通性批量测试")
    print("=" * 55)

    # 解析所有节点
    all_outbounds = proxy_handler.parse_all_urls()

    if not all_outbounds:
        print("❌ 未解析出任何可用节点，请检查 PROXY_URL")
        sys.exit(1)

    total = len(all_outbounds)
    print(f"\n共解析到 {total} 个节点：\n")

    # 打印节点列表（半明文）
    for idx, ob in enumerate(all_outbounds):
        host, port = get_server_addr(ob)
        print(f"  [{idx}] {ob.get('protocol','?'):12s}  {mask_addr(host, port)}")

    print()

    # 逐个测试
    results = []
    for idx, ob in enumerate(all_outbounds):
        # generate_config 需要 index 在整个列表中，这里传单元素列表更简洁
        single = [json.loads(json.dumps(ob))]
        single[0]["tag"] = f"proxy-0"
        res = test_node_single(idx, ob)
        results.append(res)

    # 汇总
    print(f"\n{'='*55}")
    print("  测试结果汇总")
    print(f"{'='*55}")

    passed = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]

    for r in results:
        icon = "✅" if r["success"] else "❌"
        print(f"  {icon} [{r['index']}] {r['protocol']:12s} {r['addr']:30s} {r['detail']}")

    print(f"\n通过: {len(passed)} / {total}   失败: {len(failed)} / {total}")

    if failed:
        sys.exit(1)


def test_node_single(index: int, outbound: dict) -> dict:
    """
    包装：生成只含单节点的列表再调用 test_node
    """
    host, port = get_server_addr(outbound)
    protocol   = outbound.get("protocol", "unknown")
    masked     = mask_addr(host, port)

    print(f"\n{'='*55}")
    print(f"[{index}] {protocol}  {masked}")
    print(f"{'='*55}")

    # 构造单节点列表交给 generate_config
    single_list = [json.loads(json.dumps(outbound))]
    single_list[0]["tag"] = "proxy-0"
    proxy_handler.generate_config(0, single_list)

    xray_proc = None
    result = {
        "index":    index,
        "protocol": protocol,
        "addr":     masked,
        "success":  False,
        "detail":   ""
    }

    try:
        xray_proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", CONFIG_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        ready = wait_for_port(LISTEN_HOST, LISTEN_PORT, timeout=XRAY_BOOT_WAIT + 3)
        if not ready:
            # 打印 xray stderr 帮助排查
            stderr_out = ""
            if xray_proc.stderr:
                try:
                    stderr_out = xray_proc.stderr.read(2048).decode(errors="ignore")
                except Exception:
                    pass
            result["detail"] = f"xray 端口未就绪{(' | ' + stderr_out[:120]) if stderr_out else ''}"
            print(f"  ❌ {result['detail']}")
            return result

        print(f"  ⚡ xray 就绪，正在测试 {TEST_URL} ...")

        success, detail = test_via_proxy(LISTEN_HOST, LISTEN_PORT, TEST_URL, HTTP_TIMEOUT)
        result["success"] = success
        result["detail"]  = detail
        icon = "✅" if success else "❌"
        print(f"  {icon} {detail}")

    except FileNotFoundError:
        result["detail"] = f"找不到 xray: {XRAY_BIN}"
        print(f"  ❌ {result['detail']}")

    except Exception as e:
        result["detail"] = str(e)
        print(f"  ❌ {e}")

    finally:
        if xray_proc:
            xray_proc.terminate()
            try:
                xray_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                xray_proc.kill()
            time.sleep(0.5)

    return result


if __name__ == "__main__":
    main()
