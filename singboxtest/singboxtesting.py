#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
singboxtesting.py -- 批量测试 PROXY_URL 中的节点连通性

依赖：
  - proxy_handler.py，需要在同目录或当前脚本目录
  - sing-box 可执行文件

用法：
  PROXY_URL="vless://..." python singboxtesting.py

GitHub Actions 中通过 secrets.PROXY_URL 传入即可。
"""

import os
import sys
import json
import time
import socket
import subprocess
import urllib.request
import urllib.error
from pathlib import Path


# 确保能 import 同目录下的 proxy_handler.py
sys.path.insert(0, str(Path(__file__).parent))
import proxy_handler


# ============================================================
# 配置
# ============================================================

SING_BOX_BIN    = os.environ.get("SING_BOX_BIN", "./sing-box")
LISTEN_HOST     = "127.0.0.1"
LISTEN_PORT     = 8080
TEST_URL        = os.environ.get("TEST_URL", "https://www.google.com")
HTTP_TIMEOUT    = int(os.environ.get("HTTP_TIMEOUT", "15"))
BOOT_TIMEOUT    = float(os.environ.get("BOOT_TIMEOUT", "6"))
CONFIG_FILE     = "config.json"


# ============================================================
# 隐私打印
# ============================================================

def mask_host(host: str) -> str:
    """
    隐藏 IP / 域名的最后一段。

    104.17.143.214        -> 104.17.143.***
    1.2.3.4               -> 1.2.3.***
    app.stayurgent.qzz.io -> app.stayurgent.qzz.***
    base.188086.xyz       -> base.188086.***
    2606:4700::6812:3     -> 2606:4700:****
    """
    if not host:
        return "***"

    host = str(host)

    # IPv4
    if "." in host and all(part.isdigit() for part in host.split(".") if part):
        parts = host.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3]) + ".***"

    # IPv6
    if ":" in host:
        parts = host.split(":")
        visible = []
        for p in parts:
            if p:
                visible.append(p)
            if len(visible) >= 2:
                break
        if visible:
            return ":".join(visible) + ":****"
        return "****"

    # 域名
    if "." in host:
        parts = host.rsplit(".", 1)
        if len(parts) == 2:
            return parts[0] + ".***"

    # 兜底
    if len(host) <= 6:
        return "***"

    return host[: max(len(host) // 2, 3)] + "***"


def mask_addr(host: str, port) -> str:
    return f"{mask_host(host)}:{port}"


# ============================================================
# 节点信息提取
# ============================================================

def get_server_addr(outbound: dict):
    """
    sing-box outbound 通常字段：
      server
      server_port
      type
    """
    try:
        return outbound.get("server", "unknown"), outbound.get("server_port", 0)
    except Exception:
        return "unknown", 0


def get_protocol(outbound: dict) -> str:
    return outbound.get("type", "unknown")


# ============================================================
# 本地端口检测
# ============================================================

def wait_for_port(host, port, timeout=5.0):
    """
    等待 sing-box 本地 HTTP 入站端口监听就绪。
    """
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)

    return False


# ============================================================
# 通过 HTTP 代理测试
# ============================================================

def test_via_proxy(proxy_host, proxy_port, target_url, timeout) -> tuple[bool, str]:
    """
    通过本地 HTTP 代理访问目标 URL。
    返回：
      success, detail
    """
    proxy_handler_obj = urllib.request.ProxyHandler({
        "http":  f"http://{proxy_host}:{proxy_port}",
        "https": f"http://{proxy_host}:{proxy_port}",
    })

    opener = urllib.request.build_opener(proxy_handler_obj)

    try:
        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": "curl/7.88"
            }
        )

        t0 = time.time()

        with opener.open(req, timeout=timeout) as resp:
            elapsed = time.time() - t0
            code = resp.getcode()
            return True, f"HTTP {code}  {elapsed:.2f}s"

    except urllib.error.HTTPError as e:
        return False, f"HTTPError: {e.code}"

    except urllib.error.URLError as e:
        return False, f"URLError: {e.reason}"

    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# ============================================================
# sing-box 进程管理
# ============================================================

def terminate_process(proc: subprocess.Popen):
    if not proc:
        return

    try:
        proc.terminate()
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=3)
        except Exception:
            pass
    except Exception:
        pass


def read_process_output(proc: subprocess.Popen, limit=2000) -> str:
    """
    尽量读取 sing-box 输出，避免阻塞。
    只在进程已退出或被终止后调用。
    """
    if not proc:
        return ""

    out = ""
    err = ""

    try:
        stdout_data, stderr_data = proc.communicate(timeout=1)
        if stdout_data:
            out = stdout_data.decode(errors="ignore")
        if stderr_data:
            err = stderr_data.decode(errors="ignore")
    except Exception:
        pass

    text = (out + "\n" + err).strip()
    if len(text) > limit:
        text = text[:limit]

    return text


# ============================================================
# 单节点测试
# ============================================================

def test_node_single(index: int, outbound: dict) -> dict:
    """
    生成单节点 config.json，然后启动 sing-box 测试。
    """
    host, port = get_server_addr(outbound)
    protocol = get_protocol(outbound)
    masked = mask_addr(host, port)

    print(f"\n{'=' * 60}")
    print(f"[{index}] {protocol}  {masked}")
    print(f"{'=' * 60}")

    result = {
        "index": index,
        "protocol": protocol,
        "addr": masked,
        "success": False,
        "detail": ""
    }

    # 构造单节点列表，让 proxy_handler 生成 config.json
    single_list = [json.loads(json.dumps(outbound))]
    single_list[0]["tag"] = "proxy-0"

    try:
        proxy_handler.generate_config(0, single_list)
    except Exception as e:
        result["detail"] = f"生成 config.json 失败: {e}"
        print(f"  ❌ {result['detail']}")
        return result

    # 可选：检查配置
    try:
        check_proc = subprocess.run(
            [SING_BOX_BIN, "check", "-c", CONFIG_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )

        if check_proc.returncode != 0:
            output = (
                check_proc.stdout.decode(errors="ignore")
                + "\n"
                + check_proc.stderr.decode(errors="ignore")
            ).strip()
            result["detail"] = f"sing-box check 失败: {output[:300]}"
            print(f"  ❌ {result['detail']}")
            return result

    except FileNotFoundError:
        result["detail"] = f"找不到 sing-box 可执行文件: {SING_BOX_BIN}"
        print(f"  ❌ {result['detail']}")
        return result

    except subprocess.TimeoutExpired:
        result["detail"] = "sing-box check 超时"
        print(f"  ❌ {result['detail']}")
        return result

    except Exception as e:
        result["detail"] = f"sing-box check 异常: {e}"
        print(f"  ❌ {result['detail']}")
        return result

    sing_proc = None

    try:
        sing_proc = subprocess.Popen(
            [SING_BOX_BIN, "run", "-c", CONFIG_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        ready = wait_for_port(LISTEN_HOST, LISTEN_PORT, timeout=BOOT_TIMEOUT)

        if not ready:
            terminate_process(sing_proc)
            output = read_process_output(sing_proc, limit=1200)
            if output:
                result["detail"] = f"sing-box 端口未就绪 | {output[:500]}"
            else:
                result["detail"] = "sing-box 端口未就绪"
            print(f"  ❌ {result['detail']}")
            return result

        print(f"  ⚡ sing-box 就绪，正在测试 {TEST_URL} ...")

        success, detail = test_via_proxy(
            LISTEN_HOST,
            LISTEN_PORT,
            TEST_URL,
            HTTP_TIMEOUT
        )

        result["success"] = success
        result["detail"] = detail

        icon = "✅" if success else "❌"
        print(f"  {icon} {detail}")

    except FileNotFoundError:
        result["detail"] = f"找不到 sing-box: {SING_BOX_BIN}"
        print(f"  ❌ {result['detail']}")

    except Exception as e:
        result["detail"] = str(e)
        print(f"  ❌ 异常: {e}")

    finally:
        if sing_proc:
            terminate_process(sing_proc)
            time.sleep(0.5)

    return result


# ============================================================
# 主流程
# ============================================================

def main():
    print("=" * 60)
    print("  sing-box 节点连通性批量测试")
    print("=" * 60)

    print(f"sing-box bin : {SING_BOX_BIN}")
    print(f"test url     : {TEST_URL}")
    print(f"listen       : {LISTEN_HOST}:{LISTEN_PORT}")

    try:
        version_proc = subprocess.run(
            [SING_BOX_BIN, "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )

        version_text = (
            version_proc.stdout.decode(errors="ignore")
            + "\n"
            + version_proc.stderr.decode(errors="ignore")
        ).strip()

        if version_text:
            print("\n" + version_text.splitlines()[0])

    except Exception as e:
        print(f"\n⚠️ 获取 sing-box version 失败: {e}")

    # 解析所有节点
    all_outbounds = proxy_handler.parse_all_urls()

    if not all_outbounds:
        print("❌ 未解析出任何可用节点，请检查 PROXY_URL")
        sys.exit(1)

    total = len(all_outbounds)

    print(f"\n共解析到 {total} 个节点：\n")

    for idx, ob in enumerate(all_outbounds):
        host, port = get_server_addr(ob)
        protocol = get_protocol(ob)
        print(f"  [{idx}] {protocol:12s}  {mask_addr(host, port)}")

    print()

    # 逐个测试
    results = []

    for idx, ob in enumerate(all_outbounds):
        res = test_node_single(idx, ob)
        results.append(res)

    # 汇总
    print(f"\n{'=' * 60}")
    print("  测试结果汇总")
    print(f"{'=' * 60}")

    passed = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]

    for r in results:
        icon = "✅" if r["success"] else "❌"
        print(
            f"  {icon} "
            f"[{r['index']}] "
            f"{r['protocol']:12s} "
            f"{r['addr']:30s} "
            f"{r['detail']}"
        )

    print()
    print(f"通过: {len(passed)} / {total}   失败: {len(failed)} / {total}")

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
