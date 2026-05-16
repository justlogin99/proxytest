#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxy_handler.py -- Parse PROXY_URL and generate Xray config.json.

保持原有接口不变：

  python proxy_handler.py --count
  python proxy_handler.py --index 0
  python proxy_handler.py

支持：
  - vless
  - vmess
  - trojan
  - socks5
  - http / https
  - shadowsocks / ss

说明：
  Xray 通常不原生支持 hysteria2 / tuic。
  如果 PROXY_URL 中有 hy2、hysteria2、tuic，会自动跳过。
"""

import os
import sys
import json
import base64
import re
import argparse
from urllib.parse import urlparse, parse_qs, unquote


LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8080


# ============================================================
# Utils
# ============================================================

def warn(msg):
    print(msg, file=sys.stderr)


def b64decode_with_padding(data):
    data = data.strip()
    data = data.replace("-", "+").replace("_", "/")
    pad = len(data) % 4
    if pad:
        data += "=" * (4 - pad)
    return base64.b64decode(data).decode("utf-8", errors="ignore")


def get_param(params, key, default=""):
    return params.get(key, [default])[0]


def split_alpn(value):
    if not value:
        return None
    return [x.strip() for x in value.split(",") if x.strip()]


def is_true(value):
    return str(value).lower() in ("1", "true", "yes")


def mask_addr(host, port):
    raw_addr = f"{host}:{port}"
    return re.sub(r'(\d+\.\d+\.\d+)\.\d+(:\d+)?', r'\1.*', raw_addr)


def normalize_network(net):
    """
    URL 中常见参数：
      type=tcp
      type=ws
      type=grpc
      type=http
      type=h2
      type=httpupgrade
      type=xhttp
      type=splithttp

    Xray streamSettings.network 常见：
      tcp, ws, grpc, h2, httpupgrade, xhttp, splithttp
    """
    net = (net or "tcp").lower()

    if net in ("tcp", "raw"):
        return "tcp"

    if net == "ws":
        return "ws"

    if net == "grpc":
        return "grpc"

    if net in ("http", "h2"):
        return "h2"

    if net in ("httpupgrade", "http-upgrade"):
        return "httpupgrade"

    # 新版 Xray 可能支持 xhttp/splithttp，保留映射。
    # 如果你的 Xray 版本不支持，会在启动时报错，升级 Xray 即可。
    if net in ("xhttp", "splithttp"):
        return net

    # kcp 较少用，但 Xray 支持。
    if net == "kcp":
        return "kcp"

    return "tcp"


def build_stream_settings(params, default_security="", default_network="tcp"):
    """
    根据 URL query 参数生成 Xray streamSettings。
    """
    raw_network = get_param(params, "type", default_network)
    network = normalize_network(raw_network)

    security = get_param(params, "security", default_security).lower()

    stream = {
        "network": network
    }

    # ---------------------------
    # TLS / Reality
    # ---------------------------
    if security == "tls":
        stream["security"] = "tls"

        tls_settings = {}

        sni = (
            get_param(params, "sni")
            or get_param(params, "serverName")
            or get_param(params, "peer")
        )
        if sni:
            tls_settings["serverName"] = sni

        fp = get_param(params, "fp")
        if fp:
            tls_settings["fingerprint"] = fp

        alpn = split_alpn(get_param(params, "alpn"))
        if alpn:
            tls_settings["alpn"] = alpn

        insecure = get_param(params, "insecure") or get_param(params, "allowInsecure")
        if is_true(insecure):
            tls_settings["allowInsecure"] = True

        stream["tlsSettings"] = tls_settings

    elif security == "reality":
        stream["security"] = "reality"

        reality_settings = {}

        sni = (
            get_param(params, "sni")
            or get_param(params, "serverName")
            or get_param(params, "peer")
        )
        if sni:
            reality_settings["serverName"] = sni

        fp = get_param(params, "fp")
        if fp:
            reality_settings["fingerprint"] = fp

        pbk = get_param(params, "pbk") or get_param(params, "publicKey")
        if pbk:
            reality_settings["publicKey"] = pbk

        sid = get_param(params, "sid") or get_param(params, "shortId")
        if sid:
            reality_settings["shortId"] = sid

        spx = get_param(params, "spx") or get_param(params, "spiderX")
        if spx:
            reality_settings["spiderX"] = unquote(spx)

        stream["realitySettings"] = reality_settings

    else:
        # none / 空 / 其他，默认不启用 TLS
        stream["security"] = "none"

    # ---------------------------
    # Transport Settings
    # ---------------------------
    if network == "ws":
        ws_settings = {}

        path = get_param(params, "path")
        if path:
            ws_settings["path"] = unquote(path)

        host = get_param(params, "host")
        if host:
            ws_settings["headers"] = {
                "Host": host
            }

        stream["wsSettings"] = ws_settings

    elif network == "grpc":
        grpc_settings = {}

        service_name = (
            get_param(params, "serviceName")
            or get_param(params, "service_name")
            or get_param(params, "path")
        )
        if service_name:
            grpc_settings["serviceName"] = unquote(service_name)

        mode = get_param(params, "mode")
        if mode:
            grpc_settings["multiMode"] = mode.lower() == "multi"

        stream["grpcSettings"] = grpc_settings

    elif network == "h2":
        h2_settings = {}

        path = get_param(params, "path")
        if path:
            h2_settings["path"] = unquote(path)

        host = get_param(params, "host")
        if host:
            h2_settings["host"] = [host]

        stream["httpSettings"] = h2_settings

    elif network == "httpupgrade":
        httpupgrade_settings = {}

        path = get_param(params, "path")
        if path:
            httpupgrade_settings["path"] = unquote(path)

        host = get_param(params, "host")
        if host:
            httpupgrade_settings["host"] = host

        stream["httpupgradeSettings"] = httpupgrade_settings

    elif network == "xhttp":
        xhttp_settings = {}

        path = get_param(params, "path")
        if path:
            xhttp_settings["path"] = unquote(path)

        host = get_param(params, "host")
        if host:
            xhttp_settings["host"] = host

        mode = get_param(params, "mode")
        if mode:
            xhttp_settings["mode"] = mode

        stream["xhttpSettings"] = xhttp_settings

    elif network == "splithttp":
        splithttp_settings = {}

        path = get_param(params, "path")
        if path:
            splithttp_settings["path"] = unquote(path)

        host = get_param(params, "host")
        if host:
            splithttp_settings["host"] = host

        mode = get_param(params, "mode")
        if mode:
            splithttp_settings["mode"] = mode

        stream["splithttpSettings"] = splithttp_settings

    return stream


# ============================================================
# Protocol Parsers for Xray Outbounds
# ============================================================

def parse_socks5(parsed):
    server = {
        "address": parsed.hostname,
        "port": parsed.port or 1080
    }

    if parsed.username:
        server["users"] = [{
            "user": unquote(parsed.username),
            "pass": unquote(parsed.password or "")
        }]

    return {
        "tag": "proxy",
        "protocol": "socks",
        "settings": {
            "servers": [server]
        }
    }


def parse_http(parsed):
    server = {
        "address": parsed.hostname,
        "port": parsed.port or 8080
    }

    if parsed.username:
        server["users"] = [{
            "user": unquote(parsed.username),
            "pass": unquote(parsed.password or "")
        }]

    outbound = {
        "tag": "proxy",
        "protocol": "http",
        "settings": {
            "servers": [server]
        }
    }

    # https://user:pass@host:port 形式的上游 HTTP 代理
    # Xray 可通过 streamSettings 对出站连接加 TLS。
    if parsed.scheme == "https":
        outbound["streamSettings"] = {
            "security": "tls",
            "tlsSettings": {
                "serverName": parsed.hostname
            }
        }

    return outbound


def parse_vless(parsed, params):
    uuid = unquote(parsed.username or "")

    user = {
        "id": uuid,
        "encryption": get_param(params, "encryption", "none") or "none"
    }

    flow = get_param(params, "flow")
    if flow:
        user["flow"] = flow

    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": parsed.hostname,
                    "port": parsed.port or 443,
                    "users": [user]
                }
            ]
        },
        "streamSettings": build_stream_settings(
            params,
            default_security=get_param(params, "security", ""),
            default_network=get_param(params, "type", "tcp")
        )
    }

    return outbound


def parse_trojan(parsed, params):
    password = unquote(parsed.username or "")

    server = {
        "address": parsed.hostname,
        "port": parsed.port or 443,
        "password": password
    }

    outbound = {
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {
            "servers": [server]
        },
        "streamSettings": build_stream_settings(
            params,
            default_security=get_param(params, "security", "tls") or "tls",
            default_network=get_param(params, "type", "tcp")
        )
    }

    return outbound


def parse_vmess(url_str):
    encoded = url_str[len("vmess://"):]
    decoded = b64decode_with_padding(encoded)
    cfg = json.loads(decoded)

    address = cfg.get("add", "")
    port = int(cfg.get("port", 443))
    uuid = cfg.get("id", "")
    alter_id = int(cfg.get("aid", 0))
    security_method = cfg.get("scy", "auto") or "auto"

    user = {
        "id": uuid,
        "alterId": alter_id,
        "security": security_method
    }

    outbound = {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [user]
                }
            ]
        }
    }

    # 将 vmess json 转为类似 URL params 的结构，复用 build_stream_settings
    params = {}

    net = cfg.get("net", "tcp") or "tcp"
    params["type"] = [net]

    tls = cfg.get("tls", "")
    if tls == "tls":
        params["security"] = ["tls"]
    else:
        params["security"] = ["none"]

    sni = cfg.get("sni", "") or cfg.get("host", "")
    if sni:
        params["sni"] = [sni]

    fp = cfg.get("fp", "")
    if fp:
        params["fp"] = [fp]

    alpn = cfg.get("alpn", "")
    if alpn:
        params["alpn"] = [alpn]

    path = cfg.get("path", "")
    if path:
        params["path"] = [path]

    host = cfg.get("host", "")
    if host:
        params["host"] = [host]

    outbound["streamSettings"] = build_stream_settings(
        params,
        default_security=params.get("security", ["none"])[0],
        default_network=net
    )

    return outbound


def parse_shadowsocks(url_str):
    """
    支持常见 ss:// 格式：

      ss://base64(method:password@host:port)#name
      ss://method:password@host:port#name
      ss://base64(method:password)@host:port#name

    不处理 SIP002 plugin。
    """
    raw = url_str[len("ss://"):]

    # 去掉 fragment
    if "#" in raw:
        raw = raw.split("#", 1)[0]

    # 去掉 query/plugin
    if "?" in raw:
        raw = raw.split("?", 1)[0]

    raw = unquote(raw)

    method = ""
    password = ""
    host = ""
    port = 0

    if "@" in raw:
        userinfo, serverinfo = raw.rsplit("@", 1)

        # userinfo 可能是 base64(method:password)
        if ":" not in userinfo:
            userinfo = b64decode_with_padding(userinfo)

        if ":" not in userinfo:
            raise ValueError("Invalid shadowsocks userinfo")

        method, password = userinfo.split(":", 1)

        if ":" not in serverinfo:
            raise ValueError("Invalid shadowsocks serverinfo")

        host, port_str = serverinfo.rsplit(":", 1)
        port = int(port_str)

    else:
        decoded = b64decode_with_padding(raw)

        if "@" not in decoded:
            raise ValueError("Invalid shadowsocks base64 content")

        userinfo, serverinfo = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
        host, port_str = serverinfo.rsplit(":", 1)
        port = int(port_str)

    return {
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": host,
                    "port": port,
                    "method": method,
                    "password": password
                }
            ]
        }
    }


# ============================================================
# Main Parse Logic
# ============================================================

def parse_all_urls():
    """
    解析所有节点，返回 Xray outbound 列表。
    """
    raw_url = os.environ.get("PROXY_URL", "").strip()

    if not raw_url:
        warn("PROXY_URL is empty, skipping.")
        return []

    url_list = re.split(r'[,\n]', raw_url)
    url_list = [u.strip() for u in url_list if u.strip()]

    outbounds = []

    for idx, proxy_url in enumerate(url_list):
        try:
            scheme = proxy_url.split("://", 1)[0].lower()

            if scheme == "vmess":
                outbound = parse_vmess(proxy_url)

            elif scheme in ("ss", "shadowsocks"):
                outbound = parse_shadowsocks(proxy_url)

            elif scheme in ("hy2", "hysteria2", "tuic"):
                warn(f"⚠️ Xray 通常不原生支持 {scheme}，已跳过第 {idx + 1} 个节点")
                continue

            else:
                parsed = urlparse(proxy_url)
                params = parse_qs(parsed.query, keep_blank_values=True)

                if scheme == "socks5":
                    outbound = parse_socks5(parsed)

                elif scheme in ("http", "https"):
                    outbound = parse_http(parsed)

                elif scheme == "vless":
                    outbound = parse_vless(parsed, params)

                elif scheme == "trojan":
                    outbound = parse_trojan(parsed, params)

                else:
                    warn(f"⚠️ 忽略不支持的协议: {scheme}")
                    continue

            # 为列表展示保留唯一 tag，真正生成 config 时会改回 proxy
            outbound["tag"] = f"proxy-{len(outbounds)}"
            outbounds.append(outbound)

        except Exception as e:
            warn(f"⚠️ 解析第 {idx + 1} 个节点失败: {e}")

    return outbounds


def generate_config(target_index, outbounds):
    """
    根据索引生成 Xray 单节点配置。
    """
    if target_index < 0 or target_index >= len(outbounds):
        return False

    selected = json.loads(json.dumps(outbounds[target_index]))
    selected_old_tag = selected.get("tag", f"proxy-{target_index}")
    selected["tag"] = "proxy"

    config = {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "tag": "http-in",
                "listen": LISTEN_HOST,
                "port": LISTEN_PORT,
                "protocol": "http",
                "settings": {
                    "timeout": 300,
                    "allowTransparent": False
                }
            }
        ],
        "outbounds": [
            selected,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {}
            }
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [
                        "http-in"
                    ],
                    "outboundTag": "proxy"
                }
            ]
        }
    }

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print(f"✅ 已生成节点 {selected_old_tag} 的 Xray 专属配置")
    return True


def get_outbound_server_info(ob):
    """
    用于默认打印节点摘要。
    """
    protocol = ob.get("protocol", "unknown")

    try:
        if protocol in ("vless", "vmess"):
            vnext = ob["settings"]["vnext"][0]
            return vnext["address"], vnext["port"]

        if protocol in ("trojan", "socks", "http", "shadowsocks"):
            server = ob["settings"]["servers"][0]
            return server["address"], server["port"]

    except Exception:
        pass

    return "unknown", 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", type=int, default=-1, help="Specify node index to generate single Xray config")
    parser.add_argument("--count", action="store_true", help="Only return total node count")
    args = parser.parse_args()

    all_outbounds = parse_all_urls()

    if args.count:
        print(len(all_outbounds))
        sys.exit(0)

    if not all_outbounds:
        print("❌ 没有成功解析出任何 Xray 可用节点！")
        sys.exit(1)

    if args.index >= 0:
        if not generate_config(args.index, all_outbounds):
            print(f"❌ 索引 {args.index} 超出节点范围")
            sys.exit(1)
    else:
        print(f"✅ 成功解析 {len(all_outbounds)} 个 Xray 可用节点")
        for idx, ob in enumerate(all_outbounds):
            host, port = get_outbound_server_info(ob)
            masked_addr = mask_addr(host, port)
            print(f"  [{idx}] {ob['tag']} ({ob.get('protocol', 'unknown')}) -> {masked_addr}")
