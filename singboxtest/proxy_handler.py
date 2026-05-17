#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxy_handler.py -- Parse PROXY_URL and generate sing-box config.json.
Supports single-node mode via --index for retry loop.

支持：
  - vmess
  - vless
  - trojan
  - socks5
  - http / https
  - hysteria2 / hy2
  - tuic

说明：
  针对 Cloudflare / Argo / WS + TLS 场景做了兼容：
    - WS + TLS 默认 alpn = ["http/1.1"]
    - gRPC + TLS 默认 alpn = ["h2"]
    - TLS 默认启用 utls chrome
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
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def is_true(value):
    return str(value).lower() in ("1", "true", "yes", "y", "on")


def mask_addr(host, port):
    raw_addr = f"{host}:{port}"
    return re.sub(r'(\d+\.\d+\.\d+)\.\d+(:\d+)?', r'\1.*', raw_addr)


def normalize_net_type(net):
    net = (net or "tcp").lower()

    if net in ("tcp", "raw"):
        return "tcp"

    if net == "ws":
        return "ws"

    if net == "grpc":
        return "grpc"

    if net in ("http", "h2"):
        return "http"

    if net in ("httpupgrade", "http-upgrade"):
        return "httpupgrade"

    return net


def add_common_tls(
    outbound,
    security,
    net_type="tcp",
    sni="",
    host="",
    fp="",
    alpn="",
    insecure="",
    reality_params=None
):
    """
    给 sing-box outbound 添加通用 TLS / Reality 配置。

    Cloudflare / WS-TLS 兼容：
      - WS 自动 alpn http/1.1
      - gRPC 自动 alpn h2
      - 默认 utls chrome
    """
    security = (security or "").lower()
    net_type = normalize_net_type(net_type)

    if security not in ("tls", "reality"):
        return

    tls = {
        "enabled": True
    }

    server_name = sni or host
    if server_name:
        tls["server_name"] = server_name

    alpn_list = split_alpn(alpn)
    if alpn_list:
        tls["alpn"] = alpn_list
    else:
        if net_type == "ws":
            tls["alpn"] = ["http/1.1"]
        elif net_type == "grpc":
            tls["alpn"] = ["h2"]

    # Cloudflare 场景建议默认 chrome 指纹
    fingerprint = fp or "chrome"
    tls["utls"] = {
        "enabled": True,
        "fingerprint": fingerprint
    }

    if is_true(insecure):
        tls["insecure"] = True

    if security == "reality":
        reality = {
            "enabled": True
        }

        reality_params = reality_params or {}

        pbk = (
            reality_params.get("pbk", "")
            or reality_params.get("publicKey", "")
            or reality_params.get("public_key", "")
        )
        if pbk:
            reality["public_key"] = pbk

        sid = (
            reality_params.get("sid", "")
            or reality_params.get("shortId", "")
            or reality_params.get("short_id", "")
        )
        if sid:
            reality["short_id"] = sid

        tls["reality"] = reality

    outbound["tls"] = tls


def add_transport(outbound, net_type, path="", host="", service_name="", mode=""):
    """
    添加 sing-box transport。
    说明：
      这里默认保留 ?ed=2048 在 path 中，不拆 max_early_data。
      这样兼容性更稳，避免老版本 sing-box check 失败。
    """
    net_type = normalize_net_type(net_type)

    if net_type == "ws":
        transport = {
            "type": "ws"
        }

        if path:
            transport["path"] = unquote(path)

        if host:
            transport["headers"] = {
                "Host": host
            }

        outbound["transport"] = transport

    elif net_type == "grpc":
        transport = {
            "type": "grpc"
        }

        if service_name:
            transport["service_name"] = unquote(service_name)
        elif path:
            transport["service_name"] = unquote(path)

        if mode:
            transport["idle_timeout"] = "15s"

        outbound["transport"] = transport

    elif net_type == "http":
        transport = {
            "type": "http"
        }

        if path:
            transport["path"] = unquote(path)

        if host:
            transport["host"] = [host]

        outbound["transport"] = transport

    elif net_type == "httpupgrade":
        transport = {
            "type": "httpupgrade"
        }

        if path:
            transport["path"] = unquote(path)

        if host:
            transport["host"] = host

        outbound["transport"] = transport


# ============================================================
# Protocol Parsers
# ============================================================

def parse_socks5(parsed):
    outbound = {
        "type": "socks",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port or 1080,
        "version": "5"
    }

    if parsed.username:
        outbound["username"] = unquote(parsed.username)

    if parsed.password:
        outbound["password"] = unquote(parsed.password)

    return outbound


def parse_http(parsed):
    outbound = {
        "type": "http",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port or 8080
    }

    if parsed.username:
        outbound["username"] = unquote(parsed.username)

    if parsed.password:
        outbound["password"] = unquote(parsed.password)

    if parsed.scheme == "https":
        outbound["tls"] = {
            "enabled": True,
            "server_name": parsed.hostname,
            "utls": {
                "enabled": True,
                "fingerprint": "chrome"
            }
        }

    return outbound


def parse_vless(parsed, params):
    net_type = get_param(params, "type", "tcp")
    security = get_param(params, "security", "")

    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "uuid": unquote(parsed.username or "")
    }

    flow = get_param(params, "flow")
    if flow:
        outbound["flow"] = flow

    sni = (
        get_param(params, "sni")
        or get_param(params, "serverName")
        or get_param(params, "peer")
    )
    host = get_param(params, "host")
    fp = get_param(params, "fp")
    alpn = get_param(params, "alpn")
    insecure = get_param(params, "insecure") or get_param(params, "allowInsecure")

    reality_params = {
        "pbk": get_param(params, "pbk"),
        "publicKey": get_param(params, "publicKey"),
        "sid": get_param(params, "sid"),
        "shortId": get_param(params, "shortId")
    }

    add_common_tls(
        outbound=outbound,
        security=security,
        net_type=net_type,
        sni=sni,
        host=host,
        fp=fp,
        alpn=alpn,
        insecure=insecure,
        reality_params=reality_params
    )

    path = get_param(params, "path")
    service_name = (
        get_param(params, "serviceName")
        or get_param(params, "service_name")
        or path
    )
    mode = get_param(params, "mode")

    add_transport(
        outbound=outbound,
        net_type=net_type,
        path=path,
        host=host,
        service_name=service_name,
        mode=mode
    )

    return outbound


def parse_trojan(parsed, params):
    net_type = get_param(params, "type", "tcp")
    security = get_param(params, "security", "tls") or "tls"

    outbound = {
        "type": "trojan",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "password": unquote(parsed.username or "")
    }

    sni = (
        get_param(params, "sni")
        or get_param(params, "serverName")
        or get_param(params, "peer")
    )
    host = get_param(params, "host")
    fp = get_param(params, "fp")
    alpn = get_param(params, "alpn")
    insecure = get_param(params, "insecure") or get_param(params, "allowInsecure")

    add_common_tls(
        outbound=outbound,
        security=security,
        net_type=net_type,
        sni=sni,
        host=host,
        fp=fp,
        alpn=alpn,
        insecure=insecure
    )

    path = get_param(params, "path")
    service_name = (
        get_param(params, "serviceName")
        or get_param(params, "service_name")
        or path
    )
    mode = get_param(params, "mode")

    add_transport(
        outbound=outbound,
        net_type=net_type,
        path=path,
        host=host,
        service_name=service_name,
        mode=mode
    )

    return outbound


def parse_vmess(url_str):
    encoded = url_str[len("vmess://"):]
    decoded = b64decode_with_padding(encoded)
    cfg = json.loads(decoded)

    net_type = cfg.get("net", "tcp") or "tcp"
    tls_type = cfg.get("tls", "")
    security = "tls" if tls_type == "tls" else "none"

    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": cfg.get("add", ""),
        "server_port": int(cfg.get("port", 443)),
        "uuid": cfg.get("id", ""),
        "security": cfg.get("scy", "auto") or "auto",
        "alter_id": int(cfg.get("aid", 0))
    }

    sni = cfg.get("sni", "") or cfg.get("serverName", "")
    host = cfg.get("host", "")
    fp = cfg.get("fp", "")
    alpn = cfg.get("alpn", "")
    insecure = cfg.get("allowInsecure", "") or cfg.get("insecure", "")

    add_common_tls(
        outbound=outbound,
        security=security,
        net_type=net_type,
        sni=sni,
        host=host,
        fp=fp,
        alpn=alpn,
        insecure=insecure
    )

    path = cfg.get("path", "")
    service_name = cfg.get("serviceName", "") or cfg.get("service_name", "") or path
    mode = cfg.get("mode", "")

    add_transport(
        outbound=outbound,
        net_type=net_type,
        path=path,
        host=host,
        service_name=service_name,
        mode=mode
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

    if "#" in raw:
        raw = raw.split("#", 1)[0]

    if "?" in raw:
        raw = raw.split("?", 1)[0]

    raw = unquote(raw)

    method = ""
    password = ""
    host = ""
    port = 0

    if "@" in raw:
        userinfo, serverinfo = raw.rsplit("@", 1)

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
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password
    }


def parse_hysteria2(parsed, params):
    outbound = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "password": unquote(parsed.username or "")
    }

    tls = {
        "enabled": True
    }

    sni = get_param(params, "sni")
    if sni:
        tls["server_name"] = sni

    insecure = get_param(params, "insecure") or get_param(params, "allowInsecure")
    if is_true(insecure):
        tls["insecure"] = True

    alpn = get_param(params, "alpn")
    alpn_list = split_alpn(alpn)
    if alpn_list:
        tls["alpn"] = alpn_list

    fp = get_param(params, "fp")
    if fp:
        tls["utls"] = {
            "enabled": True,
            "fingerprint": fp
        }

    outbound["tls"] = tls

    obfs = get_param(params, "obfs")
    if obfs:
        obfs_pwd = get_param(params, "obfs-password") or get_param(params, "obfs_password")
        outbound["obfs"] = {
            "type": obfs,
            "password": obfs_pwd
        }

    return outbound


def parse_tuic(parsed, params):
    user_part = unquote(parsed.username or "")
    pass_part = unquote(parsed.password or "")

    uuid = ""
    password = ""

    if ":" in user_part and not pass_part:
        uuid, password = user_part.split(":", 1)
    else:
        uuid = user_part
        password = pass_part

    outbound = {
        "type": "tuic",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "uuid": uuid,
        "password": password,
        "congestion_control": get_param(params, "congestion_control", "bbr")
    }

    tls = {
        "enabled": True
    }

    sni = get_param(params, "sni")
    if sni:
        tls["server_name"] = sni

    insecure = get_param(params, "insecure") or get_param(params, "allowInsecure")
    if is_true(insecure):
        tls["insecure"] = True

    alpn = get_param(params, "alpn")
    alpn_list = split_alpn(alpn)
    if alpn_list:
        tls["alpn"] = alpn_list

    outbound["tls"] = tls

    return outbound


# ============================================================
# Main
# ============================================================

def parse_all_urls():
    """
    解析所有节点，返回 outbound 列表。
    """
    raw_url = os.environ.get("PROXY_URL", "").strip()

    if not raw_url:
        print("PROXY_URL is empty, skipping.")
        sys.exit(0)

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

                elif scheme in ("hy2", "hysteria2"):
                    outbound = parse_hysteria2(parsed, params)

                elif scheme == "tuic":
                    outbound = parse_tuic(parsed, params)

                else:
                    warn(f"⚠️ 忽略不支持的协议: {scheme}")
                    continue

            outbound["tag"] = f"proxy-{len(outbounds)}"
            outbounds.append(outbound)

        except Exception as e:
            warn(f"⚠️ 解析第 {idx + 1} 个节点失败: {e}")

    return outbounds


def generate_config(target_index, outbounds):
    """
    根据索引生成单节点 sing-box 配置。
    """
    if target_index < 0 or target_index >= len(outbounds):
        return False

    selected = json.loads(json.dumps(outbounds[target_index]))
    selected_old_tag = selected.get("tag", f"proxy-{target_index}")

    selected["tag"] = "proxy"

    config = {
        "log": {
            "level": "warn",
            "timestamp": True
        },
        "inbounds": [
            {
                "type": "http",
                "tag": "http-in",
                "listen": LISTEN_HOST,
                "listen_port": LISTEN_PORT
            }
        ],
        "outbounds": [
            selected,
            {
                "type": "direct",
                "tag": "direct"
            }
        ]
    }

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print(f"✅ 已生成节点 {selected_old_tag} 的 sing-box 专属配置")
    return True


def get_outbound_server_info(ob):
    return ob.get("server", "unknown"), ob.get("server_port", 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", type=int, default=-1, help="Specify node index to generate single config")
    parser.add_argument("--count", action="store_true", help="Only return total node count")
    args = parser.parse_args()

    all_outbounds = parse_all_urls()

    if args.count:
        print(len(all_outbounds))
        sys.exit(0)

    if not all_outbounds:
        print("❌ 没有成功解析出任何 sing-box 可用节点！")
        sys.exit(1)

    if args.index >= 0:
        if not generate_config(args.index, all_outbounds):
            print(f"❌ 索引 {args.index} 超出节点范围")
            sys.exit(1)
    else:
        print(f"✅ 成功解析 {len(all_outbounds)} 个 sing-box 可用节点")
        for idx, ob in enumerate(all_outbounds):
            host, port = get_outbound_server_info(ob)
            masked_addr = mask_addr(host, port)
            print(f"  [{idx}] {ob['tag']} ({ob.get('type', 'unknown')}) -> {masked_addr}")
