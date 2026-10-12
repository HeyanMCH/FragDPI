#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dns_leak_check — 检查你的域名会不会从 DNS 侧泄露出去（隐私模式的配套工具）

为什么需要它：
    FragDPI 的隐私模式能把 **TLS SNI** 藏起来，但它**管不到 DNS**。
    只要解析还是明文 UDP 53，链路上的设备照样能从 DNS 查询里读到
    「这台机器查了 zzz.mihoyo.com」—— SNI 藏得再好也是白搭。

    真实隐私 = 隐藏 SNI（本工具的分片）+ 加密 DNS（DoH / DoT）。

这个工具做什么：
    1. 列出当前系统在用的 DNS 服务器
    2. 实测 UDP 53 是否为明文直连，并打印「链路上的观察者能看到什么」
    3. 向多个解析器查同一域名，做一致性 / 污染检测
    4. 检测加密 DNS 逃生通道（DoT 853 / DoH 443）是否可用
    只读检测，**不改任何系统设置**。

用法：
    python tools/dns_leak_check.py
    python tools/dns_leak_check.py --json

纯标准库，无第三方依赖。
"""
import argparse
import ctypes
import ipaddress
import json
import os
import random
import socket
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    from core.fragcore import init_console
except ImportError:                                   # 允许直接 python tools/xxx.py
    sys.path.insert(0, os.path.join(ROOT, "core"))
    from fragcore import init_console

TIMEOUT = 4.0
# 做一致性检测用的解析器（公网、无日志偏好，仅作对照）
PUBLIC_RESOLVERS = ["223.5.5.5", "119.29.29.29", "114.114.114.114"]
# 已知 DoH 端点（JSON API，无需 POST 二进制）
DOH_ENDPOINTS = [
    ("阿里 DoH", "https://dns.alidns.com/resolve"),
    ("腾讯 DoH", "https://doh.pub/dns-query"),
]
DOT_ENDPOINTS = [("阿里 DoT", "223.5.5.5"), ("腾讯 DoT", "120.53.53.53")]
# 污染检测：域名 → (已知归属的 IP 前缀, 归属方)。答案落在网段外即为疑似污染。
# 依据是各家公开的 AS 段；只取最稳定的几个前缀，避免误报。
POLLUTION_PROBES = [
    ("www.google.com",
     ("142.250.", "172.217.", "216.58.", "74.125.", "108.177.", "209.85.",
      "64.233.", "173.194.", "172.253."), "Google"),
    ("www.facebook.com",
     ("157.240.", "31.13.", "179.60.", "129.134.", "163.70."), "Meta"),
    ("www.wikipedia.org",
     ("208.80.15", "198.35.26", "103.102.166"), "Wikimedia"),
]


# ------------------------------------------------------------------ 解析器枚举
class _IP_ADDR_STRING(ctypes.Structure):
    pass


_IP_ADDR_STRING._fields_ = [
    ("Next", ctypes.POINTER(_IP_ADDR_STRING)),
    ("IpAddress", ctypes.c_char * 16),
    ("IpMask", ctypes.c_char * 16),
    ("Context", ctypes.c_ulong),
]


class _FIXED_INFO(ctypes.Structure):
    _fields_ = [
        ("HostName", ctypes.c_char * 132),
        ("DomainName", ctypes.c_char * 132),
        ("CurrentDnsServer", ctypes.POINTER(_IP_ADDR_STRING)),
        ("DnsServerList", _IP_ADDR_STRING),
        ("NodeType", ctypes.c_uint),
        ("ScopeId", ctypes.c_char * 260),
        ("EnableRouting", ctypes.c_uint),
        ("EnableProxy", ctypes.c_uint),
        ("EnableDns", ctypes.c_uint),
    ]


def system_resolvers():
    """返回系统配置的 DNS 服务器列表。Windows 走 GetNetworkParams（与语言无关）。"""
    if os.name != "nt":
        out = []
        try:
            with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        out.append(line.split()[1])
        except OSError:
            pass
        return out
    try:
        buf = _FIXED_INFO()
        size = ctypes.c_ulong(ctypes.sizeof(buf))
        ret = ctypes.windll.iphlpapi.GetNetworkParams(ctypes.byref(buf), ctypes.byref(size))
        if ret != 0:
            return []
        out, node = [], ctypes.pointer(buf.DnsServerList)
        while node:
            ip = node.contents.IpAddress.decode("ascii", "replace").strip()
            if ip and ip not in out:
                out.append(ip)
            node = node.contents.Next
        return out
    except Exception:
        return []


# ------------------------------------------------------------------ DNS 报文
def build_query(qname, qtype=1):
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in qname.strip(".").split("."):
        q += bytes([len(label)]) + label.encode("ascii")
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return tid, header + q


def _skip_name(data, pos):
    while pos < len(data):
        n = data[pos]
        if n == 0:
            return pos + 1
        if n & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + n
    return pos


def parse_a_records(resp):
    """返回 (rcode, [IPv4 字符串])。只取 A 记录。"""
    if len(resp) < 12:
        return (None, [])
    _tid, flags, qd, an, _ns, _ar = struct.unpack_from(">HHHHHH", resp, 0)
    rcode = flags & 0x000F
    pos = 12
    for _ in range(qd):
        pos = _skip_name(resp, pos) + 4
    out = []
    for _ in range(an):
        pos = _skip_name(resp, pos)
        if pos + 10 > len(resp):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack_from(">HHIH", resp, pos)
        pos += 10
        if rtype == 1 and rdlen == 4:
            out.append(str(ipaddress.IPv4Address(resp[pos:pos + 4])))
        pos += rdlen
    return (rcode, out)


def udp_query(server, qname, timeout=TIMEOUT):
    """明文 UDP 53 查询。返回 dict。"""
    res = {"server": server, "qname": qname, "ok": False, "rcode": None,
           "answers": [], "ms": None, "error": None, "query_bytes": b""}
    tid, pkt = build_query(qname)
    res["query_bytes"] = pkt
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(4096)
        res["ms"] = round((time.perf_counter() - t0) * 1000)
        if len(data) >= 2 and struct.unpack_from(">H", data, 0)[0] != tid:
            res["error"] = "事务 ID 不匹配"
        else:
            res["rcode"], res["answers"] = parse_a_records(data)
            res["ok"] = res["rcode"] == 0
    except socket.timeout:
        res["error"] = "超时（无响应）"
    except OSError as e:
        res["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        s.close()
    if res["ms"] is None:
        res["ms"] = round((time.perf_counter() - t0) * 1000)
    return res


def tcp_connect(host, port, timeout=TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.connect((host, port))
        return round((time.perf_counter() - t0) * 1000)
    except OSError:
        return None
    finally:
        s.close()


def doh_query(url, qname, timeout=TIMEOUT):
    """DoH（JSON 格式）查询。显式禁代理，确保走的是直连。"""
    import urllib.request
    import urllib.parse
    import urllib.error
    full = url + "?" + urllib.parse.urlencode({"name": qname, "type": "A"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(full, headers={"accept": "application/dns-json"})
    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as r:
            body = json.loads(r.read().decode("utf-8"))
        ms = round((time.perf_counter() - t0) * 1000)
        ans = [a["data"] for a in body.get("Answer", []) if a.get("type") == 1]
        return {"ok": True, "ms": ms, "answers": ans, "error": None}
    except Exception as e:
        return {"ok": False, "ms": round((time.perf_counter() - t0) * 1000),
                "answers": [], "error": "%s: %s" % (type(e).__name__, e)}


# ------------------------------------------------------------------ 主流程
def hexdump(b, limit=64):
    b = b[:limit]
    return " ".join("%02x" % x for x in b) + (" ..." if len(b) == limit else "")


def check_probe_domain():
    """选一个能稳定解析、且属于大厂 CDN 的域名做对照。"""
    return "www.qq.com"


def quick_check(domain=None, timeout=3.0):
    """控制台用的紧凑版检测（不打印，返回结构化结果）。

    比 CLI 精简：每种逃生通道只测一个端点，污染只查主解析器，力求几秒内返回。
    """
    domain = domain or check_probe_domain()
    resolvers = system_resolvers()
    primary = resolvers[0] if resolvers else PUBLIC_RESOLVERS[0]

    plain = udp_query(primary, domain, timeout)
    dot = [{"name": n, "host": h, "ms": tcp_connect(h, 853, timeout)}
           for n, h in DOT_ENDPOINTS]
    doh = []
    for n, u in DOH_ENDPOINTS[:1]:
        r = doh_query(u, domain, timeout)
        doh.append({"name": n, "ok": r["ok"], "ms": r["ms"]})

    poisoned = []
    for dom, prefixes, _owner in POLLUTION_PROBES:
        r = udp_query(primary, dom, timeout)
        if r["ok"] and r["answers"] and any(
                not any(ip.startswith(p) for p in prefixes) for ip in r["answers"]):
            poisoned.append(dom)

    return {
        "domain": domain,
        "resolvers": resolvers,
        "resolver_is_local": bool(resolvers) and all(
            ipaddress.ip_address(i).is_private for i in resolvers),
        "plaintext_ok": bool(plain["ok"]),
        "plaintext_ms": plain["ms"],
        "dot": dot,
        "doh": doh,
        "encrypted_available": any(x["ms"] for x in dot) or any(x["ok"] for x in doh),
        "poisoned": poisoned,
    }


def main():
    init_console()
    ap = argparse.ArgumentParser(description="DNS 泄露自检（隐私模式配套）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--domain", default=None, help="用于测试的域名")
    args = ap.parse_args()

    domain = args.domain or check_probe_domain()
    result = {"resolvers": [], "plaintext": {}, "consistency": {},
              "dot": [], "doh": [], "verdict": {}}

    if not args.json:
        print("=" * 68)
        print("  DNS 泄露自检  ·  FragDPI 隐私模式配套")
        print("=" * 68)
        print("  隐私模式藏的是 TLS SNI；DNS 是另一条泄露通道，本工具专查这条。")
        print()

    # --- 1. 解析器
    resolvers = system_resolvers()
    result["resolvers"] = resolvers
    if not args.json:
        print("[1] 系统当前使用的 DNS 服务器")
        if resolvers:
            for ip in resolvers:
                tag = "  ← 内网地址（路由器/本地转发）" if ipaddress.ip_address(ip).is_private else ""
                print("      %-16s%s" % (ip, tag))
        else:
            print("      （未能枚举到，可能权限不足）")
        print()

    # --- 2. 明文查询
    targets = list(dict.fromkeys(resolvers + PUBLIC_RESOLVERS))
    if not args.json:
        print("[2] 明文 UDP 53 查询测试  目标域名：%s" % domain)
    for srv in targets:
        r = udp_query(srv, domain)
        result["plaintext"][srv] = {
            "ok": r["ok"], "rcode": r["rcode"], "ms": r["ms"],
            "answers": r["answers"], "error": r["error"],
        }
        if not args.json:
            if r["ok"]:
                print("      %-16s  ✓ %4sms  %s" % (srv, r["ms"], ",".join(r["answers"]) or "(无 A 记录)"))
            else:
                print("      %-16s  ✗ %4sms  %s" % (srv, r["ms"], r["error"]))
    if not args.json:
        _tid, qbytes = build_query(domain)
        print()
        print("      ⚠ 链路上的观察者能直接看到（这就是泄露本身）：")
        print("        查询域名 : %s" % domain)
        print("        原始字节 : %s" % hexdump(qbytes))
        print()

    # --- 3. 污染检测（按已知归属网段判定，避免把 CDN 的 geo-DNS 误报成污染）
    if not args.json:
        print("[3] 污染检测（答案是否落在该域名的已知归属网段）")
    primary = resolvers[0] if resolvers else (PUBLIC_RESOLVERS[0])
    result["poisoning"] = {}
    for dom, prefixes, owner in POLLUTION_PROBES:
        r = udp_query(primary, dom)
        if r["ok"] and r["answers"]:
            bad = [ip for ip in r["answers"]
                   if not any(ip.startswith(p) for p in prefixes)]
            result["poisoning"][dom] = {"resolver": primary, "answers": r["answers"],
                                        "suspicious": bad}
            if not args.json:
                if bad:
                    print("      ⚠ %-20s %-28s 不在 %s 网段 → 疑似污染：%s"
                          % (dom, ",".join(r["answers"]), owner, ",".join(bad)))
                else:
                    print("      ✓ %-20s %-28s 归属 %s" % (dom, ",".join(r["answers"]), owner))
        else:
            result["poisoning"][dom] = {"resolver": primary, "answers": [],
                                        "suspicious": [], "error": r["error"]}
            if not args.json:
                print("      – %-20s %s" % (dom, r["error"] or "无答案（可能被屏蔽，属正常）"))
    if not args.json:
        print("      （查不通不等于被污染 —— 被屏蔽的域名解析不到是正常的）")
        print()

    # --- 4. 多解析器一致性（仅作参考）
    if not args.json:
        print("[4] 多解析器答案对比（仅供参考：CDN 域名答案不同是**正常**的）")
    answers = {}
    for srv, info in result["plaintext"].items():
        if info["ok"] and info["answers"]:
            answers[srv] = tuple(sorted(info["answers"]))
    dist = sorted(set(answers.values()))
    result["consistency"] = {
        "consistent": len(dist) <= 1,
        "variants": [list(v) for v in dist],
        "responded": len(answers),
    }
    if not args.json:
        if not answers:
            print("      无解析器给出有效答案，跳过")
        elif len(dist) == 1:
            print("      · %d 个解析器给出同一组答案" % len(answers))
        else:
            print("      · 出现 %d 组不同答案（CDN 边缘节点不同，通常正常）：" % len(dist))
            for v in dist:
                who = [s for s, a in answers.items() if a == v]
                print("        %-40s ← %s" % (",".join(v), ", ".join(who)))
            print("        要判污染请看上面 [3]，不要看这里。")
        print()

    # --- 5. DoT
    if not args.json:
        print("[5] 加密 DNS 逃生通道 · DoT (TCP 853)")
    for name, host in DOT_ENDPOINTS:
        ms = tcp_connect(host, 853)
        result["dot"].append({"name": name, "host": host, "ms": ms})
        if not args.json:
            print("      %-10s %-16s %s" % (name, host,
                  ("✓ %sms" % ms) if ms else "✗ 不可达"))
    if not args.json:
        print()

    # --- 6. DoH
    if not args.json:
        print("[6] 加密 DNS 逃生通道 · DoH (HTTPS 443)")
    for name, url in DOH_ENDPOINTS:
        r = doh_query(url, domain)
        result["doh"].append({"name": name, "url": url, "ok": r["ok"],
                              "ms": r["ms"], "answers": r["answers"], "error": r["error"]})
        if not args.json:
            print("      %-10s %-32s %s" % (name, url,
                  ("✓ %sms  %s" % (r["ms"], ",".join(r["answers"]) or "(无 A)"))
                  if r["ok"] else ("✗ %s" % r["error"])))
    if not args.json:
        print()

    # --- 结论
    any_dot = any(x["ms"] for x in result["dot"])
    any_doh = any(x["ok"] for x in result["doh"])
    escape = any_dot or any_doh
    local_only = all(ipaddress.ip_address(i).is_private for i in resolvers) if resolvers else False
    poisoned = [d for d, v in result.get("poisoning", {}).items() if v.get("suspicious")]
    result["verdict"] = {
        "plaintext_dns": True,          # UDP 53 有响应即说明明文可用
        "encrypted_dns_available": bool(escape),
        "dot": bool(any_dot),
        "doh": bool(any_doh),
        "resolver_is_local": bool(local_only),
        "poisoned_domains": poisoned,
    }
    if not args.json:
        print("-" * 68)
        print("  结论")
        print("-" * 68)
        if escape:
            print("  ⚠ 你的 DNS 仍是明文：链路上的设备能看到你查询的每一个域名。")
            print("    好消息：加密 DNS 通道可用（%s）。" %
                  " / ".join([x for x in ("DoT" if any_dot else "", "DoH" if any_doh else "") if x]))
            print("    建议：把系统 DNS 或浏览器安全 DNS 指向上面可达的 DoH/DoT 端点。")
        else:
            print("  ✗ 你的 DNS 是明文，且没有可用的加密 DNS 通道。")
            print("    此时隐私模式只能藏住 SNI —— 域名照样从 DNS 泄露。")
        if local_only:
            print("  注意：当前解析器是内网地址（如路由器），你的查询会先明文送到它，")
            print("        再由它转发；这段链路上的设备同样能看到。")
        if poisoned:
            print("  ⚠ 检出疑似 DNS 污染：%s" % "、".join(poisoned))
            print("    污染靠加密 DNS 才能绕开（明文查询无论如何都会被改）。")
        print()
        print("  一句话：**隐私模式 + 加密 DNS 才是完整的隐私**；只开前者只有一半。")
        print()

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
