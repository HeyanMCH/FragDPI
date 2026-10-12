#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_fast — 快速对照实验：把「分片前」的瓶颈拆开定位。

分成四段独立测量，用来回答「慢到底是 DNS、TCP 建连、TLS 握手，还是走了代理」：

  1. DNS 解析（走系统解析器 = 本机网关）
  2. 直连 443 的 TCP 建连（不经 TLS）
  3. 直连 443 的完整 TLS 握手
  4. 通过本地代理 CONNECT 再 TLS（对照：游戏客户端**不会**走这条路）

用法：
    python probe_fast.py                         # 默认 zzz.mihoyo.com
    python probe_fast.py zzz.mihoyo.com          # 指定主机
    python probe_fast.py zzz.mihoyo.com 127.0.0.1:6483   # 额外指定本地代理

第 4 段是可选的：不传代理就跳过。结果同时写入
research/probe_fast_result.json。
"""
import json
import os
import socket
import ssl
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import out_path  # noqa: E402

DEFAULT_HOST = "zzz.mihoyo.com"


def stats(lst):
    lst = [x for x in lst if x is not None]
    if not lst:
        return {"n": 0, "fail": True}
    lst_s = sorted(lst)
    return {
        "n": len(lst),
        "min": round(min(lst), 1),
        "avg": round(statistics.mean(lst), 1),
        "max": round(max(lst), 1),
        "jitter": round(statistics.pstdev(lst), 1),
        "p95": (round(lst_s[int(len(lst_s) * 0.95) - 1], 1)
                if len(lst_s) >= 20 else round(lst_s[-1], 1)),
    }


def parse_proxy(s):
    if not s:
        return None
    host, _, port = s.rpartition(":")
    return (host or "127.0.0.1", int(port))


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    proxy = parse_proxy(sys.argv[2] if len(sys.argv) > 2 else None)
    result = {"host": host, "proxy": proxy}

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # ---- 1. DNS 解析（系统解析器 → 本机网关 / 路由器）
    dns_times, ips = [], set()
    for _ in range(8):
        t0 = time.perf_counter()
        try:
            for af in socket.getaddrinfo(host, 443, socket.AF_INET):
                ips.add(af[4][0])
            dns_times.append(round((time.perf_counter() - t0) * 1000, 1))
        except Exception:
            dns_times.append(None)
    result["dns"] = {"times": dns_times, "stats": stats(dns_times), "ips": sorted(ips)}
    ip = sorted(ips)[0] if ips else None
    result["resolved_ip"] = ip
    print(f"[1/4] DNS  解析到 {ip} 中位 "
          f"{stats(dns_times).get('avg', 'n/a')}ms", flush=True)

    # ---- 2. 直连 443 的 TCP 建连（不含 TLS）
    tcp_times = []
    if ip:
        for _ in range(15):
            s = socket.socket()
            s.settimeout(3)
            t0 = time.perf_counter()
            try:
                s.connect((ip, 443))
                tcp_times.append(round((time.perf_counter() - t0) * 1000, 1))
            except Exception:
                tcp_times.append(None)
            finally:
                s.close()
    result["tcp_direct_443"] = {"stats": stats(tcp_times), "times": tcp_times}
    print(f"[2/4] TCP  直连 443 平均 {stats(tcp_times).get('avg', 'n/a')}ms", flush=True)

    # ---- 3. 直连的完整 TLS 握手
    tls_times = []
    if ip:
        for _ in range(6):
            t0 = time.perf_counter()
            try:
                with socket.create_connection((ip, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        tls_times.append(round((time.perf_counter() - t0) * 1000, 1))
            except Exception:
                tls_times.append(None)
    result["tls_direct"] = {"stats": stats(tls_times), "times": tls_times}
    print(f"[3/4] TLS  直连握手平均 {stats(tls_times).get('avg', 'n/a')}ms", flush=True)

    # ---- 4. 走本地代理 CONNECT 的对照（可选）
    if proxy:
        proxy_times = []
        for _ in range(6):
            try:
                t0 = time.perf_counter()
                s = socket.create_connection(proxy, timeout=3)
                s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\n"
                          f"Host: {host}:443\r\n\r\n".encode())
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = s.recv(256)
                    if not chunk:
                        break
                    resp += chunk
                if b" 200" in resp.split(b"\r\n")[0]:
                    with ctx.wrap_socket(s, server_hostname=host):
                        proxy_times.append(round((time.perf_counter() - t0) * 1000, 1))
                else:
                    proxy_times.append(None)
                    s.close()
            except Exception:
                proxy_times.append(None)
        result["tcp_tls_via_proxy"] = {"stats": stats(proxy_times), "times": proxy_times}
        print(f"[4/4] 代理 经 {proxy[0]}:{proxy[1]} 平均 "
              f"{stats(proxy_times).get('avg', 'n/a')}ms", flush=True)
    else:
        print("[4/4] 未指定本地代理，跳过（游戏客户端不会走代理这条路）", flush=True)

    dst = out_path("probe_fast_result.json")
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1, ensure_ascii=False)
    print("\n结果已写入 " + os.path.relpath(dst))
    return 0


if __name__ == "__main__":
    sys.exit(main())
