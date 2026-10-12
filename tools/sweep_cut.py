#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sweep_cut — 扫首段切点，找出中间设备真正放行的长度区间。

背景：设备不会做 TCP 流重组，但它有个「攒够多少字节才查」的水位线。所以
「把 ClientHello 拆成两段」这件事，第一段切多长是决定成败的关键：

    切得太短（关键词完整出现在首段之前的位置）→ 被 RST
    切到域名内部 → 关键词不完整 → 通过

本脚本把同一个 ClientHello 按一串 cut 值逐个试，最后直接把「通过 / 被拦」的分界
打印出来 —— 换一台设备时，先用它测出阈值，再回去改 `min_cut`。

本机实测（2026-10-12）：分界线在 113/114 之间，即首段 <=113 必被拦、>=114 即通过。
因此引擎默认 `min_cut=124`（留 10B 余量）。

用法：
    python sweep_cut.py                     # 默认 zzz.mihoyo.com
    python sweep_cut.py www.mihoyo.com
    python sweep_cut.py zzz.mihoyo.com 1,16,64,100,112,113,114,116,124
"""
import socket
import ssl
import sys
import time

DEFAULT_HOST = "zzz.mihoyo.com"

# 2026-10-12 当天该域名的 DNS 解析结果，仅在解析失败时兜底
FALLBACK_IP = "60.163.131.14"

DEFAULT_CUTS = [1, 16, 32, 48, 64, 80, 96, 100, 104, 108, 112, 113, 114, 116,
                120, 124, 128, 129, 130, 132, 134]


def init_console():
    """把 stdout/stderr 切到 UTF-8：输出被重定向到管道/文件时，编码会退化成系统 ANSI
    代码页（英文 Windows 的 cp1252 编不了中文 → UnicodeEncodeError 直接崩）。真控制台上
    Python 走 WriteConsoleW、本来就是 UTF-8，所以等于没做事。实现与 core/fragcore.py
    的同名函数一致（本脚本保持零依赖，所以复制了一份）。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            try:
                stream.reconfigure(errors="replace")
            except Exception:
                pass


def resolve(host):
    try:
        ip = socket.gethostbyname(host)
        print(f"DNS  {host} -> {ip}")
        return ip
    except Exception as e:
        print(f"DNS  {host} 解析失败（{type(e).__name__}），回退到记录值 {FALLBACK_IP}")
        return FALLBACK_IP


def build_client_hello(host):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=host)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def main():
    init_console()
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    if len(sys.argv) > 2:
        cuts = [int(x) for x in sys.argv[2].replace(" ", "").split(",") if x]
    else:
        cuts = DEFAULT_CUTS

    ip = resolve(host)
    hello = build_client_hello(host)
    kw = hello.find(b"mihoyo")
    if kw < 0:
        kw = hello.find(b"zzz")
    print(f"ClientHello {len(hello)}B，关键词偏移 {kw}B（第二段从 cut 开始发）")
    print(f"{'cut':>5} | 结果")
    print("-" * 46)

    passed, blocked = [], []

    def try_cut(cut, delay=0.01):
        s = socket.socket()
        s.settimeout(4)
        try:
            s.connect((ip, 443))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.sendall(hello[:cut])
            time.sleep(delay)
            s.sendall(hello[cut:])
            try:
                data = s.recv(2048)
            except socket.timeout:
                return "无响应（既没通过也没 RST）", None
            if not data:
                return "空包 / 被关闭", None
            if data[0:1] == b"\x16":
                return "✅ 通过（收到服务端响应）", True
            return f"其他 {data[:2].hex()}", None
        except ConnectionResetError:
            return "❌ RST（被拦截）", False
        except Exception as e:
            return f"❌ {type(e).__name__}", None
        finally:
            s.close()

    for cut in cuts:
        if cut >= len(hello):
            continue
        text, verdict = try_cut(cut)
        if verdict is True:
            passed.append(cut)
        elif verdict is False:
            blocked.append(cut)
        print(f"{cut:>5} | {text}")
        sys.stdout.flush()

    print()
    if blocked and passed:
        print(f"被拦的最大 cut = {max(blocked)}   通过的最小 cut = {min(passed)}")
        print(f"→ 这台设备的分界可能在 {max(blocked)} / {min(passed)} 之间；"
              f"把 min_cut 设在 {min(passed) + 10} 左右留余量。")
    elif passed and not blocked:
        print(f"所有测试的 cut 都通过（最小 {min(passed)}）—— 这台设备可能不检查首包，"
              f"或者关键词不在这份名单里。")
    elif blocked and not passed:
        print("所有 cut 都被拦 —— 这台设备可能做了 TCP 流重组，"
              "或者封锁不是按 SNI 关键词做的，分片方案对它无效。")
    else:
        print("没有得到有效判决（全是超时 / 其他响应），请检查网络是否可达。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
