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

⭐ 必须看对照组：
    脚本会先「整包一次发」做对照组。**只有对照组被 RST，才说明设备在场**，
    下面的扫描结果才有意义。若对照组就通过了，说明这条链路当前没有那台设备，
    此时所有 cut 都会「通过」—— 那是假证据，不是好消息。
    真发生过：同一天换到另一条链路复测，对照组直接通过，8 个实验全部"成功"。

用法：
    python sweep_cut.py                          # 默认 zzz.mihoyo.com，试默认 cut 列表
    python sweep_cut.py www.mihoyo.com
    python sweep_cut.py zzz.mihoyo.com 1,16,64,112,113,114,116,124
    python sweep_cut.py zzz.mihoyo.com --window  # ★ 扫 [114, 域名起点-1] 全窗口

`--window` 的用途：验证**隐私模式随机切点**的前提 ——
「窗口内每一个 cut 值都能放行」。如果设备行为在窗口内不单调，随机切点会随机失败。
⚠️ 这个扫描必须在**有设备的网络**里跑；没有设备的链路上它会给出"全部通过"的假象。
"""
import argparse
import socket
import ssl
import sys
import time

DEFAULT_HOST = "zzz.mihoyo.com"

# 2026-10-12 当天该域名的 DNS 解析结果，仅在解析失败时兜底
FALLBACK_IP = "60.163.131.14"

# 实测的设备水位线：首段 <=113 被拦，>=114 通过
DEVICE_THRESHOLD = 114

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


def probe(ip, hello, cut=None, delay=0.01, timeout=4):
    """发一次探测。

    cut=None  → 对照组：整包一次 sendall（设备在场的话应当被 RST）
    cut=N     → 实验组：先发前 N 字节，停顿 delay，再发剩下的

    返回 (描述, 判决)：判决 True=通过 / False=被 RST / None=不确定
    """
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, 443))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if cut is None:
            s.sendall(hello)
        else:
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


def window_cuts(hello, host, lo, hi=None):
    """按域名在 ClientHello 里的真实偏移，算出窗口内的全部 cut 值。

    上界取「域名起点 - 1」—— 切在域名之前，完整域名才不会落在首段里。
    """
    start = hello.find(host.encode())
    if start < 0:
        return None, []
    top = (start - 1) if hi is None else min(hi, start - 1)
    if top < lo:
        return start, []
    return start, list(range(lo, top + 1))


def main():
    init_console()
    ap = argparse.ArgumentParser(description="扫首段切点，找出设备真正放行的长度区间")
    ap.add_argument("host", nargs="?", default=DEFAULT_HOST)
    ap.add_argument("cuts", nargs="?", default=None,
                    help="逗号分隔的 cut 列表，例如 1,64,112,113,114,124")
    ap.add_argument("--window", action="store_true",
                    help="扫描 [--lo, 域名起点-1] 的全窗口（验证隐私模式随机切点的前提）")
    ap.add_argument("--lo", type=int, default=DEVICE_THRESHOLD,
                    help=f"窗口下界，默认 {DEVICE_THRESHOLD}（实测设备阈值）")
    ap.add_argument("--no-control", action="store_true", help="跳过对照组（不推荐）")
    ap.add_argument("--delay", type=float, default=0.01, help="两段之间的停顿，默认 0.01s")
    args = ap.parse_args()

    ip = resolve(args.host)
    hello = build_client_hello(args.host)
    kw = hello.find(b"mihoyo")
    if kw < 0:
        kw = hello.find(b"zzz")
    start = hello.find(args.host.encode())
    print(f"ClientHello {len(hello)}B，域名起始偏移 {start}B，关键词偏移 {kw}B")
    print()

    # ---------- 对照组：这一步决定了后面所有结论有没有意义 ----------
    control_ok = None            # None=未跑 / True=被拦(设备在场) / False=通过(设备不在)
    if not args.no_control:
        text, verdict = probe(ip, hello, cut=None, delay=args.delay)
        print(f"对照组（整包一次发）: {text}")
        if verdict is False:
            control_ok = True
            print("  → 设备在场 ✅ 下面的扫描结果有效。")
        elif verdict is True:
            control_ok = False
            print("  ⚠ 对照组没有被 RST —— **这条链路当前很可能没有那台设备**。")
            print("    此时下面所有 cut 都会『通过』，但那是假证据：说明的是设备不在，")
            print("    不是分片有效。请换到有设备的网络再跑，或先确认封锁确实存在。")
        else:
            print("  ⚠ 对照组没有拿到明确判决（超时/其他响应），结论同样不可靠。")
        print()

    # ---------- 生成 cut 列表 ----------
    if args.window:
        start, cuts = window_cuts(hello, args.host, args.lo)
        if start is None:
            print(f"✗ 在 ClientHello 里找不到域名 {args.host} 的字节，无法确定窗口。")
            return 1
        if not cuts:
            print(f"✗ 窗口为空：域名起始偏移 {start}B <= 下界 {args.lo}B，")
            print("  没有既能放行又不泄露域名的切点取值（这正是引擎里『跳过』的分支）。")
            return 1
        print(f"全窗口扫描：cut ∈ [{cuts[0]}, {cuts[-1]}]，共 {len(cuts)} 个值")
        print("（验证「窗口内每个 cut 都放行」—— 隐私模式随机切点的前提）")
    elif args.cuts:
        cuts = [int(x) for x in args.cuts.replace(" ", "").split(",") if x]
    else:
        cuts = DEFAULT_CUTS

    print(f"{'cut':>5} | 结果")
    print("-" * 46)

    passed, blocked, other = [], [], []
    for cut in cuts:
        if cut >= len(hello):
            continue
        text, verdict = probe(ip, hello, cut=cut, delay=args.delay)
        if verdict is True:
            passed.append(cut)
        elif verdict is False:
            blocked.append(cut)
        else:
            other.append(cut)
        print(f"{cut:>5} | {text}")
        sys.stdout.flush()

    # ---------- 汇总 ----------
    print()
    unreliable = (control_ok is False)
    if unreliable:
        print("=" * 62)
        print("  ⚠ 本次结果不可作为证据：对照组没被 RST，设备不在这条链路上。")
        print("    下面这些『通过』只说明封锁不存在，**不能**说明分片有效。")
        print("=" * 62)
        print()

    if blocked and passed:
        print(f"被拦的最大 cut = {max(blocked)}   通过的最小 cut = {min(passed)}")
        print(f"→ 这台设备的分界可能在 {max(blocked)} / {min(passed)} 之间；"
              f"把 min_cut 设在 {min(passed) + 10} 左右留余量。")
    elif passed and not blocked:
        print(f"所有测试的 cut 都通过（最小 {min(passed)}）。")
        if control_ok is True:
            print("  对照组被 RST 且全部 cut 通过 → 设备确实只看首包、不重装，属于预期行为。")
        elif control_ok is None:
            print("  （未跑对照组，无法判断这个『全部通过』是否可信。）")
    elif blocked and not passed:
        print("所有 cut 都被拦 —— 这台设备可能做了 TCP 流重组，"
              "或者封锁不是按 SNI 关键词做的，分片方案对它无效。")
    else:
        print("没有得到有效判决（全是超时 / 其他响应），请检查网络是否可达。")

    if args.window and passed:
        gaps = [c for c in range(cuts[0], cuts[-1] + 1)
                if c not in passed and c not in blocked]
        print()
        if blocked:
            print("★ 窗口内存在**被拦**的 cut 值 —— 随机切点会随机失败！")
            print(f"  被拦取值：{blocked}")
            print("  结论：不要开启随机切点，或把随机范围收缩到连续通过的子区间。")
        elif gaps:
            print(f"★ 窗口内有 {len(gaps)} 个取值没有得到判决（超时/其他）：{gaps}")
            print("  这些取值上随机切点不可靠，建议重跑确认。")
        elif unreliable:
            print("★ 窗口内每个 cut 都通过，但对照组已证明设备不在。")
            print("  → **结论无效**，请在确认封锁存在的网络里重跑本扫描。")
        else:
            print("★ 窗口内每一个 cut 值都通过 ✅ —— 随机切点的前提成立。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
