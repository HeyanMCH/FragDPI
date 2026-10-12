#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fragdpi.py — 系统级首包分片工具（WinDivert 内核驱动方案，架构参考 GoodbyeDPI）

作用：在本机网络层拦截出站 TCP 443 上的 TLS ClientHello，把承载它的第一个
      数据包重新切分成多个 TCP 段发出，使域名关键词不再出现在首个报文里，
      从而绕过"只检查首包 SNI 关键词"的中间设备（本环境为教室网行为管理设备）。
      全部程序（浏览器、游戏客户端、更新器）自动生效，无需配置任何代理。

原理要点（本环境实测得出）：
      1. 中间设备会解析 TLS 记录/扩展结构，且会把前几个报文攒到一定长度再查；
         实测阈值 = 114 字节：首段 <= 113 字节必被拦，>= 114 即通过。
         因此默认 min-cut=124（留 10 字节余量），别调小；
      2. 同时切割点必须落在域名之前，使关键词不完整地出现在首段里 —— 默认
         取"关键词位置 - guard(6)"，实测稳定通过；
      3. 切太早（如第 1 字节、第 64 字节）会被拦截。

依赖：WinDivert.dll + WinDivert64.sys（在 <repo>/third_party/windivert/，官方 2.2.2 x64 版）
      必须以管理员身份运行（加载内核驱动）

用法：
    python fragdpi.py --selftest        # 启动并自检直连是否成功
    python fragdpi.py --keyword mihoyo,hoyoverse
    python fragdpi.py --selfcheck       # 只检查 DLL/驱动/权限，不启动拦截
    python fragdpi.py --packettest      # 离线验证分片算法（无需管理员）
"""
import argparse
import ctypes
import os
import socket
import ssl
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WINDIVERT_LAYER_NETWORK = 0
ADDR_SIZE = 128  # WINDIVERT_ADDRESS 用不透明缓冲，留足空间

# ---------------------------------------------------------------- WinDivert 绑定
_wd = None


def _find_dll():
    """WinDivert.dll 在 <repo>/third_party/windivert/，本脚本在 <repo>/tools/ 下。
    从脚本目录逐级向上查找，这样从任意位置调用都能定位。"""
    rel = (os.path.join("third_party", "windivert", "WinDivert.dll"), "WinDivert.dll")
    d = HERE
    for _ in range(5):
        for r in rel:
            p = os.path.join(d, r)
            if os.path.exists(p):
                return p
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    for r in rel:
        p = os.path.join(os.getcwd(), r)
        if os.path.exists(p):
            return p
    return None


def load_windivert():
    global _wd
    if _wd is not None:
        return _wd
    dll_path = _find_dll()
    if not dll_path:
        raise FileNotFoundError(
            "找不到 WinDivert.dll（已查找 %s 及其上级目录）" % HERE)
    dll = ctypes.WinDLL(dll_path, use_last_error=True)
    dll.WinDivertOpen.restype = ctypes.c_void_p
    dll.WinDivertOpen.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int16, ctypes.c_uint64]
    dll.WinDivertRecv.restype = ctypes.c_int
    dll.WinDivertRecv.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
                                  ctypes.POINTER(ctypes.c_uint), ctypes.c_void_p]
    dll.WinDivertSend.restype = ctypes.c_int
    dll.WinDivertSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
                                  ctypes.POINTER(ctypes.c_uint), ctypes.c_void_p]
    dll.WinDivertHelperCalcChecksums.restype = ctypes.c_int
    dll.WinDivertHelperCalcChecksums.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                                 ctypes.c_void_p, ctypes.c_uint64]
    dll.WinDivertClose.restype = ctypes.c_int
    dll.WinDivertClose.argtypes = [ctypes.c_void_p]
    _wd = dll
    return dll


# ---------------------------------------------------------------- 分片核心逻辑
def split_packet(data, keywords, guard=6, min_cut=128, mtu=1500):
    """把承载 ClientHello 的出站包切成多个 TCP 段。

    返回 (packets, info)：packets 为待发送的字节串列表（原包不发送），
    info 为 None 或说明字符串。
    """
    if len(data) < 40:
        return [data], None
    ver = data[0] >> 4
    if ver == 4:
        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl + 20:
            return [data], None
        proto = data[9]
        total = struct.unpack_from(">H", data, 2)[0]
        hdr_len = ihl
    elif ver == 6:
        if len(data) < 60:
            return [data], None
        proto = data[6]
        hdr_len = 40
        total = hdr_len + struct.unpack_from(">H", data, 4)[0]
    else:
        return [data], None

    if proto != 6:  # 只处理 TCP
        return [data], None
    total = min(total, len(data))
    tcp_off = hdr_len
    if total < tcp_off + 20:
        return [data], None
    doff = (data[tcp_off + 12] >> 4) * 4
    if doff < 20:
        return [data], None
    payload_off = tcp_off + doff
    if payload_off >= total:
        return [data], None
    payload = bytes(data[payload_off:total])

    # 只处理"TLS 握手首包 + ClientHello"（记录类型 0x16，握手类型 0x01）
    if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
        return [data], None

    pos = -1
    hit_kw = None
    for kw in keywords:
        p = payload.find(kw.encode("ascii"))
        if p >= 0:
            pos, hit_kw = p, kw
            break
    if pos < 0:
        return [data], None

    cut = pos - guard
    if cut < min_cut:
        cut = min_cut
    if cut >= pos:                     # 会把关键词整体留在首段 → 改为切在关键词内部
        cut = pos + 1
    if cut < min_cut or cut <= 0 or cut >= len(payload) - 1:
        return [data], f"关键词 {hit_kw!r}@{pos}B 位置不合适（cut={cut}），原样发送"

    hdr = data[:payload_off]
    seq = struct.unpack_from(">I", hdr, tcp_off + 4)[0]
    max_seg = max(200, mtu - payload_off)      # 单段最大负载（MTU 扣除包头）

    # 第一段固定为 cut 字节，其余按 MTU 重新分段
    bounds = [0, cut]
    while bounds[-1] < len(payload):
        bounds.append(min(len(payload), bounds[-1] + max_seg))

    packets = []
    for i in range(len(bounds) - 1):
        seg = payload[bounds[i]:bounds[i + 1]]
        seg_seq = (seq + bounds[i]) & 0xFFFFFFFF
        pkt = bytearray(hdr + seg)
        struct.pack_into(">I", pkt, tcp_off + 4, seg_seq)
        if ver == 4:
            struct.pack_into(">H", pkt, 2, len(pkt))
        else:
            struct.pack_into(">H", pkt, 4, len(pkt) - hdr_len)
        packets.append(bytes(pkt))

    info = (f"关键词 {hit_kw!r}@{pos}B → 首段 {cut}B"
            f"{'' if len(packets) == 2 else f'，其余拆成 {len(packets) - 1} 段'}")
    return packets, info


# ---------------------------------------------------------------- 运行主体
class Runner:
    def __init__(self, args):
        self.args = args
        self.keywords = [k.strip() for k in args.keyword.split(",") if k.strip()]
        self.stop = threading.Event()
        self.stats = {"seen": 0, "split": 0, "sent": 0, "recent": []}

    def send(self, handle, addr, packet):
        buf = ctypes.create_string_buffer(packet, len(packet))
        send_len = ctypes.c_uint()
        ok = _wd.WinDivertSend(handle, buf, len(packet), ctypes.byref(send_len), addr)
        if ok:
            self.stats["sent"] += 1
        return ok

    def fix_checksum(self, packet, addr):
        buf = ctypes.create_string_buffer(packet, len(packet))
        _wd.WinDivertHelperCalcChecksums(buf, len(packet), addr, 0)
        return buf.raw

    def log(self, msg):
        now = time.time()
        self.stats["recent"] = [t for t in self.stats["recent"] if now - t < 3]
        self.stats["recent"].append(now)
        if len(self.stats["recent"]) > 12 and not self.args.verbose:
            return
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

    def loop(self):
        args = self.args
        dll = load_windivert()
        handle = dll.WinDivertOpen(args.filter.encode(), WINDIVERT_LAYER_NETWORK, 0, 0)
        if not handle or handle == ctypes.c_void_p(-1).value:
            err = ctypes.get_last_error()
            print(f"\n[错误] 打开 WinDivert 过滤句柄失败（Win32 错误码 {err}）")
            if err == 5:
                print("       这是权限不足：WinDivert 需要加载内核驱动，请以【管理员身份】运行。")
            else:
                print("       请确认 third_party/windivert/ 下的 WinDivert.dll / WinDivert64.sys 存在且为 x64 版本。")
            self.stop.set()
            return
        print(f"[{time.strftime('%H:%M:%S')}] 拦截已启动  过滤器: {args.filter}")
        print(f"[{time.strftime('%H:%M:%S')}] 关键词: {self.keywords}  guard={args.guard}  min-cut={args.min_cut}")

        pkt_buf = ctypes.create_string_buffer(65535)
        addr = ctypes.create_string_buffer(ADDR_SIZE)
        recv_len = ctypes.c_uint()
        started = time.time()

        try:
            while not self.stop.is_set():
                if args.duration and time.time() - started > args.duration:
                    break
                if not dll.WinDivertRecv(handle, pkt_buf, 65535, ctypes.byref(recv_len), addr):
                    err = ctypes.get_last_error()
                    if err == 995:  # ERROR_OPERATION_ABORTED
                        break
                    continue
                data = pkt_buf.raw[:recv_len.value]
                self.stats["seen"] += 1
                packets, info = split_packet(data, self.keywords, args.guard, args.min_cut, args.mtu)
                if info:
                    self.stats["split"] += 1
                    self.log(f"分片 #{self.stats['split']}  {info}  原包 {len(data)}B")
                    for p in packets:
                        self.send(handle, addr, self.fix_checksum(p, addr))
                else:
                    self.send(handle, addr, data)
        except KeyboardInterrupt:
            pass
        finally:
            dll.WinDivertClose(handle)
            print(f"\n已停止。共捕获 {self.stats['seen']} 个包，分片 {self.stats['split']} 次，发送 {self.stats['sent']} 个包。")

    def start(self):
        t = threading.Thread(target=self.loop, daemon=True)
        t.start()
        return t


# ---------------------------------------------------------------- 自检
def selfcheck():
    print("=== 1. 加载 WinDivert.dll ===")
    try:
        dll = load_windivert()
        print("    OK，符号已绑定")
    except Exception as e:
        print(f"    失败：{e}")
        return
    print("=== 2. 尝试打开过滤句柄（需要管理员）===")
    h = dll.WinDivertOpen(b"false", WINDIVERT_LAYER_NETWORK, 0, 0)
    if h and h != ctypes.c_void_p(-1).value:
        print("    OK，权限正常，可以启动拦截")
        dll.WinDivertClose(h)
    else:
        err = ctypes.get_last_error()
        print(f"    失败，Win32 错误码 {err}" + ("（权限不足，请用管理员运行）" if err == 5 else ""))


def selftest_direct(host="zzz.mihoyo.com", delay=2.0):
    time.sleep(delay)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        print(f"  [自检] DNS 解析失败：{e}")
        return
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        t0 = time.perf_counter()
        with socket.create_connection((ip, 443), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                ms = (time.perf_counter() - t0) * 1000
                print(f"  [自检] 直连 {host}:443 TLS 握手成功，耗时 {ms:.0f}ms  —— 分片生效 ✅")
    except Exception as e:
        print(f"  [自检] 直连 {host}:443 失败 ❌ {type(e).__name__}: {e}")
        print("         （若上面显示拦截已启动且你是管理员运行，说明参数需要调整，试试 --guard 9）")


# ---------------------------------------------------------------- 离线算法验证
def packettest():
    """构造一个结构真实、含 SNI 的 ClientHello（IPv4/TCP），验证分片结果的字节与校验和。"""
    import random
    random.seed(1)

    def build_hello(pad_len):
        rand = bytes(random.getrandbits(8) for _ in range(32))
        sid = b"\x20" + bytes(random.getrandbits(8) for _ in range(32))
        ciphers = b"\x00\x3a" + bytes(random.getrandbits(8) for _ in range(58))
        host = b"zzz.mihoyo.com"
        ext_pad = b"\x00\x15" + struct.pack(">H", pad_len) + b"\x00" * pad_len
        ext_alpn = b"\x00\x10\x00\x05\x00\x03\x02h2"
        ext_sni = (b"\x00\x00" + struct.pack(">H", len(host) + 5) +
                   struct.pack(">H", len(host) + 3) + b"\x00" +
                   struct.pack(">H", len(host)) + host)
        ext_ks = (b"\x00\x33\x00\x24\x00\x1d\x00\x20" +
                  bytes(random.getrandbits(8) for _ in range(32)))
        exts = ext_pad + ext_alpn + ext_sni + ext_ks
        body = b"\x03\x03" + rand + sid + ciphers + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs

    pad = 0
    hello = build_hello(pad)
    while hello.find(b"mihoyo") < 140:
        pad += 16
        hello = build_hello(pad)
    print(f"伪造 ClientHello 长度 {len(hello)}B，关键词 mihoyo @ {hello.find(b'mihoyo')}B")

    tcp_payload = hello
    src_ip, dst_ip = b"\xc0\xa8\x1f\x4c", b"\x3c\xa3\x4e\x18"
    tcp = struct.pack(">HHIIBBHHH", 54321, 443, 1000, 2000, (5 << 4), 0x18, 65535, 0, 0) + tcp_payload
    # 伪头部 + TCP 计算校验和
    pseudo = src_ip + dst_ip + b"\x00\x06" + struct.pack(">H", len(tcp))
    def cksum(b):
        if len(b) % 2:
            b += b"\x00"
        s = sum(struct.unpack(">%dH" % (len(b) // 2), b))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF
    tcp = tcp[:16] + struct.pack(">H", cksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1234, 0x4000, 64, 6, 0, src_ip, dst_ip)
    ip = ip[:10] + struct.pack(">H", cksum(ip)) + ip[12:]
    packet = ip + tcp
    print(f"原始包 {len(packet)}B（IPv4 {20}B + TCP 20B + 负载 {len(tcp_payload)}B）")

    dll = load_windivert()
    addr = ctypes.create_string_buffer(ADDR_SIZE)

    def fix(p):
        buf = ctypes.create_string_buffer(p, len(p))
        dll.WinDivertHelperCalcChecksums(buf, len(p), addr, 0)
        return buf.raw

    packets, info = split_packet(packet, ["mihoyo"], guard=6, min_cut=124)
    print(f"分片结果：{len(packets)} 个包，info = {info}")
    assert len(packets) == 2, "应当拆成 2 个包"

    p1, p2 = fix(packets[0]), fix(packets[1])
    hdr_len = 40
    pay1, pay2 = p1[hdr_len:], p2[hdr_len:]
    seq1 = struct.unpack_from(">I", p1, 24)[0]
    seq2 = struct.unpack_from(">I", p2, 24)[0]

    ok = True
    cut = len(pay1)
    print(f"  包1: 总长 {len(p1)}B, 负载 {cut}B, seq={seq1}")
    print(f"  包2: 总长 {len(p2)}B, 负载 {len(pay2)}B, seq={seq2}")
    ok &= (pay1 + pay2 == tcp_payload)
    print(f"  [1] 两段拼回原负载: {'通过' if pay1 + pay2 == tcp_payload else '失败'}")
    ok &= (seq2 == seq1 + cut)
    print(f"  [2] seq 衔接正确: {'通过' if seq2 == seq1 + cut else '失败'}")
    ok &= (b"mihoyo" not in pay1)
    print(f"  [3] 首段不含完整关键词: {'通过' if b'mihoyo' not in pay1 else '失败'}")
    ok &= (cut >= 124)
    print(f"  [4] 首段长度 >= min-cut(124): {'通过' if cut >= 124 else '失败'}")
    # 校验和验证
    def verify(pkt):
        hlen = (pkt[0] & 0xF) * 4
        tot = struct.unpack_from(">H", pkt, 2)[0]
        if tot != len(pkt):
            return False, "长度字段不符"
        if cksum(pkt[:hlen]) != 0:
            return False, "IP 校验和错误"
        tcpseg = pkt[hlen:tot]
        ps = pkt[12:20] + b"\x00\x06" + struct.pack(">H", len(tcpseg))
        if cksum(ps + tcpseg) != 0:
            return False, "TCP 校验和错误"
        return True, "ok"
    for i, p in enumerate((p1, p2), 1):
        good, why = verify(p)
        ok &= good
        print(f"  [5.{i}] 包{i} 长度/校验和: {'通过' if good else '失败 - ' + why}")

    # ---- 场景 2：LSO/TSO 大包（负载 > MTU）应被重新分段 ----
    print("\n--- 场景 2：大负载包（负载 4000B，模拟网卡 LSO 卸载）---")
    big_payload = tcp_payload + b"\x17\x03\x03\x0f\xa0" + bytes(4000)
    big_tcp = struct.pack(">HHIIBBHHH", 54321, 443, 1000, 2000, (5 << 4), 0x18, 65535, 0, 0) + big_payload
    ps = src_ip + dst_ip + b"\x00\x06" + struct.pack(">H", len(big_tcp))
    big_tcp = big_tcp[:16] + struct.pack(">H", cksum(ps + big_tcp)) + big_tcp[18:]
    big_ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(big_tcp), 1235, 0x4000, 64, 6, 0, src_ip, dst_ip)
    big_ip = big_ip[:10] + struct.pack(">H", cksum(big_ip)) + big_ip[12:]
    big_pkt = big_ip + big_tcp

    segs, info2 = split_packet(big_pkt, ["mihoyo"], guard=6, min_cut=124, mtu=1500)
    print(f"原始包 {len(big_pkt)}B → 拆成 {len(segs)} 个包，info = {info2}")
    reassembled, seqs, sizes, ck_ok = b"", [], [], True
    for i, s in enumerate(segs):
        s = fix(s)
        reassembled += s[40:]
        seqs.append(struct.unpack_from(">I", s, 24)[0])
        sizes.append(len(s))
        good, why = verify(s)
        if not good:
            ck_ok = False
            print(f"     段{i + 1} 校验和失败：{why}")
    ok &= (reassembled == big_payload)
    print(f"  [6] 所有分段拼回原负载: {'通过' if reassembled == big_payload else '失败'}")
    seq_ok = all(seqs[i + 1] == seqs[i] + len(segs[i][40:]) for i in range(len(segs) - 1))
    ok &= seq_ok
    print(f"  [7] 各段 seq 连续: {'通过' if seq_ok else '失败'}")
    mtu_ok = all(s <= 1500 for s in sizes) and len(segs[0]) == 200
    ok &= mtu_ok
    print(f"  [8] 各段均 <= MTU 且首段为切点: {'通过' if mtu_ok else '失败'}  段长={sizes}")
    ok &= ck_ok
    print(f"  [9] 所有分段校验和: {'通过' if ck_ok else '失败'}")

    print("\n结论: " + ("全部通过 ✅ 分片算法与校验和正确" if ok else "存在失败项 ❌"))
    return ok


def main():
    ap = argparse.ArgumentParser(description="系统级首包分片工具（WinDivert，架构参考 GoodbyeDPI）")
    ap.add_argument("--keyword", default="mihoyo,hoyoverse", help="关键词，逗号分隔")
    ap.add_argument("--guard", type=int, default=6, help="在关键词前多少字节处切（建议 3~12）")
    ap.add_argument("--min-cut", type=int, default=124,
                    help="首段最小长度。实测该网络阈值 114（<=113 被拦），默认 124 留 10B 余量")
    ap.add_argument("--mtu", type=int, default=1500, help="重新分段时的 MTU，默认 1500")
    ap.add_argument("--filter", default="outbound and tcp and tcp.DstPort == 443",
                    help="WinDivert 过滤器")
    ap.add_argument("--duration", type=float, default=0, help="运行秒数，0 表示一直运行")
    ap.add_argument("--selftest", action="store_true", help="启动后自动测试直连是否成功")
    ap.add_argument("--selfcheck", action="store_true", help="只检查 DLL/驱动/权限")
    ap.add_argument("--packettest", action="store_true", help="离线验证分片算法（无需管理员）")
    ap.add_argument("--logfile", help="把输出同时写入该文件（便于提权运行后回读结果）")
    ap.add_argument("--verbose", action="store_true", help="输出所有分片日志")
    args = ap.parse_args()

    if args.logfile:
        class _Tee:
            def __init__(self, path):
                self.f = open(path, "w", encoding="utf-8", buffering=1)

            def write(self, s):
                try:
                    sys.__stdout__.write(s)
                except Exception:
                    pass
                self.f.write(s)

            def flush(self):
                try:
                    sys.__stdout__.flush()
                except Exception:
                    pass
                self.f.flush()

        sys.stdout = _Tee(args.logfile)
        sys.stderr = sys.stdout

    if args.packettest:
        sys.exit(0 if packettest() else 1)
    if args.selfcheck:
        selfcheck()
        return

    print("=" * 64)
    print(" fragdpi 系统级首包分片工具（WinDivert）")
    print("=" * 64)
    runner = Runner(args)
    if args.selftest:
        threading.Thread(target=selftest_direct, daemon=True).start()
    runner.start()
    try:
        while not runner.stop.is_set():
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass
    runner.stop.set()
    time.sleep(0.5)


if __name__ == "__main__":
    main()
