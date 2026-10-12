#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fragcore — 首包分片引擎核心（WinDivert）

职责：
  1. ctypes 绑定 WinDivert 2.2.2 x64
  2. 从 ClientHello 里**解析出真实 SNI 域名**（规则系统的基础）
  3. 规则系统：模式 off / rules / global，规则类型 suffix（域名后缀）/ keyword（关键词）
  4. 分片：把承载 ClientHello 的首个 TCP 报文切成多段，重算校验和后重注入
  5. Engine：后台线程跑抓包循环，事件通过回调上报

实测约束（2026-10-12，教室网行为管理设备）：
  · 设备会把前几个报文攒到 **114 字节**再查：首段 <= 113 必被拦，>= 114 即通过
  · 且切割点必须落在 SNI 扩展内部（域名之前），否则关键词会完整出现在首段
  · 因此 cut = max(min_cut, 域名起始位置 - guard)
"""
import ctypes
import os
import socket
import struct
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WINDIVERT_LAYER_NETWORK = 0
ADDR_SIZE = 128
MEASURED_DEVICE_THRESHOLD = 114  # 实测：首段 <=113 被拦

# WinDivert 二进制放在 <repo>/third_party/windivert/，本模块在 <repo>/core/。
# 从 HERE 起逐级向上找，这样 core/ 与 tools/ 下的脚本都能正确定位。
_DLL_CANDIDATES = (
    "WinDivert.dll",
    os.path.join("third_party", "windivert", "WinDivert.dll"),
    os.path.join("tools", "WinDivert.dll"),
)


def find_dll():
    d = HERE
    for _ in range(5):                       # core/ -> 仓库根 -> 再往上留余量
        for rel in _DLL_CANDIDATES:
            p = os.path.join(d, rel)
            if os.path.exists(p):
                return p
        parent = os.path.dirname(d)
        if parent == d:                      # 到盘符根了
            break
        d = parent
    for rel in _DLL_CANDIDATES:              # 最后兜底：当前工作目录
        p = os.path.join(os.getcwd(), rel)
        if os.path.exists(p):
            return p
    return None


DLL_PATH = find_dll()

_wd = None
_wd_lock = threading.Lock()


# ------------------------------------------------------------------ WinDivert
def load_dll():
    global _wd
    with _wd_lock:
        if _wd is not None:
            return _wd
        path = find_dll()
        if not path:
            raise FileNotFoundError(
                "找不到 WinDivert.dll（已查找：%s 及其上级目录）" % HERE)
        dll = ctypes.WinDLL(path, use_last_error=True)
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


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ------------------------------------------------------------------ SNI 解析
def parse_sni(payload):
    """从 TLS ClientHello 里取出 SNI 域名。

    返回 (domain, host_start, host_end)：
      domain     —— 域名（若当前报文里被截断，则为已收到的部分）
      host_start —— 域名在 payload 内的起始偏移（分片切点靠它定位）
      host_end   —— 域名结束偏移；None 表示本包内不完整
    解析失败返回 (None, None, None)。
    """
    if len(payload) < 9 or payload[0] != 0x16 or payload[1] != 0x03:
        return (None, None, None)
    hs = payload[5:]
    if len(hs) < 4 or hs[0] != 0x01:          # 必须是 ClientHello
        return (None, None, None)
    body_len = int.from_bytes(hs[1:4], "big")
    body = hs[4:4 + body_len]
    pos = 34                                   # version(2) + random(32)
    if len(body) <= pos:
        return (None, None, None)
    sid_len = body[pos]
    pos += 1 + sid_len
    if pos + 2 > len(body):
        return (None, None, None)
    cs_len = struct.unpack_from(">H", body, pos)[0]
    pos += 2 + cs_len
    if pos + 1 > len(body):
        return (None, None, None)
    comp_len = body[pos]
    pos += 1 + comp_len
    if pos + 2 > len(body):
        return (None, None, None)
    ext_len = struct.unpack_from(">H", body, pos)[0]
    pos += 2
    end = min(len(body), pos + ext_len)
    base = 5 + 4                               # payload 内 body 的起始偏移
    while pos + 4 <= end:
        etype, elen = struct.unpack_from(">HH", body, pos)
        if etype == 0x0000:                    # server_name
            #   结构：etype(2) elen(2) | list_len(2) name_type(1) name_len(2) name
            #   所以 name_len 在 pos+7，name 在 pos+9
            if pos + 9 > len(body):
                return (None, None, None)
            nlen = struct.unpack_from(">H", body, pos + 7)[0]
            start = base + pos + 9
            if start >= len(payload):
                return (None, None, None)
            avail = payload[start:start + nlen]
            dom = avail.decode("ascii", "replace")
            complete = len(avail) >= nlen
            return (dom, start, start + nlen if complete else None)
        pos += 4 + elen
    return (None, None, None)


# ------------------------------------------------------------------ 规则系统
class Rule:
    TYPES = ("suffix", "keyword")

    def __init__(self, name="", type="suffix", value="", enabled=True):
        self.name = name or "未命名规则"
        self.type = type if type in self.TYPES else "suffix"
        self.value = value or ""
        self.enabled = bool(enabled)
        self.hits = 0

    def values(self):
        return [v.strip() for v in self.value.split(",") if v.strip()]

    def match(self, domain, raw):
        if not self.enabled:
            return False
        if self.type == "suffix":
            if not domain:
                return False
            d = domain.lower().rstrip(".")
            for suf in self.values():
                s = suf.lower().lstrip("*").lstrip(".")
                if d == s or d.endswith("." + s):
                    return True
            return False
        # keyword：既查域名也查报文原始字节（应对域名在首包内不完整的情况）
        for kw in self.values():
            k = kw.lower()
            if domain and k in domain.lower():
                return True
            if raw and k.encode("latin1", "ignore") in raw.lower():
                return True
        return False

    def to_dict(self):
        return {"name": self.name, "type": self.type, "value": self.value,
                "enabled": self.enabled, "hits": self.hits}

    @staticmethod
    def from_dict(d):
        return Rule(d.get("name", ""), d.get("type", "suffix"), d.get("value", ""), d.get("enabled", True))


def default_rules():
    """内置「游戏」预设。

    依据 2026-10-12 本机对 100+ 个游戏相关域名的实测（research/gamelist*_result.json）：
      · 实测被 DPI 注入 RST 的：*.mihoyo.com（21 个）、*.hoyoverse.com（6 个）、
        steampowered.com / steamstatic.com、battle.net、pubgmobile.com、uu.163.com
      · 实测正常放行的：腾讯系、网易系、库洛、鹰角、西山居、epic/riot/ps/xbox 等
    这里仍然把常见的游戏域名一并纳入 —— 分片的代价只是每个连接多一个 TCP 包
    （payload 逐字节不变、序列号连续，已单测验证），换来的是设备清单变化时不用再改配置。
    """
    return [
        # ===== 实测被 RST：必须分片 =====
        Rule("游戏 · 米哈游系（绝区零/原神/星铁/崩3/未定）", "suffix",
             "mihoyo.com", True),
        Rule("游戏 · 米哈游国际服 Hoyoverse", "suffix",
             "hoyoverse.com", True),
        Rule("游戏 · 暴雪战网 Battle.net", "suffix",
             "battle.net,blizzard.com,blzstatic.com", True),
        Rule("游戏 · PUBG（绝地求生/和平精英国际）", "suffix",
             "pubgmobile.com,pubg.com", True),
        Rule("游戏 · Steam 平台", "suffix",
             "steampowered.com,steamstatic.com,steamcommunity.com,"
             "steamcontent.com,steamusercontent.com,steamgames.com", True),
        Rule("游戏 · 加速器（网易UU/迅游/雷神/奇游）", "suffix",
             "uu.163.com,xunyou.com,leigod.com,qiyou.com,biubiu.com", True),

        # ===== 实测未封，一并纳入备用覆盖 =====
        Rule("游戏 · 米哈游社区（米游社 / HoYoLAB）", "suffix",
             "miyoushe.com,hoyolab.com", True),
        Rule("游戏 · 腾讯系", "suffix",
             "game.qq.com,lol.qq.com,dnf.qq.com,cf.qq.com,pvp.qq.com,"
             "speed.qq.com,honorofkings.com", True),
        Rule("游戏 · 网易系", "suffix",
             "game.163.com,neteasegames.com", True),
        Rule("游戏 · 其他国内厂商", "suffix",
             "kurogame.com,kurobbs.com,hypergryph.com,xoyo.com,jx3.xoyo.com,"
             "wanmei.com,4399.com,lilithgames.com,ztgame.com,sdo.com,changyou.com", True),
        Rule("游戏 · 主机与海外平台", "suffix",
             "playstation.com,playstation.net,xboxlive.com,xbox.com,epicgames.com,"
             "riotgames.com,leagueoflegends.com,valorant.com,nintendo.com,"
             "minecraft.net,mojang.com,roblox.com,unrealengine.com", True),

        # ===== 兜底与示例 =====
        Rule("关键词兜底（SNI 被截断时按原始字节匹配）", "keyword",
             "mihoyo,hoyoverse,steampowered,steamstatic,battle.net,pubgmobile", True),
        Rule("示例 · 自定义域名（默认停用）", "suffix", "example.com", False),
    ]


class RuleSet:
    """mode: off（不拦截）| rules（按规则）| global（全部 TLS 443）"""

    def __init__(self, mode="rules", rules=None):
        self.mode = mode if mode in ("off", "rules", "global") else "rules"
        self.rules = rules if rules is not None else default_rules()

    def decide(self, domain, raw):
        """返回 (是否分片, 命中的规则名)"""
        if self.mode == "off":
            return (False, None)
        if self.mode == "global":
            return (True, "全局模式")
        for r in self.rules:
            if r.match(domain, raw):
                r.hits += 1
                return (True, r.name)
        return (False, None)

    def to_dict(self):
        return {"mode": self.mode, "rules": [r.to_dict() for r in self.rules]}

    @staticmethod
    def from_dict(d):
        rules = [Rule.from_dict(x) for x in d.get("rules", [])] or default_rules()
        return RuleSet(d.get("mode", "rules"), rules)


# ------------------------------------------------------------------ 参数 / 分片
class Params:
    def __init__(self, guard=6, min_cut=124, mtu=1500, port=443):
        self.guard = guard
        self.min_cut = min_cut
        self.mtu = mtu
        self.port = port

    def to_dict(self):
        return {"guard": self.guard, "min_cut": self.min_cut, "mtu": self.mtu, "port": self.port}

    @staticmethod
    def from_dict(d):
        return Params(int(d.get("guard", 6)), int(d.get("min_cut", 124)),
                      int(d.get("mtu", 1500)), int(d.get("port", 443)))


def _split_into_segments(hdr, payload, cut, seq, tcp_off, ver, payload_off, mtu):
    max_seg = max(200, mtu - payload_off)
    bounds = [0, cut]
    while bounds[-1] < len(payload):
        bounds.append(min(len(payload), bounds[-1] + max_seg))
    packets = []
    for i in range(len(bounds) - 1):
        seg = payload[bounds[i]:bounds[i + 1]]
        pkt = bytearray(hdr + seg)
        struct.pack_into(">I", pkt, tcp_off + 4, (seq + bounds[i]) & 0xFFFFFFFF)
        if ver == 4:
            struct.pack_into(">H", pkt, 2, len(pkt))          # IPv4 total length
        else:
            struct.pack_into(">H", pkt, 4, len(pkt) - 40)     # IPv6 payload length
        packets.append(bytes(pkt))
    return packets


def inspect(data):
    """解析出 (ver, payload_off, payload, seq, tcp_off, total) 或 None"""
    if len(data) < 40:
        return None
    ver = data[0] >> 4
    if ver == 4:
        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl + 20:
            return None
        total = min(struct.unpack_from(">H", data, 2)[0], len(data))
        if data[9] != 6:
            return None
        tcp_off, hdr_len = ihl, ihl
    elif ver == 6:
        if len(data) < 60 or data[6] != 6:
            return None
        hdr_len = 40
        total = min(hdr_len + struct.unpack_from(">H", data, 4)[0], len(data))
        tcp_off = hdr_len
    else:
        return None
    if total < tcp_off + 20:
        return None
    doff = (data[tcp_off + 12] >> 4) * 4
    if doff < 20:
        return None
    payload_off = tcp_off + doff
    if payload_off >= total:
        return None
    payload = bytes(data[payload_off:total])
    seq = struct.unpack_from(">I", data, tcp_off + 4)[0]
    return (ver, payload_off, payload, seq, tcp_off, total)


def split_packet(data, ruleset, params):
    """按规则决定是否分片。返回 dict(packets, info, domain, rule)"""
    out = {"packets": [data], "info": None, "domain": None, "rule": None}
    r = inspect(data)
    if not r:
        return out
    ver, payload_off, payload, seq, tcp_off, total = r
    if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
        return out                                  # 只处理 ClientHello

    domain, host_start, host_end = parse_sni(payload)
    out["domain"] = domain
    ok, rule_name = ruleset.decide(domain, payload)
    out["rule"] = rule_name
    if not ok:
        return out

    # 切点：域名起始位置之前 guard 字节；拿不到域名时用 min_cut
    pos = host_start if host_start else None
    if pos is None:
        cut = params.min_cut
    else:
        cut = max(params.min_cut, pos - params.guard)
        if pos and cut >= pos:
            cut = pos + 1                            # 落在域名内部，避免完整域名出现在首段
    if cut <= 0 or cut >= len(payload) - 1 or cut < min(params.min_cut, MEASURED_DEVICE_THRESHOLD):
        out["info"] = f"域名 {domain or '?'} 位置不合适（cut={cut}），跳过"
        return out

    packets = _split_into_segments(data[:payload_off], payload, cut, seq, tcp_off,
                                   ver, payload_off, params.mtu)
    out["packets"] = packets
    seg_note = "" if len(packets) == 2 else f"，其余拆成 {len(packets) - 1} 段"
    out["info"] = (f"{domain or '未知域名'}  首段 {cut}B{seg_note}"
                   f"  命中规则：{rule_name}")
    return out


# ------------------------------------------------------------------ 引擎
class Engine:
    """后台线程跑 WinDivert 循环；on_event(level, text) 上报事件"""

    def __init__(self, ruleset, params, on_event=None):
        self.ruleset = ruleset
        self.params = params
        self.on_event = on_event or (lambda level, text: None)
        self.stats = {"seen": 0, "split": 0, "sent": 0, "started": None, "last_domain": None}
        self._thread = None
        self._stop = threading.Event()
        self._handle = None
        self._lock = threading.Lock()

    # -- 对外接口
    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.running:
            return True
        dll = load_dll()
        flt = f"outbound and tcp and tcp.DstPort == {self.params.port}".encode()
        handle = dll.WinDivertOpen(flt, WINDIVERT_LAYER_NETWORK, 0, 0)
        if not handle or handle == ctypes.c_void_p(-1).value:
            err = ctypes.get_last_error()
            if err == 5:
                self.on_event("error", "打开过滤句柄失败：权限不足（需要管理员权限加载内核驱动）")
            else:
                self.on_event("error", f"打开过滤句柄失败：Win32 错误码 {err}")
            return False
        with self._lock:
            self._handle = handle
        self._stop.clear()
        self.stats.update(seen=0, split=0, sent=0, started=time.time())
        self.on_event("info", f"拦截已启动 · 模式 {self.ruleset.mode} · 端口 {self.params.port}"
                              f" · guard={self.params.guard} · min-cut={self.params.min_cut}")
        self._thread = threading.Thread(target=self._loop, args=(handle,), daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        dll = load_dll()
        with self._lock:
            handle, self._handle = self._handle, None
        if handle:
            try:
                dll.WinDivertClose(handle)      # 会让阻塞中的 recv 立即返回
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=3)
        self._thread = None
        self.on_event("info", f"拦截已停止（累计分片 {self.stats['split']} 次）")

    def selftest(self, host="zzz.mihoyo.com", timeout=8):
        """裸 socket 直连测试（不经过任何代理），返回 dict"""
        import ssl as _ssl
        res = {"host": host, "ok": False, "ms": None, "error": None}
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        t0 = time.perf_counter()
        try:
            ip = socket.gethostbyname(host)
            res["ip"] = ip
            with socket.create_connection((ip, int(self.params.port)), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    res["ok"] = True
                    res["ms"] = round((time.perf_counter() - t0) * 1000)
        except Exception as e:
            res["error"] = f"{type(e).__name__}: {e}"
            res["ms"] = round((time.perf_counter() - t0) * 1000)
        self.on_event("selftest", f"自检 {host}: {'直连成功 ' + str(res['ms']) + 'ms ✅' if res['ok'] else '失败 ❌ ' + str(res['error'])}")
        return res

    # -- 内部
    def _loop(self, handle):
        dll = load_dll()
        pkt = ctypes.create_string_buffer(65535)
        addr = ctypes.create_string_buffer(ADDR_SIZE)
        recv_len = ctypes.c_uint()
        while not self._stop.is_set():
            ok = dll.WinDivertRecv(handle, pkt, 65535, ctypes.byref(recv_len), addr)
            if not ok:
                if ctypes.get_last_error() == 995:      # 句柄被关闭
                    break
                continue
            data = pkt.raw[:recv_len.value]
            self.stats["seen"] += 1
            res = split_packet(data, self.ruleset, self.params)
            if res["info"]:
                self.stats["split"] += 1
                self.stats["last_domain"] = res["domain"]
                self.on_event("split", res["info"])
                for p in res["packets"]:
                    if self._send(dll, handle, addr, p):
                        self.stats["sent"] += 1
            else:
                if self._send(dll, handle, addr, data):
                    self.stats["sent"] += 1
        try:
            dll.WinDivertClose(handle)
        except Exception:
            pass

    def _send(self, dll, handle, addr, packet):
        buf = ctypes.create_string_buffer(packet, len(packet))
        dll.WinDivertHelperCalcChecksums(buf, len(packet), addr, 0)
        send_len = ctypes.c_uint()
        return bool(dll.WinDivertSend(handle, buf, len(packet), ctypes.byref(send_len), addr))
