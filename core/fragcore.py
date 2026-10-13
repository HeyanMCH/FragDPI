#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fragcore — 首包分片引擎核心（WinDivert）

职责：
  1. ctypes 绑定 WinDivert 2.2.2 x64
  2. 从 ClientHello 里**解析出真实 SNI 域名**（规则系统的基础）
  3. 规则系统：模式 off / rules / global / privacy，规则类型 suffix / keyword
  4. 分片：把承载 ClientHello 的首个 TCP 报文切成多段，重算校验和后重注入
  5. Engine：后台线程跑抓包循环，事件通过回调上报

关于 privacy 模式（隐私保护模式）：
  · 对所有 TLS ClientHello 分片（不看域名、不匹配规则），让链路上的中间设备读不到 SNI
  · **域名绝不外泄**：`split_packet` 返回的 domain 恒为 None，事件文本里不含域名
  · 但 SNI 解析**仍然必须做** —— 切点位置依赖域名起始偏移，不解析就不知道切哪
  · ⚠️ 它只能藏 SNI，藏不了明文 DNS / 目的 IP / 服务器证书 / JA3 指纹

实测约束（2026-10-12，某校园网行为管理设备）：
  · 设备会把前几个报文攒到 **114 字节**再查：首段 <= 113 必被拦，>= 114 即通过
  · 且切割点必须落在 SNI 扩展内部（域名之前），否则关键词会完整出现在首段
  · 因此 cut = max(min_cut, 域名起始位置 - guard)
"""
import ctypes
import os
import random
import socket
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WINDIVERT_LAYER_NETWORK = 0
ADDR_SIZE = 128
MEASURED_DEVICE_THRESHOLD = 114  # 实测：首段 <=113 被拦

# privacy 模式的随机切点用系统熵源（不是 Mersenne Twister）——目的是让分段方式
# 不可预测，做一个可被设备学习的稳定签名是没意义的。
_rng = random.SystemRandom()

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


# ------------------------------------------------------------------ 驱动清理
# ⚠️ 为什么需要这一段：
#   WinDivert 2.2 的 DLL **不导出任何卸载接口**（WinDivertUninstall 之类都不存在），
#   驱动装卸完全藏在 WinDivertOpen/WinDivertClose 内部。实测有两个后果：
#     1. WinDivertOpen 会创建名为 `WinDivert` 的内核服务，其 ImagePath 直接指向
#        **本仓库里的 third_party/windivert/WinDivert64.sys**。驱动一旦加载，
#        内核就锁住这个文件 —— 于是整个文件夹删不掉（用户实际踩到的 bug）。
#     2. WinDivertOpen 失败（例如被内存完整性 HVCI 拦下，Win32=1450）时，
#        服务已经建好了却**不会回滚**，留下一个 STOPPED 的孤儿服务。
#   所以我们必须自己在停止/退出时把服务停掉并删除。
SERVICE_NAME = "WinDivert"
_SERVICE_STOPPED = 1
_SERVICE_RUNNING = 4

_SC_MANAGER_CONNECT = 0x0001
_SC_MANAGER_ALL_ACCESS = 0xF003F
_SERVICE_QUERY_STATUS = 0x0004
_SERVICE_STOP = 0x0020
_SERVICE_DELETE = 0x10000
_ERROR_SERVICE_MARKED_FOR_DELETE = 1072
_ERROR_SERVICE_DOES_NOT_EXIST = 1060


class _SERVICE_STATUS(ctypes.Structure):
    _fields_ = [("dwServiceType", ctypes.c_ulong),
                ("dwCurrentState", ctypes.c_ulong),
                ("dwControlsAccepted", ctypes.c_ulong),
                ("dwWin32ExitCode", ctypes.c_ulong),
                ("dwServiceSpecificExitCode", ctypes.c_ulong),
                ("dwCheckPoint", ctypes.c_ulong),
                ("dwWaitHint", ctypes.c_ulong)]


def _open_scm(access=_SC_MANAGER_CONNECT):
    """打开服务管理器。

    ⚠️ 查询用 SC_MANAGER_CONNECT（非管理员也能开），删除才用 ALL_ACCESS。
    早先一律用 ALL_ACCESS 时，非管理员这边 `OpenSCManagerW` 直接返回 NULL，
    于是 `driver_service_state()` 把「没权限」误报成「服务不存在」——
    会让用户以为已经干净了。这个坑踩过一次，别再合并这两级权限。
    """
    adv = ctypes.windll.advapi32
    adv.OpenSCManagerW.restype = ctypes.c_void_p
    adv.OpenSCManagerW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
    adv.OpenServiceW.restype = ctypes.c_void_p
    adv.OpenServiceW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
    adv.CloseServiceHandle.argtypes = [ctypes.c_void_p]
    return adv, adv.OpenSCManagerW(None, None, access)


def driver_service_state(name=SERVICE_NAME):
    """返回 None=服务不存在 / 状态码（1=SERVICE_STOPPED，4=SERVICE_RUNNING）。

    只用 SCM API —— 本机把 sc.exe 拉进了程序黑名单，不能靠命令行。
    查询只需要 CONNECT，所以非管理员也能拿到真实状态。
    """
    try:
        adv, scm = _open_scm(_SC_MANAGER_CONNECT)
        if not scm:
            return None
        try:
            h = adv.OpenServiceW(ctypes.c_void_p(scm), name, _SERVICE_QUERY_STATUS)
            if not h:
                return None
            try:
                st = _SERVICE_STATUS()
                if not adv.QueryServiceStatus(ctypes.c_void_p(h), ctypes.byref(st)):
                    return None
                return int(st.dwCurrentState)
            finally:
                adv.CloseServiceHandle(ctypes.c_void_p(h))
        finally:
            adv.CloseServiceHandle(ctypes.c_void_p(scm))
    except Exception:
        return None


def uninstall_driver(name=SERVICE_NAME):
    """停止并删除 WinDivert 驱动服务，释放被内核锁住的 WinDivert64.sys。

    返回 (ok, 说明)。幂等：服务不存在也算成功。
    """
    state = driver_service_state(name)
    if state is None:
        return (True, "驱动服务不存在，无需清理")
    if state == _SERVICE_RUNNING:
        # 说明还有进程在用（可能是本程序，也可能是别的 WinDivert 程序）
        pass
    adv, scm = _open_scm(_SC_MANAGER_ALL_ACCESS)      # 删除需要 ALL_ACCESS
    if not scm:
        err = ctypes.get_last_error()
        if err == 5:
            return (False, "打开服务管理器失败：需要管理员权限")
        return (False, f"打开服务管理器失败：Win32={err}")
    try:
        h = adv.OpenServiceW(ctypes.c_void_p(scm), name,
                             _SERVICE_STOP | _SERVICE_QUERY_STATUS | _SERVICE_DELETE)
        if not h:
            err = ctypes.get_last_error()
            if err == _ERROR_SERVICE_DOES_NOT_EXIST:
                return (True, "驱动服务不存在，无需清理")
            return (False, f"打开驱动服务失败：Win32={err}")
        try:
            stopped = True
            if state == _SERVICE_RUNNING:
                st = _SERVICE_STATUS()
                adv.ControlService(ctypes.c_void_p(h), _SERVICE_STOP, ctypes.byref(st))
                # 等服务真正停下（最多 3s）
                for _ in range(30):
                    time.sleep(0.1)
                    if adv.QueryServiceStatus(ctypes.c_void_p(h), ctypes.byref(st)) \
                            and st.dwCurrentState == _SERVICE_STOPPED:
                        break
                else:
                    stopped = False
            ok = bool(adv.DeleteService(ctypes.c_void_p(h)))
            err = ctypes.get_last_error()
            if not ok:
                if err == _ERROR_SERVICE_MARKED_FOR_DELETE:
                    return (True, "驱动服务已标记删除（重启后彻底消失）")
                return (False, f"删除驱动服务失败：Win32={err}")
            note = "已停止并删除 WinDivert 驱动服务"
            if not stopped:
                note = "已请求停止并删除 WinDivert 驱动服务（可能需重启才彻底释放）"
            return (True, note)
        finally:
            adv.CloseServiceHandle(ctypes.c_void_p(h))
    finally:
        adv.CloseServiceHandle(ctypes.c_void_p(scm))


def hvci_enabled():
    """内存完整性 / HVCI 是否开启。

    实测（2026-10-13，本机）：开着 HVCI 时 WinDivertOpen 直接失败 Win32=1450
    （ERROR_NO_SYSTEM_RESOURCES），驱动根本进不了内核 —— 本程序会完全失效。
    返回值：True / False / None（读不到注册表）
    """
    try:
        import winreg
        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios"
                r"\HypervisorEnforcedCodeIntegrity") as k:
            return bool(winreg.QueryValueEx(k, "Enabled")[0])
    except Exception:
        return None


def cleanup_stale_driver(name=SERVICE_NAME):
    """**安全清理**：只在服务处于 STOPPED 时删除它。

    为什么不无条件删：如果有别的程序（zapret / 其他 WinDivert 应用）正在用这个驱动，
    服务会是 RUNNING —— 那说明不是残留，删了会打断别人。RUNNING 时一律不动手。

    返回 (ok, 说明)。ok=True 且说明里带「跳过」表示没动手。
    """
    state = driver_service_state(name)
    if state is None:
        return (True, "没有残留")
    if state == _SERVICE_RUNNING:
        return (True, "驱动正在被使用（服务状态 RUNNING），跳过清理")
    return uninstall_driver(name)


def driver_leftovers():
    """检查驱动残留 + 会拦截驱动的系统设置。返回 dict，供 UI / CLI 显示。"""
    state = driver_service_state()
    sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                         "System32", "drivers", "WinDivert.sys")
    return {
        "service_exists": state is not None,
        "service_state": state,
        "service_state_name": {1: "STOPPED", 4: "RUNNING"}.get(state, str(state)),
        "service_running": state == _SERVICE_RUNNING,
        "sys32_driver": sys32 if os.path.exists(sys32) else None,
        "hvci": hvci_enabled(),
    }


def init_console():
    """把 stdout/stderr 切到 UTF-8，避免中文在「被重定向」时把脚本弄崩。

    Python 3.6+ 在真控制台上通过 WriteConsoleW 输出，中文永远正常；但一旦输出被重定向
    到管道或文件（`> log.txt`、CI 捕获输出），编码就退化成系统 ANSI 代码页：中文
    Windows 是 cp936（能编码中文，没事），英文 Windows 是 cp1252 —— 编不了中文，
    直接 UnicodeEncodeError 把脚本弄崩。

    这不是理论问题。GitHub Actions 的 Windows runner 上，8 个单测 job 全过，只有
    `tools/fragdpi.py --packettest` 挂了，就是因为它的输出被 CI 捕获：
        UnicodeEncodeError: 'charmap' codec can't encode characters in position 0-1
    本地一行即可复现：
        PYTHONIOENCODING=cp1252 python tools/fragdpi.py --packettest

    处理方式：主动切 UTF-8。这样重定向出去的产物是干净的 UTF-8（而不是把中文降级成
    '?'），而真控制台本来就是 UTF-8，等于没做事。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            try:                       # 极少数流不支持改编码，至少别让它崩
                stream.reconfigure(errors="replace")
            except Exception:
                pass


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
    """mode: off（不拦截）| rules（按规则）| global（全部 TLS）| privacy（隐私保护）

    global 与 privacy 都是「对所有 TLS 分片」，区别在于**是否留下域名痕迹**：
      · global  —— 仍会解析并**记录**域名（用于事件日志和"最近命中域名"展示）
      · privacy —— 不记录任何域名，事件文本里也不含域名；且不遍历规则（不做命中计数）
    换句话说：global 解决的是「连不上」，privacy 解决的是「别被记录」。
    """

    MODES = ("off", "rules", "global", "privacy")

    def __init__(self, mode="rules", rules=None):
        self.mode = mode if mode in self.MODES else "rules"
        self.rules = rules if rules is not None else default_rules()

    def decide(self, domain, raw):
        """返回 (是否分片, 命中的规则名)"""
        if self.mode == "off":
            return (False, None)
        if self.mode == "privacy":
            # 刻意**不遍历规则**：既省 CPU，也避免 hits 计数间接暴露"访问了哪一类站点"
            return (True, "隐私模式")
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
    def __init__(self, guard=6, min_cut=124, mtu=1500, port=443,
                 random_cut=False, ports=None):
        self.guard = guard
        self.min_cut = min_cut
        self.mtu = mtu
        self.port = int(port)
        # privacy 用：切点在合法窗口内随机取（默认关 —— 见 _cut_point 的说明）
        self.random_cut = bool(random_cut)
        # 附加 TLS 端口（主端口之外的，如 8443 / 2053）
        self.ports = [int(p) for p in (ports or [])]

    def port_list(self):
        """去重后的端口列表，主端口排第一。"""
        seen, out = set(), []
        for p in [self.port] + list(self.ports):
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out

    def to_dict(self):
        return {"guard": self.guard, "min_cut": self.min_cut, "mtu": self.mtu,
                "port": self.port, "random_cut": self.random_cut,
                "ports": self.ports}

    @staticmethod
    def from_dict(d):
        return Params(int(d.get("guard", 6)), int(d.get("min_cut", 124)),
                      int(d.get("mtu", 1500)), int(d.get("port", 443)),
                      bool(d.get("random_cut", False)), d.get("ports") or [])


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


def _cut_point(host_start, params):
    """算切点偏移。

    非随机模式（默认）与改造前**逐字节等价**：
        cut = max(min_cut, host_start - guard)；若已切进域名，则取 host_start + 1

    随机模式（privacy 可选）在**合法窗口**内取随机值：
        [max(min_cut, MEASURED_DEVICE_THRESHOLD), host_start - 1]
    下界来自实测（首段 <= 113 被拦），上界保证完整域名不进首段。
    窗口为空（域名起始位置太靠前）时**回退到固定逻辑**，不抛异常。

    ⚠️ 随机模式默认关闭。现有实测只证明了「后缀 >= 114 通过」这一个边界点，
    并没有验证窗口内**每一个** cut 值都能过；设备行为若不单调，随机切点会随机失败。
    开启前请先跑 tools/scan_window.py 做全窗口扫描。
    """
    if host_start is None:
        return params.min_cut
    if params.random_cut:
        lo = max(params.min_cut, MEASURED_DEVICE_THRESHOLD)
        hi = host_start - 1
        if hi >= lo:
            return _rng.randint(lo, hi)
    cut = max(params.min_cut, host_start - params.guard)
    if cut >= host_start:
        cut = host_start + 1                 # 落在域名内部，避免完整域名出现在首段
    return cut


def split_packet(data, ruleset, params):
    """按规则决定是否分片。返回 dict(packets, info, domain, rule)

    privacy 模式下 `domain` 恒为 None、`info` 不含域名 —— 这是隐私保护模式的**契约**，
    有单测守着，不要为了方便调试把它改回去。
    """
    out = {"packets": [data], "info": None, "domain": None, "rule": None}
    privacy = (ruleset.mode == "privacy")
    r = inspect(data)
    if not r:
        return out
    ver, payload_off, payload, seq, tcp_off, total = r
    if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
        return out                                  # 只处理 ClientHello

    # SNI 一定要解析（切点位置依赖 host_start），但 privacy 下结果只在本函数内存活
    domain, host_start, host_end = parse_sni(payload)
    ok, rule_name = ruleset.decide(domain, payload)
    out["rule"] = rule_name
    if not privacy:
        out["domain"] = domain
    if not ok:
        return out

    cut = _cut_point(host_start, params)
    if cut <= 0 or cut >= len(payload) - 1 or cut < min(params.min_cut, MEASURED_DEVICE_THRESHOLD):
        if privacy:
            out["info"] = f"TLS 位置不合适（cut={cut}），跳过分片"
        else:
            out["info"] = f"域名 {domain or '?'} 位置不合适（cut={cut}），跳过"
        return out

    packets = _split_into_segments(data[:payload_off], payload, cut, seq, tcp_off,
                                   ver, payload_off, params.mtu)
    out["packets"] = packets
    if privacy:
        out["info"] = f"TLS 出站分片 · 首段 {cut}B（域名已隐去）"
        return out
    seg_note = "" if len(packets) == 2 else f"，其余拆成 {len(packets) - 1} 段"
    out["info"] = (f"{domain or '未知域名'}  首段 {cut}B{seg_note}"
                   f"  命中规则：{rule_name}")
    return out


def build_filter(params):
    """生成 WinDivert 过滤表达式（抽成独立函数，便于单测）。"""
    ports = params.port_list()
    expr = " or ".join(f"tcp.DstPort == {int(p)}" for p in ports)
    return f"outbound and tcp and ({expr})"


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
        # 启动前先清掉上次异常退出留下的孤儿服务。
        # ⚠️ 只在服务是 STOPPED 时才动手 —— RUNNING 说明有别的程序在用这个驱动。
        try:
            _ok, _msg = cleanup_stale_driver()
            if "没有残留" not in _msg and "跳过" not in _msg:
                self.on_event("info", f"启动前清理驱动残留：{_msg}")
        except Exception:
            pass
        ports = self.params.port_list()
        flt = build_filter(self.params).encode()
        handle = dll.WinDivertOpen(flt, WINDIVERT_LAYER_NETWORK, 0, 0)
        if not handle or handle == ctypes.c_void_p(-1).value:
            err = ctypes.get_last_error()
            if err == 5:
                self.on_event("error", "打开过滤句柄失败：权限不足（需要管理员权限加载内核驱动）")
            elif err == 1450:
                self.on_event("error",
                              "打开过滤句柄失败：Win32=1450（ERROR_NO_SYSTEM_RESOURCES）。"
                              "这几乎总是「内存完整性」（内核隔离 / HVCI）拦下了 WinDivert 驱动 —— "
                              "WinDivert 2.2.2 已是上游最新版，没有可升级的版本，"
                              "本机若不关掉它，本程序无法工作。"
                              "关法：设置 → 隐私和安全性 → Windows 安全中心 → 设备安全性 → "
                              "内核隔离 → 关闭「内存完整性」并重启（会降低系统安全性，请自行权衡）。")
            else:
                self.on_event("error", f"打开过滤句柄失败：Win32 错误码 {err}")
            return False
        with self._lock:
            self._handle = handle
        self._stop.clear()
        self.stats.update(seen=0, split=0, sent=0, started=time.time(), last_domain=None)
        self.on_event("info", f"拦截已启动 · 模式 {self.ruleset.mode}"
                              f" · 端口 {','.join(str(p) for p in ports)}"
                              f" · guard={self.params.guard} · min-cut={self.params.min_cut}")
        self._thread = threading.Thread(target=self._loop, args=(handle,), daemon=True)
        self._thread.start()
        return True

    def stop(self, cleanup_driver=False):
        """停止拦截。

        cleanup_driver=True 时会顺带把 WinDivert 服务停掉并删除 —— 这是为了修
        「用过之后仓库文件夹删不掉」那个 bug：服务的 ImagePath 指向本仓库里的
        WinDivert64.sys，驱动加载期间内核会锁住它。默认 False 是为了让界面上
        频繁的启停保持轻快；控制台退出与命令行工具退出时会显式打开它。
        """
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
        if cleanup_driver:
            try:
                ok, msg = cleanup_stale_driver()
                self.on_event("info" if ok else "warn", f"驱动清理：{msg}")
            except Exception as e:
                self.on_event("warn", f"驱动清理失败：{type(e).__name__}: {e}")
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
                if res["domain"] is not None:      # privacy 模式下恒为 None，不留痕
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
