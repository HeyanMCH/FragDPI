#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""doh_stub — 本地 DoH 存根解析器：把明文 DNS 换成加密 DNS（隐私模式的另一半）。

为什么要它：
    FragDPI 的隐私模式把 TLS SNI 藏起来了，但 **明文 DNS 是另一条泄露通道**。
    只要系统还在用 UDP 53 明文查询，链路上的设备照样知道你访问了哪些域名。

架构：

    应用 → 系统解析器(Dnscache) → 127.0.0.1:53（本存根） --HTTPS 443--> 阿里/腾讯 DoH
                                                          （RFC 8484 wireformat 透传）

    设备在链路上只能看到：到 DoH 服务器的一条 TLS 连接，域名查询本身全程加密。
    配合隐私模式的首包分片，连「你在访问 DoH 服务器」这件事的 SNI 都看不到。

关键实现选择：
    · 上游用 **IP 直连**（https://223.5.5.5/dns-query），不依赖域名解析 —— 否则要解析
      DoH 服务器自己的域名就先得用明文 DNS（引导问题）。
    · 转发用 RFC 8484 **wireformat**：DNS 报文原样透传，不做任何解析/重建，
      因此 A/AAAA/HTTPS/SVCB/TXT/DNSSEC/EDNS 全部天然兼容。
    · 显式 `ProxyHandler({})` 禁代理直连：DNS 不应该走 HTTP 代理。

⚠️ 安全设计（这个工具会改系统 DNS，所以复原优先于一切）：
    1. 切换前先把原配置写进 core/dns_backup.json
    2. 切换前先自检：存根必须真的通过 DoH 解析成功，才允许动系统设置
    3. 控制台退出 / 切离隐私模式时自动复原
    4. `restore_dns.cmd` 一键手动复原
    5. 下次启动若发现有残留备份（上次异常退出），先复原再干活

用法：
    python tools/doh_stub.py --test       # 自检：DoH 上游 + 本地存根
    python tools/doh_stub.py --serve      # 只起存根，不改系统 DNS
    python tools/doh_stub.py --on         # 起存根 + 把系统 DNS 切到 127.0.0.1
    python tools/doh_stub.py --off        # 复原系统 DNS
    python tools/doh_stub.py --status     # 查看当前状态
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORE = os.path.join(ROOT, "core")
if CORE not in sys.path:
    sys.path.insert(0, CORE)

try:
    import fragcore as fc            # 只为 init_console
except ImportError:
    fc = None

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 53
BACKUP_FILE = os.path.join(CORE, "dns_backup.json")
STUB_DNS = "127.0.0.1"

# 上游刻意用 IP 直连，避免「解析 DoH 域名需要明文 DNS」的引导问题
DOH_UPSTREAMS = [
    ("阿里 DoH", "https://223.5.5.5/dns-query"),
    ("腾讯 DoH", "https://120.53.53.53/dns-query"),
]

# 这些虚拟网卡不碰（它们通常也没有 DNS 配置，这里是双保险）
VIRTUAL_HINTS = ("vmware", "radmin", "letstap", "xray", "vethernet", "loopback",
                 "hyper-v", "virtualbox", "tap-", "wsl", "bluestacks", "mumu",
                 "_ldplayer", "nox")

TIMEOUT = 5.0


# ------------------------------------------------------------------ 工具
def _run(*args):
    """跑 netsh，返回 (rc, stdout+stderr)。CREATE_NO_WINDOW 防止闪黑窗。"""
    flags = 0x08000000 if os.name == "nt" else 0      # CREATE_NO_WINDOW
    p = subprocess.run(list(args), capture_output=True, creationflags=flags)
    return p.returncode, p.stdout.decode("utf-8", "replace") + \
        p.stderr.decode("utf-8", "replace")


def _decode(b):
    for enc in ("utf-8", "gbk"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode("utf-8", "replace")


# ------------------------------------------------------------------ 网卡与系统 DNS
def interfaces_state():
    """返回 {别名: 是否已连接}。netsh 的列顺序固定：管理状态 状态 类型 名称。"""
    rc, out = _run("netsh", "interface", "show", "interface")
    state = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        low = line.lower()
        if "disconn" in low or "已断开" in line:
            connected = False
        elif "conn" in low or "已连接" in line:
            connected = True
        else:
            continue
        # 名字可能含空格（“本地连接* 1”），取第 4 列起拼回来
        state[" ".join(parts[3:])] = connected
    return state


def dns_config():
    """返回 [{alias, dhcp, servers}]。netsh 输出按接口分段。

    中英文都能解析：接口头一行必有 "别名"；DHCP 段的行含 "DHCP"（两种语言都含）。
    """
    rc, out = _run("netsh", "interface", "ip", "show", "dnsservers")
    blocks, cur = [], None
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        if '"' in s:                       # 接口头：接口 "WLAN" 的配置 / Configuration for interface "WLAN"
            alias = s.split('"')[1] if s.count('"') >= 2 else None
            if alias:
                cur = {"alias": alias, "dhcp": False, "servers": []}
                blocks.append(cur)
            continue
        if cur is None:
            continue
        if "dhcp" in s.lower():            # “通过 DHCP 配置的 DNS 服务器” / "DNS servers configured through DHCP"
            cur["dhcp"] = True
        for tok in s.replace(":", " ").split():
            if tok.count(".") == 3 and all(p.isdigit() and 0 <= int(p) <= 255
                                           for p in tok.split(".")):
                cur["servers"].append(tok)
    return blocks


def dns_targets():
    """返回应该被接管的接口：已连接 + 有 DNS + 非虚拟网卡。"""
    st = interfaces_state()
    out = []
    for b in dns_config():
        alias = b["alias"]
        low = alias.lower()
        if any(h in low for h in VIRTUAL_HINTS):
            continue
        if not b["servers"]:
            continue
        if not st.get(alias):
            continue                        # 未连接的网卡不碰
        out.append(b)
    return out


def _netsh_set_static(alias, server):
    return _run("netsh", "interface", "ip", "set", "dnsservers",
                f"name={alias}", "source=static", f"address={server}",
                "validate=no")


def backup_dns():
    """把目标接口的当前 DNS 配置写进备份文件。返回备份 dict 或 None。"""
    targets = dns_targets()
    if not targets:
        return None
    backup = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "interfaces": targets}
    with open(BACKUP_FILE, "w", encoding="utf-8") as f:
        json.dump(backup, f, ensure_ascii=False, indent=2)
    return backup


def load_backup():
    try:
        with open(BACKUP_FILE, encoding="utf-8") as f:
            b = json.load(f)
        return b if isinstance(b.get("interfaces"), list) else None
    except (OSError, ValueError):
        return None


def restore_dns(quiet=False):
    """按备份文件复原系统 DNS。返回 (ok, 详情)。"""
    backup = load_backup()
    if not backup:
        return (False, "没有可复原的备份")
    errors = []
    for it in backup["interfaces"]:
        alias, servers = it["alias"], it["servers"]
        if it.get("dhcp") or not servers:
            rc, out = _run("netsh", "interface", "ip", "set", "dnsservers",
                           f"name={alias}", "source=dhcp", "validate=no")
            if rc != 0:
                errors.append(f"{alias}: {out.strip()[:80]}")
        else:
            rc, out = _netsh_set_static(alias, servers[0])
            if rc != 0:
                errors.append(f"{alias}: {out.strip()[:80]}")
                continue
            for extra in servers[1:]:
                _run("netsh", "interface", "ip", "add", "dnsservers",
                     f"name={alias}", f"address={extra}", "validate=no")
    try:
        os.remove(BACKUP_FILE)
    except OSError:
        pass
    if errors:
        return (False, "; ".join(errors))
    return (True, "已复原 %d 个接口" % len(backup["interfaces"]))


def switch_dns():
    """把目标接口的 DNS 切到 127.0.0.1（先备份）。返回 (ok, 详情)。"""
    if not dns_targets():
        return (False, "没有找到可接管的网卡（需要已连接且配置了 DNS 的物理网卡）")
    backup = backup_dns()
    if backup is None:
        return (False, "备份原配置失败")
    errors = []
    for it in backup["interfaces"]:
        rc, out = _netsh_set_static(it["alias"], STUB_DNS)
        if rc != 0:
            errors.append(f"{it['alias']}: {out.strip()[:80]}")
    if errors:                              # 切换失败 → 立刻复原，不留半改状态
        restore_dns(quiet=True)
        return (False, "; ".join(errors))
    return (True, "已接管 %d 个接口：%s" %
            (len(backup["interfaces"]), ", ".join(i["alias"] for i in backup["interfaces"])))


# ------------------------------------------------------------------ DoH 上游
def doh_resolve_wire(url, wire, timeout=TIMEOUT):
    """RFC 8484：POST 原始 DNS 报文，返回原始响应。失败抛异常。"""
    req = urllib.request.Request(
        url, data=wire, method="POST",
        headers={"Content-Type": "application/dns-message",
                 "Accept": "application/dns-message"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        body = r.read()
    if len(body) < 12 or body[:2] != wire[:2]:
        raise ValueError("DoH 响应异常（长度 %d / 事务 ID 不匹配）" % len(body))
    return body


# ------------------------------------------------------------------ 存根
class DohStub:
    """本地 DoH 转发器：127.0.0.1:53（UDP + TCP）。

    事件通过 on_event(kind, text) 上报；kind ∈ start/stop/query/error。
    stats 里 deliberately 不记录查询过的域名（这是隐私工具，别自打脸）。
    """

    def __init__(self, upstreams=None, on_event=None):
        self.upstreams = upstreams or DOH_UPSTREAMS
        self.on_event = on_event or (lambda k, t: None)
        self.stats = {"queries": 0, "answered": 0, "failed": 0,
                      "consecutive_fail": 0, "started": None}
        self._stop = threading.Event()
        self._threads = []
        self._socks = []
        self._sem = threading.BoundedSemaphore(16)     # 限制并发，防止线程爆炸
        self._lock = threading.Lock()
        self._up_idx = 0                               # 记住上次成功的上游（粘性）

    @property
    def running(self):
        return any(t.is_alive() for t in self._threads)

    def start(self):
        if self.running:
            return True
        self._stop.clear()
        for family, kind in ((socket.SOCK_DGRAM, "udp"), (socket.SOCK_STREAM, "tcp")):
            try:
                s = socket.socket(socket.AF_INET, family)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((LISTEN_HOST, LISTEN_PORT))
                if family == socket.SOCK_STREAM:
                    s.listen(8)
                self._socks.append(s)
            except OSError as e:
                self.on_event("error", f"绑定 {LISTEN_HOST}:{LISTEN_PORT}/{kind} 失败：{e}")
                self.stop()
                return False
        with self._lock:
            self.stats.update(queries=0, answered=0, failed=0, consecutive_fail=0,
                              started=time.time())
        t1 = threading.Thread(target=self._udp_loop, args=(self._socks[0],), daemon=True)
        t2 = threading.Thread(target=self._tcp_loop, args=(self._socks[1],), daemon=True)
        self._threads = [t1, t2]
        t1.start()
        t2.start()
        self.on_event("start", f"本地 DoH 存根已启动 · {LISTEN_HOST}:{LISTEN_PORT}"
                               f" · 上游 {' / '.join(n for n, _ in self.upstreams)}")
        return True

    def stop(self):
        self._stop.set()
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        self._socks = []
        for t in self._threads:
            t.join(timeout=2)
        if self._threads:
            self.on_event("stop", f"DoH 存根已停止（处理 {self.stats['queries']} 次，"
                                  f"失败 {self.stats['failed']} 次）")
        self._threads = []

    # -- 转发
    def _forward(self, wire):
        """按顺序试上游，返回响应 bytes 或 None。"""
        n = len(self.upstreams)
        for k in range(n):
            idx = (self._up_idx + k) % n
            name, url = self.upstreams[idx]
            try:
                body = doh_resolve_wire(url, wire)
                self._up_idx = idx
                return body
            except Exception as e:
                self.on_event("error", f"DoH 上游 {name} 失败：{type(e).__name__}")
        return None

    def _udp_loop(self, s):
        while not self._stop.is_set():
            try:
                wire, addr = s.recvfrom(4096)
            except OSError:
                break
            threading.Thread(target=self._udp_one, args=(s, wire, addr), daemon=True).start()

    def _udp_one(self, s, wire, addr):
        with self._sem:
            if self._stop.is_set():
                return
            with self._lock:
                self.stats["queries"] += 1
            body = self._forward(wire)
            if body:
                with self._lock:
                    self.stats["answered"] += 1
                    self.stats["consecutive_fail"] = 0
                try:
                    s.sendto(body, addr)
                except OSError:
                    pass
            else:
                with self._lock:
                    self.stats["failed"] += 1
                    self.stats["consecutive_fail"] += 1

    def _tcp_loop(self, s):
        while not self._stop.is_set():
            try:
                conn, _ = s.accept()
            except OSError:
                break
            threading.Thread(target=self._tcp_one, args=(conn,), daemon=True).start()

    def _tcp_one(self, conn):
        try:
            conn.settimeout(TIMEOUT)
            hdr = self._recv_exact(conn, 2)
            if not hdr:
                return
            n = int.from_bytes(hdr, "big")
            if n <= 0 or n > 65535:
                return
            wire = self._recv_exact(conn, n)
            if not wire:
                return
            with self._sem:
                with self._lock:
                    self.stats["queries"] += 1
                body = self._forward(wire)
                if body:
                    with self._lock:
                        self.stats["answered"] += 1
                        self.stats["consecutive_fail"] = 0
                    conn.sendall(len(body).to_bytes(2, "big") + body)
                else:
                    with self._lock:
                        self.stats["failed"] += 1
                        self.stats["consecutive_fail"] += 1
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # -- 自检
    def health_check(self, domain="www.baidu.com"):
        """端到端自检：向 127.0.0.1:53 发一次真实查询，走完整存根链路。"""
        try:
            from dns_leak_check import build_query, parse_a_records
        except ImportError:
            sys.path.insert(0, HERE)
            from dns_leak_check import build_query, parse_a_records
        _tid, wire = build_query(domain)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(TIMEOUT)
        try:
            s.sendto(wire, (LISTEN_HOST, LISTEN_PORT))
            data, _ = s.recvfrom(4096)
            rcode, answers = parse_a_records(data)
            return {"ok": bool(answers) or rcode == 0, "rcode": rcode,
                    "answers": answers, "error": None}
        except OSError as e:
            return {"ok": False, "rcode": None, "answers": [], "error": str(e)}
        finally:
            s.close()


# ------------------------------------------------------------------ CLI
def main():
    if fc:
        fc.init_console()
    ap = argparse.ArgumentParser(description="本地 DoH 存根（隐私模式的加密 DNS）")
    ap.add_argument("--test", action="store_true", help="自检 DoH 上游 + 本地存根")
    ap.add_argument("--serve", action="store_true", help="只起存根，不改系统 DNS")
    ap.add_argument("--on", action="store_true", help="起存根 + 接管系统 DNS（先备份）")
    ap.add_argument("--off", action="store_true", help="复原系统 DNS")
    ap.add_argument("--status", action="store_true", help="查看状态")
    args = ap.parse_args()

    if args.status:
        st = interfaces_state()
        print("接口状态：")
        for a, c in st.items():
            print("  %-28s %s" % (a, "已连接" if c else "未连接"))
        print("\n当前 DNS 配置：")
        for b in dns_config():
            if b["servers"] or b["dhcp"]:
                print("  %-28s %-6s %s" % (b["alias"], "DHCP" if b["dhcp"] else "静态",
                                           ", ".join(b["servers"]) or "(无)"))
        print("\n接管目标：", [b["alias"] for b in dns_targets()] or "(无)")
        print("备份文件：", "存在" if load_backup() else "无")
        return 0

    if args.off:
        ok, msg = restore_dns()
        print(("✓ " if ok else "✗ ") + msg)
        return 0 if ok else 1

    if args.test:
        print("== DoH 上游自检 ==")
        from dns_leak_check import build_query, parse_a_records
        _t, wire = build_query("www.baidu.com")
        for name, url in DOH_UPSTREAMS:
            try:
                body = doh_resolve_wire(url, wire)
                rc, ans = parse_a_records(body)
                print("  ✓ %-8s %d bytes  rcode=%s  %s" % (name, len(body), rc, ",".join(ans)))
            except Exception as e:
                print("  ✗ %-8s %s: %s" % (name, type(e).__name__, e))
        print("\n== 本地存根自检（127.0.0.1:53 必须先在跑）==")
        stub = DohStub()
        if stub.health_check()["ok"]:
            print("  ✓ 存根链路可用")
        else:
            print("  ✗ 存根不可用（未启动或上游全挂）")
        return 0

    if args.on:
        stub = DohStub(on_event=lambda k, t: print(f"  [{k}] {t}"))
        if not stub.start():
            print("✗ 存根启动失败")
            return 1
        time.sleep(0.3)
        h = stub.health_check()
        if not h["ok"]:
            print("✗ 存根自检失败，不接管系统 DNS：%s" % h["error"])
            stub.stop()
            return 1
        ok, msg = switch_dns()
        print(("✓ " if ok else "✗ ") + msg)
        if not ok:
            stub.stop()
            return 1
        print("已接管。复原：python tools/doh_stub.py --off   或  双击 restore_dns.cmd")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            restore_dns()
            stub.stop()
        return 0

    if args.serve:
        stub = DohStub(on_event=lambda k, t: print(f"  [{k}] {t}"))
        if not stub.start():
            return 1
        print(f"存根已监听 {LISTEN_HOST}:{LISTEN_PORT}（未接管系统 DNS）")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            stub.stop()
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
