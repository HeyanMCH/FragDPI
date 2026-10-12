#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fragserver — 首包分片引擎 · 可视化控制台（本地 Web GUI）

在 fragcore 引擎之上提供：
  · 三种工作模式：关闭 / 规则模式 / 全局模式
  · 规则系统：域名后缀规则 + 关键词规则，可增删改、单独启停、命中计数
  · 参数面板：guard / min-cut / mtu / 端口
  · 实时统计 + 事件日志流
  · 一键自检（裸直连测试）/ 启停拦截

只监听 127.0.0.1，不对外暴露。需要管理员权限（WinDivert 要加载内核驱动）。
"""
import collections
import json
import os
import re
import sys
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import fragcore as fc

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)          # 保证从任意工作目录启动都能 import fragcore
CONFIG_PATH = os.path.join(HERE, "fragconfig.json")
HTML_PATH = os.path.join(HERE, "console.html")
BIND_HOST = "127.0.0.1"
BIND_PORT = 8899

# DNS 泄露自检（隐私模式的配套）放在 tools/ 下，这里按需加载，缺了也不影响控制台
TOOLS_DIR = os.path.join(os.path.dirname(HERE), "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)
try:
    import dns_leak_check as _dlc
except Exception:                     # 模块不在（比如只拷了 core/）时降级
    _dlc = None
try:
    import doh_stub as _doh           # 本地 DoH 存根（加密 DNS）
except Exception:
    _doh = None

MODE_LABEL = {"off": "关闭", "rules": "规则模式",
              "global": "全局模式", "privacy": "隐私模式"}

# 隐私模式下的**兜底脱敏**：split_packet 层面已经不含域名了，这里再加一道，
# 防止将来别处又把域名塞进事件文本。排除常见文件扩展名，避免误伤 "console.html"。
_HOSTNAME_RE = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+([a-z]{2,24})(?![\w-])",
                          re.IGNORECASE)
_FILE_TLDS = {"html", "htm", "json", "py", "txt", "md", "cmd", "bat", "dll", "sys",
              "log", "yaml", "yml", "ini", "cfg", "conf", "exe", "js", "css", "local"}


def redact_hosts(text):
    """把疑似主机名替换成 <域名>。"""
    def _sub(m):
        return m.group(0) if m.group(1).lower() in _FILE_TLDS else "<域名>"
    return _HOSTNAME_RE.sub(_sub, text)


def parse_ports(value):
    """把 "443,8443 2053" 这类输入解析成去重后的端口列表（保持顺序）。"""
    if isinstance(value, (list, tuple)):
        raw = list(value)
    else:
        raw = re.split(r"[,，;；\s]+", str(value or ""))
    out, seen = [], set()
    for item in raw:
        s = str(item).strip()
        if not s:
            continue
        p = int(s)                        # 非法值抛 ValueError，由调用方兜住
        if not (1 <= p <= 65535):
            raise ValueError("端口超出范围：%s" % s)
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


# ------------------------------------------------------------------ 配置
def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_config(cfg):
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CONFIG_PATH)


# ------------------------------------------------------------------ 控制台状态
class Console:
    def __init__(self):
        cfg = load_config()
        self.ruleset = fc.RuleSet.from_dict(cfg.get("ruleset", {}))
        self.params = fc.Params.from_dict(cfg.get("params", {}))
        priv = cfg.get("privacy", {})
        # 隐私模式退出时自动清空事件日志（默认开 —— 符合隐私模式的语义）
        self.clear_on_exit = bool(priv.get("clear_on_exit", True))
        # 隐私模式自动启用加密 DNS（默认开 —— 用户指定；只藏 SNI 不藏 DNS 只有半个隐私）
        self.dns_encrypt = bool(priv.get("dns_encrypt", True))
        self.dns_stub = None            # 运行中的 DoH 存根
        self.dns_switched = False       # 是否改了系统 DNS（改了才需要复原）
        self.dns_watchdog = None
        self._dns_lock = threading.Lock()
        self.events = collections.deque(maxlen=500)
        self._eid = 0
        self._lock = threading.Lock()
        self.last_selftest = None
        self.last_dnscheck = None
        self.engine = fc.Engine(self.ruleset, self.params, on_event=self.log)
        # 规则命中计数在 fragcore 内部累加，这里只做快照展示

    @property
    def privacy(self):
        return self.ruleset.mode == "privacy"

    # -- 事件
    def log(self, level, text):
        if self.privacy and level == "split":
            text = redact_hosts(text)          # 兜底：就算上游漏了域名也挡住
        with self._lock:
            self._eid += 1
            self.events.append({
                "id": self._eid,
                "t": time.strftime("%H:%M:%S"),
                "level": level,
                "text": text,
            })

    def events_since(self, since):
        with self._lock:
            return [e for e in self.events if e["id"] > since]

    # -- 持久化
    def persist(self):
        save_config({
            "ruleset": self.ruleset.to_dict(),
            "params": self.params.to_dict(),
            "privacy": {"clear_on_exit": self.clear_on_exit,
                        "dns_encrypt": self.dns_encrypt},
        })

    def privacy_state(self):
        return {
            "active": self.privacy,
            "random_cut": self.params.random_cut,
            "ports": self.params.port_list(),
            "clear_on_exit": self.clear_on_exit,
            "dns_encrypt": self.dns_encrypt,
            "dns_active": self.dns_stub is not None,
            "dns_switched": self.dns_switched,
        }

    # -- 加密 DNS（隐私模式的另一半）
    def enable_encrypted_dns(self):
        """起 DoH 存根 + 接管系统 DNS。任何一步失败都不留半改状态。"""
        if _doh is None:
            self.log("error", "DoH 存根模块不可用（tools/doh_stub.py 缺失）")
            return False
        with self._dns_lock:
            if self.dns_stub is not None:
                return True
            # ① 上次异常退出留下的备份先复原，避免叠加接管
            if _doh.load_backup():
                ok, msg = _doh.restore_dns()
                self.log("warn", f"检测到上次未复原的 DNS 接管，已先复原（{msg}）")
            # ② 起存根（只听 127.0.0.1:53，不影响局域网）
            stub = _doh.DohStub(on_event=lambda k, t: self.log(
                "info" if k != "error" else "warn", f"[DoH] {t}"))
            if not stub.start():
                self.log("error", "DoH 存根启动失败：127.0.0.1:53 可能被占用")
                return False
            # ③ 自检必须真的解析成功，才允许动系统设置
            time.sleep(0.4)
            h = stub.health_check()
            if not h["ok"]:
                self.log("error", f"DoH 存根自检失败，未接管系统 DNS：{h['error']}")
                stub.stop()
                return False
            # ④ 接管系统 DNS（需要管理员）
            if not fc.is_admin():
                self.log("warn", "DoH 存根已运行，但当前无管理员权限，无法接管系统 DNS"
                                 "（用 start_console.cmd 启动可提权）")
                self.dns_stub = stub
                self._start_dns_watchdog()
                return False
            ok, msg = _doh.switch_dns()
            if not ok:
                self.log("error", f"接管系统 DNS 失败：{msg}")
                stub.stop()
                return False
            self.dns_stub = stub
            self.dns_switched = True
            self.log("info", f"加密 DNS 已启用（{msg}）。链路上不再有明文域名查询，"
                             "DoT/DoH 出口见 DNS 泄露自检。")
            self._start_dns_watchdog()
            return True

    def disable_encrypted_dns(self, reason=""):
        with self._dns_lock:
            self._stop_dns_watchdog()
            if self.dns_switched:
                if _doh is not None:
                    ok, msg = _doh.restore_dns()
                    self.log("info" if ok else "error",
                             f"系统 DNS 已复原（{msg}）{('：' + reason) if reason else ''}")
                self.dns_switched = False
            if self.dns_stub is not None:
                self.dns_stub.stop()
                self.dns_stub = None

    def _stop_dns_watchdog(self):
        self.dns_watchdog = None            # 线程靠 dns_stub 判空自然退出

    def _start_dns_watchdog(self):
        if self.dns_watchdog is not None:
            return

        def loop():
            fails = 0
            while True:
                time.sleep(15)
                stub = self.dns_stub
                if stub is None or self.dns_watchdog is not thread_ref:
                    return
                h = stub.health_check()
                if h["ok"]:
                    fails = 0
                    continue
                fails += 1
                self.log("warn", f"加密 DNS 健康检查失败（{fails}/3）：{h['error']}")
                if fails >= 3:
                    self.log("error", "加密 DNS 连续失败，自动复原系统 DNS（网络可用性优先）")
                    self.disable_encrypted_dns()
                    return

        thread_ref = threading.Thread(target=loop, daemon=True)
        self.dns_watchdog = thread_ref
        thread_ref.start()

    # -- 状态快照
    def snapshot(self):
        e = self.engine
        st = dict(e.stats)
        up = None
        if st.get("started") and e.running:
            up = int(time.time() - st["started"])
        last_domain = None if self.privacy else st.get("last_domain")
        return {
            "app": "fragdpi-console",
            "admin": fc.is_admin(),
            "running": e.running,
            "uptime": up,
            "mode": self.ruleset.mode,
            "mode_label": MODE_LABEL.get(self.ruleset.mode, self.ruleset.mode),
            "rules": [r.to_dict() for r in self.ruleset.rules],
            "params": self.params.to_dict(),
            "privacy": self.privacy_state(),
            "stats": {
                "seen": st.get("seen", 0),
                "split": st.get("split", 0),
                "sent": st.get("sent", 0),
                "last_domain": last_domain,
            },
            "device_threshold": fc.MEASURED_DEVICE_THRESHOLD,
            "last_selftest": self.last_selftest,
            "last_dnscheck": self.last_dnscheck,
            "dnscheck_available": _dlc is not None,
            "last_event_id": self._eid,
        }


CONSOLE = Console()


# ------------------------------------------------------------------ HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "fragdpi-console/1.0"
    protocol_version = "HTTP/1.1"

    # ---- 工具
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def log_message(self, fmt, *args):      # 静音访问日志
        pass

    # ---- GET
    def do_GET(self):
        u = urlparse(self.path)
        p = u.path
        if p in ("/", "/index.html"):
            try:
                with open(HTML_PATH, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                return self._send(500, "console.html 缺失", "text/plain; charset=utf-8")
        if p == "/api/state":
            return self._json(CONSOLE.snapshot())
        if p == "/api/events":
            q = parse_qs(u.query)
            since = int((q.get("since") or ["0"])[0] or 0)
            return self._json({"events": CONSOLE.events_since(since),
                               "last_event_id": CONSOLE._eid})
        return self._send(404, "not found", "text/plain; charset=utf-8")

    # ---- POST
    def do_POST(self):
        p = urlparse(self.path).path
        try:
            return self._route(p, self._body())
        except Exception as ex:
            traceback.print_exc()
            return self._json({"ok": False, "error": f"{type(ex).__name__}: {ex}"}, 500)

    def _route(self, p, data):
        c = CONSOLE

        if p == "/api/mode":
            mode = data.get("mode")
            if mode not in fc.RuleSet.MODES:
                return self._json({"ok": False,
                                   "error": "mode 必须是 " + " / ".join(fc.RuleSet.MODES)}, 400)
            c.ruleset.mode = mode
            c.persist()
            c.log("info", f"工作模式切换为：{MODE_LABEL[mode]}")
            if mode == "privacy":
                c.log("warn", "隐私模式：所有 TLS 出站都会分片，事件日志不再记录域名。")
                if c.dns_encrypt:
                    threading.Thread(target=c.enable_encrypted_dns, daemon=True).start()
                else:
                    c.log("warn", "加密 DNS 当前关闭：明文 DNS 仍会泄露域名（可在隐私设置里开启）")
            elif c.dns_switched or c.dns_stub:
                c.disable_encrypted_dns()
            return self._json({"ok": True, "mode": mode})

        if p == "/api/rule":
            act = data.get("action")
            rules = c.ruleset.rules
            idx = data.get("index")
            if act == "add":
                r = fc.Rule.from_dict(data.get("rule") or {})
                if not r.value.strip():
                    return self._json({"ok": False, "error": "规则内容为空"}, 400)
                rules.append(r)
                c.log("info", f"新增规则：{r.name} [{r.type}] {r.value}")
            elif act == "update":
                if not isinstance(idx, int) or not (0 <= idx < len(rules)):
                    return self._json({"ok": False, "error": "规则下标越界"}, 400)
                old = rules[idx]
                new = fc.Rule.from_dict(data.get("rule") or {})
                new.hits = old.hits
                rules[idx] = new
                c.log("info", f"更新规则：{new.name} [{new.type}] {new.value}")
            elif act == "toggle":
                if not isinstance(idx, int) or not (0 <= idx < len(rules)):
                    return self._json({"ok": False, "error": "规则下标越界"}, 400)
                rules[idx].enabled = not rules[idx].enabled
                r = rules[idx]
                c.log("info", f"{'启用' if r.enabled else '停用'}规则：{r.name}")
            elif act == "delete":
                if not isinstance(idx, int) or not (0 <= idx < len(rules)):
                    return self._json({"ok": False, "error": "规则下标越界"}, 400)
                r = rules.pop(idx)
                c.log("info", f"删除规则：{r.name}")
            elif act == "reset":
                c.ruleset.rules = fc.default_rules()
                n, en = len(c.ruleset.rules), sum(1 for r in c.ruleset.rules if r.enabled)
                c.log("info", f"已载入内置游戏预设（{n} 组，启用 {en} 组）")
            else:
                return self._json({"ok": False, "error": "未知的 action"}, 400)
            c.persist()
            return self._json({"ok": True, "rules": [r.to_dict() for r in c.ruleset.rules]})

        if p == "/api/params":
            try:
                c.params.guard = max(0, min(60, int(data.get("guard", c.params.guard))))
                c.params.min_cut = max(0, min(1400, int(data.get("min_cut", c.params.min_cut))))
                c.params.mtu = max(576, min(9000, int(data.get("mtu", c.params.mtu))))
                new_ports = parse_ports(data.get("ports", c.params.port_list()))
            except (TypeError, ValueError) as ex:
                return self._json({"ok": False, "error": f"参数不合法：{ex}"}, 400)
            if not new_ports:
                return self._json({"ok": False, "error": "至少要保留一个端口"}, 400)
            old_ports = c.params.port_list()
            c.params.port = new_ports[0]
            c.params.ports = new_ports[1:]
            restart = new_ports != old_ports
            c.persist()
            c.log("info", f"参数更新：guard={c.params.guard} min-cut={c.params.min_cut} "
                          f"mtu={c.params.mtu} 端口={','.join(str(x) for x in new_ports)}")
            if restart and c.engine.running:
                c.engine.stop()
                c.engine.start()
                c.log("warn", "端口变了，已自动重启拦截")
            return self._json({"ok": True, "params": c.params.to_dict()})

        if p == "/api/privacy":
            want_dns = None
            if "clear_on_exit" in data:
                c.clear_on_exit = bool(data["clear_on_exit"])
            if "random_cut" in data:
                c.params.random_cut = bool(data["random_cut"])
            if "dns_encrypt" in data:
                new = bool(data["dns_encrypt"])
                if new != c.dns_encrypt:
                    c.dns_encrypt = new
                    want_dns = new
            c.persist()
            st = c.privacy_state()
            c.log("info", f"隐私选项更新：随机切点={'开' if st['random_cut'] else '关'}"
                          f" · 退出清日志={'开' if st['clear_on_exit'] else '关'}"
                          f" · 加密 DNS={'开' if st['dns_encrypt'] else '关'}"
                          f" · 端口={','.join(str(x) for x in st['ports'])}")
            if want_dns is True and c.ruleset.mode == "privacy":
                threading.Thread(target=c.enable_encrypted_dns, daemon=True).start()
            elif want_dns is False and (c.dns_switched or c.dns_stub):
                c.disable_encrypted_dns()
            return self._json({"ok": True, "privacy": st})

        if p == "/api/control":
            act = data.get("action")
            if act == "start":
                ok = c.engine.start()
                if not ok:
                    return self._json({"ok": False, "error": "启动失败，见事件日志"}, 500)
                return self._json({"ok": True})
            if act == "stop":
                c.engine.stop()
                return self._json({"ok": True})
            return self._json({"ok": False, "error": "未知的 action"}, 400)

        if p == "/api/selftest":
            host = (data.get("host") or "zzz.mihoyo.com").strip()
            if not host:
                return self._json({"ok": False, "error": "主机名不能为空"}, 400)
            res = c.engine.selftest(host)
            res["proxy_used"] = False
            res["at"] = time.strftime("%H:%M:%S")
            c.last_selftest = res
            return self._json({"ok": True, "result": res})

        if p == "/api/events/clear":
            with c._lock:
                c.events.clear()
            return self._json({"ok": True})

        if p == "/api/dnscheck":
            if _dlc is None:
                return self._json({"ok": False, "error": "DNS 自检模块不可用（tools/dns_leak_check.py 缺失）"}, 500)
            try:
                res = _dlc.quick_check()
            except Exception as ex:
                traceback.print_exc()
                return self._json({"ok": False, "error": f"{type(ex).__name__}: {ex}"}, 500)
            c.last_dnscheck = res
            # ⚠️ 日志里不写域名/解析器细节，只说结论（隐私模式下更不能写）
            c.log("info", "DNS 泄露自检完成：明文 DNS 可用"
                          f" · 加密 DNS {'可用' if res['encrypted_available'] else '不可用'}"
                          f" · 疑似污染 {len(res['poisoned'])} 个域名")
            return self._json({"ok": True, "result": res})

        return self._json({"ok": False, "error": "not found"}, 404)


# ------------------------------------------------------------------ 入口
def banner():
    c = CONSOLE
    print("=" * 62)
    print("  fragdpi 控制台  ·  首包分片引擎 (WinDivert)")
    print("=" * 62)
    print(f"  管理员权限 : {'是' if fc.is_admin() else '否  ⚠ 必须管理员运行才能加载驱动'}")
    print(f"  工作模式   : {MODE_LABEL.get(c.ruleset.mode, c.ruleset.mode)}")
    print(f"  规则数量   : {len(c.ruleset.rules)}（启用 "
          f"{sum(1 for r in c.ruleset.rules if r.enabled)}）")
    print(f"  参数       : guard={c.params.guard} min-cut={c.params.min_cut} "
          f"mtu={c.params.mtu} 端口={','.join(str(p) for p in c.params.port_list())}")
    if c.privacy:
        print(f"  隐私选项   : 随机切点={'开' if c.params.random_cut else '关'}"
              f" · 退出清日志={'开' if c.clear_on_exit else '关'}"
              f" · 加密 DNS={'开' if c.dns_encrypt else '关'}")
        print("               ⚠ 事件日志不含域名；加密 DNS 关闭时明文查询仍会泄露域名")
    print(f"  控制台地址 : http://{BIND_HOST}:{BIND_PORT}/")
    print("=" * 62)


def main():
    fc.init_console()          # 重定向输出时也别因为中文编码崩掉
    argv = sys.argv[1:]
    no_browser = "--no-browser" in argv
    autostart = "--autostart" in argv
    if not fc.is_admin():
        print("\n  [!] 当前不是管理员，拦截功能将无法启动（界面仍可打开）。")
        print("      请用 start_console.cmd 启动以自动提权。")
        print("      加密 DNS 的「接管系统 DNS」一步同样需要管理员。\n")
    if _doh is not None and _doh.load_backup():
        ok, msg = _doh.restore_dns()
        print(f"\n  [!] 检测到上次未复原的 DNS 接管，已自动复原：{msg}")
        if not ok:
            print("      手动复原：python tools/doh_stub.py --off")
    banner()
    try:
        httpd = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    except OSError as e:
        print(f"\n  [X] 无法监听 {BIND_HOST}:{BIND_PORT} —— {e}")
        print( "      多半是已经有一个控制台实例在运行（重复双击了 start_console.cmd）。")
        print(f"      · 直接用已有实例：  http://{BIND_HOST}:{BIND_PORT}/")
        print( "      · 或先双击 stop_console.cmd 把它结束，再重新启动。\n")
        return 1
    httpd.daemon_threads = True
    if autostart:
        CONSOLE.engine.start()
    if not no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(f"http://{BIND_HOST}:{BIND_PORT}/")).start()
    print("  按 Ctrl+C 退出。\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if CONSOLE.dns_switched or CONSOLE.dns_stub:
                CONSOLE.disable_encrypted_dns()
        except Exception:
            pass
        try:
            CONSOLE.engine.stop()
        except Exception:
            pass
        if CONSOLE.privacy and CONSOLE.clear_on_exit:
            with CONSOLE._lock:               # 退出即抹掉本次会话的事件记录
                CONSOLE.events.clear()
            print("隐私模式：事件日志已清空。")
        httpd.server_close()
        print("控制台已退出。")


if __name__ == "__main__":
    main()
