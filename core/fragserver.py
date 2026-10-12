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
        self.events = collections.deque(maxlen=500)
        self._eid = 0
        self._lock = threading.Lock()
        self.last_selftest = None
        self.engine = fc.Engine(self.ruleset, self.params, on_event=self.log)
        # 规则命中计数在 fragcore 内部累加，这里只做快照展示

    # -- 事件
    def log(self, level, text):
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
        })

    # -- 状态快照
    def snapshot(self):
        e = self.engine
        st = dict(e.stats)
        up = None
        if st.get("started") and e.running:
            up = int(time.time() - st["started"])
        return {
            "app": "fragdpi-console",
            "admin": fc.is_admin(),
            "running": e.running,
            "uptime": up,
            "mode": self.ruleset.mode,
            "rules": [r.to_dict() for r in self.ruleset.rules],
            "params": self.params.to_dict(),
            "stats": {
                "seen": st.get("seen", 0),
                "split": st.get("split", 0),
                "sent": st.get("sent", 0),
                "last_domain": st.get("last_domain"),
            },
            "device_threshold": fc.MEASURED_DEVICE_THRESHOLD,
            "last_selftest": self.last_selftest,
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
            if mode not in ("off", "rules", "global"):
                return self._json({"ok": False, "error": "mode 必须是 off / rules / global"}, 400)
            c.ruleset.mode = mode
            c.persist()
            c.log("info", f"工作模式切换为：{ {'off':'关闭','rules':'规则模式','global':'全局模式'}[mode] }")
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
                new_port = max(1, min(65535, int(data.get("port", c.params.port))))
            except (TypeError, ValueError):
                return self._json({"ok": False, "error": "参数必须是整数"}, 400)
            restart = new_port != c.params.port
            c.params.port = new_port
            c.persist()
            c.log("info", f"参数更新：guard={c.params.guard} min-cut={c.params.min_cut} "
                          f"mtu={c.params.mtu} port={c.params.port}")
            if restart and c.engine.running:
                c.engine.stop()
                c.engine.start()
                c.log("warn", "端口变了，已自动重启拦截")
            return self._json({"ok": True, "params": c.params.to_dict()})

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

        return self._json({"ok": False, "error": "not found"}, 404)


# ------------------------------------------------------------------ 入口
def banner():
    c = CONSOLE
    print("=" * 62)
    print("  fragdpi 控制台  ·  首包分片引擎 (WinDivert)")
    print("=" * 62)
    print(f"  管理员权限 : {'是' if fc.is_admin() else '否  ⚠ 必须管理员运行才能加载驱动'}")
    print(f"  工作模式   : {c.ruleset.mode}")
    print(f"  规则数量   : {len(c.ruleset.rules)}（启用 "
          f"{sum(1 for r in c.ruleset.rules if r.enabled)}）")
    print(f"  参数       : guard={c.params.guard} min-cut={c.params.min_cut} "
          f"mtu={c.params.mtu} port={c.params.port}")
    print(f"  控制台地址 : http://{BIND_HOST}:{BIND_PORT}/")
    print("=" * 62)


def main():
    argv = sys.argv[1:]
    no_browser = "--no-browser" in argv
    autostart = "--autostart" in argv
    if not fc.is_admin():
        print("\n  [!] 当前不是管理员，拦截功能将无法启动（界面仍可打开）。")
        print("      请用 start_console.cmd 启动以自动提权。\n")
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
            CONSOLE.engine.stop()
        except Exception:
            pass
        httpd.server_close()
        print("控制台已退出。")


if __name__ == "__main__":
    main()
