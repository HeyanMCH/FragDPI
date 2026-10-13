#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""safety_audit — 开机安全审计：确认这台机器没有被本工具（或任何驱动残留）搞成
「重启蓝屏」或「开不了机」的状态。

为什么需要它：

    内核驱动服务有两个字段直接决定「会不会把系统搞挂」——

        Start        0=BOOT_START  1=SYSTEM_START  2=AUTO_START  3=DEMAND_START
                     WinDivert 注册的是 3（按需）。**只要保持 3，开机根本不加载它**，
                     所以删驱动文件、删整个文件夹都不会影响开机。
                     一旦被改成 0/1/2 且文件又不存在 → 开机加载失败，可能卡在启动阶段。

        ErrorControl 0=IGNORE  1=NORMAL  2=SEVERE  3=CRITICAL
                     WinDivert 是 1（只记日志）。若是 3，加载失败会**直接蓝屏**。

本脚本只读，不改任何东西。检查项覆盖：

    A. 所有内核驱动服务 —— 找「随系统启动但文件已不存在」的开机隐患
    B. 指向用户可写目录的驱动（桌面/下载/临时目录 —— 这类驱动天生脆弱）
    C. 指向本仓库的驱动服务（本工具自己留下的）
    D. 启动项（Run / RunOnce / 启动文件夹 / 计划任务）里有没有本工具
    E. DNS 有没有被留在 127.0.0.1（加密 DNS 接管没复原会直接断网）
    F. hosts 文件、系统代理 有没有被改
    G. 防火墙规则里有没有本工具的路径
    H. 残留进程 / 遗留文件（_update_staging、apply_update.cmd、dns_backup.json）
    I. BCD 启动配置有没有被加过奇怪的东西

用法：
    python tools/safety_audit.py            # 人读的报告
    python tools/safety_audit.py --json     # 结构化输出
"""
import json
import os
import re
import subprocess
import sys
import winreg

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORE = os.path.join(ROOT, "core")
if CORE not in sys.path:
    sys.path.insert(0, CORE)

try:
    import fragcore as fc
except ImportError:
    fc = None

SERVICE_KEY = r"SYSTEM\CurrentControlSet\Services"
START_NAME = {0: "BOOT_START（随内核）", 1: "SYSTEM_START（随系统）",
              2: "AUTO_START（自动）", 3: "DEMAND_START（按需）", 4: "DISABLED（已禁用）"}
EC_NAME = {0: "IGNORE", 1: "NORMAL", 2: "SEVERE", 3: "CRITICAL（失败即蓝屏）"}

SEV_OK, SEV_WARN, SEV_BAD, SEV_INFO = "OK", "WARN", "BAD", "INFO"


class Report:
    def __init__(self):
        self.items = []

    def add(self, sev, title, detail, extra=None):
        self.items.append({"sev": sev, "title": title, "detail": detail, "extra": extra})

    def count(self, sev):
        return sum(1 for i in self.items if i["sev"] == sev)


# ------------------------------------------------------------------ 工具
def reg_get(root, path, name):
    try:
        with winreg.OpenKey(root, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except Exception:
        return None


def norm_image_path(ip):
    r"""把 \??\C:\... / \SystemRoot\... / system32\... 归一成真实路径。"""
    if not ip:
        return None
    p = str(ip)
    p = p.strip('"')
    for pre in ("\\??\\", "\\SystemRoot\\"):
        if p.startswith(pre):
            p = p[len(pre):]
            break
    if p[:1] == "\\":
        p = p.lstrip("\\")
    if p.lower().startswith("system32\\"):
        p = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), p)
    return p


def is_user_writable_dir(p):
    """驱动文件放在用户可写目录里 → 任何人都能替换它 → 本质上是提权后门，也很脆弱。"""
    if not p:
        return False
    low = p.lower().replace("/", "\\")
    marks = ["\\users\\", "\\desktop\\", "\\downloads\\", "\\documents\\",
             "\\appdata\\local\\temp\\", "\\temp\\", "\\workbuddy\\", "\\onedrive\\"]
    return any(m in low for m in marks)


def enum_driver_services():
    """枚举所有内核/文件系统驱动服务。"""
    out = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE_KEY) as base:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(base, i)
                except OSError:
                    break
                i += 1
                sub = SERVICE_KEY + "\\" + name
                stype = reg_get(winreg.HKEY_LOCAL_MACHINE, sub, "Type")
                if stype is None:
                    continue
                if not (int(stype) & 0x3):        # 只关心 driver(1) / file system driver(2)
                    continue
                start = reg_get(winreg.HKEY_LOCAL_MACHINE, sub, "Start")
                ec = reg_get(winreg.HKEY_LOCAL_MACHINE, sub, "ErrorControl")
                ip = reg_get(winreg.HKEY_LOCAL_MACHINE, sub, "ImagePath")
                path = norm_image_path(ip)
                out.append({
                    "name": name,
                    "type": int(stype),
                    "start": int(start) if isinstance(start, int) else None,
                    "error_control": int(ec) if isinstance(ec, int) else None,
                    "image_path": ip,
                    "resolved": path,
                    "exists": bool(path) and os.path.exists(path),
                })
    except Exception:
        pass
    return out


# ------------------------------------------------------------------ A/B/C 驱动
def check_drivers(rep, drivers):
    """找真正的开机隐患。

    ⚠️ 这里的判据必须**极准**，因为误报会让人去"修"不该动的东西 ——
       第一版就犯过这个错：把「Start∈{0,1,2} 且 ErrorControl=3」直接判成隐患，
       结果把 ACPI / pci / ndis / storahci 等 37 个**核心启动驱动**全报成红的。
       但那些驱动的 ErrorControl=3 是**设计如此**（系统盘栈挂了本来也就起不来）。

       真正的隐患只有一个条件：**服务随系统启动 + ImagePath 指向的文件不存在**。
       （文件在 → 它能正常加载；ErrorControl 只在这时候决定"加载失败的后果有多严重"）

    另外：**没有 ImagePath 的服务不算隐患** —— 那是内核内置驱动
    （Null / Beep / Msfs / Npfs / Wof 之类），本来就不需要文件。
    """
    hazards, builtins, loose, ours = [], [], [], []
    for d in drivers:
        auto = d["start"] in (0, 1, 2)
        if not d["image_path"]:
            if auto:
                builtins.append(d)
            continue
        # 判据统一走 fragcore.is_boot_hazard —— 纯函数，有单测钉着，
        # 免得这里又退化成"ErrorControl=3 就算隐患"那种误报。
        if fc is not None and fc.is_boot_hazard(d["start"], d["image_path"], d["exists"]):
            hazards.append(d)
        elif auto and not d["exists"]:
            hazards.append(d)          # fragcore 不可用时的兜底
        if d["exists"] and is_user_writable_dir(d["resolved"]):
            loose.append(d)
        rp = (d["resolved"] or "").lower().replace("/", "\\")
        if ROOT.lower().replace("/", "\\") in rp:
            ours.append(d)

    if hazards:
        for d in hazards:
            ec = d["error_control"]
            sev_note = (fc.boot_hazard_severity(ec) if fc is not None
                        else "ErrorControl=%s" % ec)
            rep.add(SEV_BAD, "开机隐患：驱动服务随系统启动，但指向的文件不存在",
                    "%s  Start=%s(%s)  %s" % (d["name"], d["start"],
                                              START_NAME.get(d["start"], "?"),
                                              d["resolved"]),
                    "%s。修法：摘掉这个服务注册（不是本工具的也要处理）" % sev_note)
    else:
        rep.add(SEV_OK, "没有「随系统启动但文件不存在」的驱动服务",
                "已扫描全部内核/文件系统驱动服务（%d 个）—— 这是唯一的真隐患判据" % len(drivers))

    if builtins:
        rep.add(SEV_OK, "无 ImagePath 的服务已正确排除",
                "%d 个（内核内置驱动，如 %s）—— 它们本来就不需要驱动文件"
                % (len(builtins), ", ".join(b["name"] for b in builtins[:5])))

    if loose:
        for d in loose[:8]:
            rep.add(SEV_WARN, "驱动文件位于用户可写目录",
                    "%s -> %s（Start=%s）" % (d["name"], d["resolved"], d["start"]),
                    "任何本地用户都能替换该文件 —— 属于提权风险面，且这类驱动很脆弱")
    else:
        rep.add(SEV_OK, "没有驱动从用户可写目录加载", "")

    if ours:
        for d in ours:
            rep.add(SEV_WARN, "存在指向本仓库的驱动服务",
                    "%s -> %s（Start=%s）" % (d["name"], d["resolved"], d["start"]),
                    "删文件夹前先跑 cleanup_driver.cmd；Start=3 时不影响开机")
    else:
        rep.add(SEV_OK, "没有指向本仓库的驱动服务残留", "")


# ------------------------------------------------------------------ D 启动项
RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]


def check_autostart(rep):
    hits = []
    for root, path in RUN_KEYS:
        try:
            with winreg.OpenKey(root, path) as k:
                i = 0
                while True:
                    try:
                        n, v, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    if ROOT.lower() in str(v).lower() or "fragdpi" in str(v).lower():
                        hits.append("%s\\%s = %s" % (path.split("\\")[-1], n, v))
        except Exception:
            pass
    # 启动文件夹（desktop.ini 是 Windows 自带的，不是启动项）
    for folder in (os.path.join(os.environ.get("APPDATA", ""),
                                r"Microsoft\Windows\Start Menu\Programs\Startup"),
                   os.path.join(os.environ.get("ProgramData", ""),
                                r"Microsoft\Windows\Start Menu\Programs\Startup")):
        try:
            for f in os.listdir(folder):
                if f.lower() == "desktop.ini":
                    continue
                hits.append("启动文件夹: " + os.path.join(folder, f))
        except OSError:
            pass
    # 计划任务：扫 Tasks 目录里提到本仓库的
    tasks_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks")
    try:
        for dirpath, _dirs, files in os.walk(tasks_dir):
            for f in files:
                p = os.path.join(dirpath, f)
                try:
                    data = open(p, "rb").read()
                except OSError:
                    continue
                if ROOT.encode("utf-8", "ignore").lower() in data.lower() \
                        or b"fragdpi" in data.lower():
                    hits.append("计划任务: " + p)
    except OSError:
        pass

    if hits:
        for h in hits[:10]:
            rep.add(SEV_WARN, "启动项里出现了本工具", h)
    else:
        rep.add(SEV_OK, "没有把本工具加进任何启动项",
                "已查 Run/RunOnce（HKLM+HKCU）、启动文件夹、计划任务")


# ------------------------------------------------------------------ E/F 网络
def check_network(rep):
    # DNS：有没有被留在 127.0.0.1
    stuck = []
    try:
        flags = 0x08000000
        p = subprocess.run(["netsh", "interface", "ip", "show", "dnsservers"],
                           capture_output=True, creationflags=flags)
        out = (p.stdout + p.stderr).decode("utf-8", "replace")
        cur = None
        for line in out.splitlines():
            s = line.strip()
            if not s:
                continue
            if '"' in s and s.count('"') >= 2:
                cur = s.split('"')[1]
                continue
            for tok in s.replace(":", " ").split():
                if tok.count(".") == 3 and all(x.isdigit() for x in tok.split(".")):
                    if tok == "127.0.0.1" or tok.startswith("127."):
                        stuck.append("%s -> %s" % (cur, tok))
    except Exception:
        pass
    if stuck:
        for s in stuck:
            rep.add(SEV_BAD, "DNS 被留在 127.0.0.1（加密 DNS 接管没复原）",
                    s, "如果本地 DoH 存根没在跑，这台机器会**直接解析不了域名**。"
                       "修法：restore_dns.cmd 或 tools/doh_stub.py --off")
    else:
        rep.add(SEV_OK, "DNS 没有指向 127.0.0.1", "DNS 接管已复原或从未接管")

    if fc is not None:
        drv = fc.driver_leftovers()
        if drv.get("hvci") is True:
            rep.add(SEV_INFO, "内存完整性（HVCI）处于启用状态",
                    "本工具的 WinDivert 驱动会被拦下（WinDivertOpen 报 1450）",
                    "这是**系统安全设置拦驱动**，不会导致蓝屏或开机失败；只是工具用不了")
        elif drv.get("hvci") is False:
            rep.add(SEV_OK, "内存完整性（HVCI）未启用", "WinDivert 驱动不被它拦")

    # hosts
    hosts = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                         "System32", "drivers", "etc", "hosts")
    try:
        txt = open(hosts, encoding="utf-8", errors="replace").read()
        bad = [l for l in txt.splitlines()
               if l.strip() and not l.strip().startswith("#")
               and ("fragdpi" in l.lower() or "windivert" in l.lower())]
        if bad:
            rep.add(SEV_WARN, "hosts 文件里有本工具相关条目", "; ".join(bad[:3]))
        else:
            rep.add(SEV_OK, "hosts 文件没有被本工具改动", "%d 行" % len(txt.splitlines()))
    except OSError:
        rep.add(SEV_INFO, "读不到 hosts 文件", "", "")

    # 系统代理
    ie = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
    enabled = reg_get(winreg.HKEY_CURRENT_USER, ie, "ProxyEnable")
    server = reg_get(winreg.HKEY_CURRENT_USER, ie, "ProxyServer")
    if enabled == 1 or server:
        # 只提示，不改 —— 用户自己配的代理是正常的
        own = "fragdpi" in str(server).lower() or "8888" in str(server)
        rep.add(SEV_WARN if own else SEV_INFO, "系统代理已启用",
                "ProxyEnable=%s ProxyServer=%s" % (enabled, server),
                "这不是本工具设的 —— 本工具从不改系统代理（只在自己进程内用/禁用代理）"
                if not own else "看着像本工具早期版本留下的，请自行确认")
    else:
        rep.add(SEV_OK, "系统代理未启用", "本工具也不会去动它")


# ------------------------------------------------------------------ G 防火墙
def check_firewall(rep):
    flags = 0x08000000
    try:
        p = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule",
                            "name=all"], capture_output=True, creationflags=flags)
        out = (p.stdout + p.stderr).decode("utf-8", "replace")
        hits = [l.strip() for l in out.splitlines()
                if ROOT.lower() in l.lower() or "fragdpi" in l.lower()]
        if hits:
            for h in hits[:5]:
                rep.add(SEV_WARN, "防火墙规则里提到本工具", h)
        else:
            rep.add(SEV_OK, "防火墙里没有本工具的规则", "")
    except Exception:
        rep.add(SEV_INFO, "防火墙审计跳过（netsh 不可用）", "", "")


# ------------------------------------------------------------------ H 遗留
def check_leftovers(rep):
    checks = [
        ("core/dns_backup.json", "加密 DNS 接管备份（残留=DNS 可能仍被接管）"),
        ("apply_update.cmd", "自动升级的替换脚本（用完后应自行删除）"),
        ("_update_staging", "自动升级的下载暂存目录"),
        ("core/fragconfig.json", "控制台配置（正常，含规则与参数）"),
        ("android/debug.keystore", "本地调试签名密钥库（正常，但不该用于发布）"),
    ]
    tails = []
    for rel, note in checks:
        p = os.path.join(ROOT, rel)
        if os.path.exists(p):
            tails.append("%s —— %s" % (rel, note))
    if tails:
        for t in tails:
            sev = SEV_WARN if ("dns_backup" in t or "_update_staging" in t) else SEV_INFO
            rep.add(sev, "仓库里有运行时文件", t)
    else:
        rep.add(SEV_OK, "仓库里没有运行时残留文件", "")

    # 残留进程
    procs = []
    try:
        p = subprocess.run(["wmic", "process", "where", "name like '%python%'",
                            "get", "ProcessId,CommandLine"],
                           capture_output=True, creationflags=0x08000000)
        out = (p.stdout + p.stderr).decode("utf-8", "replace")
        for line in out.splitlines():
            if ROOT.lower() in line.lower():
                procs.append(line.strip()[:160])
    except Exception:
        pass
    if procs:
        for pr in procs[:5]:
            rep.add(SEV_WARN, "还有进程在跑本仓库里的程序", pr,
                    "会占着 WinDivert.dll 导致文件夹删不掉；先结束它")
    else:
        rep.add(SEV_OK, "没有残留进程占着本仓库", "")

    # 驱动文件是否被锁
    if fc is not None:
        sysf = os.path.join(ROOT, "third_party", "windivert", "WinDivert64.sys")
        if fc.driver_file_locked(sysf):
            rep.add(SEV_WARN, "仓库里的 WinDivert64.sys 正被占用",
                    sysf, "现在删不掉；先关程序 + 跑 cleanup_driver.cmd")
        else:
            rep.add(SEV_OK, "仓库里的驱动文件未被占用",
                    "现在可以安全删除/移动 FragDPI 文件夹")


# ------------------------------------------------------------------ I BCD
def check_boot(rep):
    flags = 0x08000000
    try:
        p = subprocess.run(["bcdedit", "/enum", "{current}"],
                           capture_output=True, creationflags=flags)
        out = (p.stdout + p.stderr).decode("utf-8", "replace")
        if "拒绝访问" in out or "Access is denied" in out or not out.strip():
            rep.add(SEV_INFO, "BCD 审计跳过（需要管理员）", "", "")
            return
        risky = [l.strip() for l in out.splitlines()
                 if re.search(r"(bootexecute|testsigning|nointegritychecks|"
                              r"hypervisorlaunchtype|nx|safeboot)", l, re.I)]
        odd = [l for l in risky if "hypervisorlaunchtype" not in l.lower()]
        if odd:
            for o in odd:
                rep.add(SEV_INFO, "BCD 里的非默认项", o, "只读检查，未做修改")
        else:
            rep.add(SEV_OK, "BCD 启动配置没有异常项", "")
    except Exception:
        rep.add(SEV_INFO, "bcdedit 不可用，跳过", "", "")


# ------------------------------------------------------------------ main
def main():
    if fc is not None:
        fc.init_console()
    as_json = "--json" in sys.argv

    rep = Report()
    drivers = enum_driver_services()
    check_drivers(rep, drivers)
    check_autostart(rep)
    check_network(rep)
    check_firewall(rep)
    check_leftovers(rep)
    check_boot(rep)

    bad, warn = rep.count(SEV_BAD), rep.count(SEV_WARN)

    if as_json:
        print(json.dumps({
            "bad": bad, "warn": warn,
            "driver_count": len(drivers),
            "items": rep.items,
            "verdict": ("UNSAFE" if bad else ("ATTENTION" if warn else "CLEAN")),
        }, ensure_ascii=False, indent=2))
        return 1 if bad else 0

    mark = {SEV_OK: "  ✓", SEV_WARN: "  ⚠", SEV_BAD: "  🔴", SEV_INFO: "  ·"}
    print("=" * 74)
    print("  开机安全审计  ·  FragDPI")
    print("=" * 74)
    print("  只读检查，不改任何设置。目的是确认：这台机器不会因为")
    print("  「驱动残留 / 删了文件」而在重启后蓝屏或开不了机。")
    print()
    for it in rep.items:
        print("%s %s" % (mark[it["sev"]], it["title"]))
        if it["detail"]:
            print("      %s" % it["detail"])
        if it["extra"]:
            print("      → %s" % it["extra"])
    print()
    print("-" * 74)
    if bad:
        print("  结论：🔴 发现 %d 项**必须处理**的隐患（见上）" % bad)
    elif warn:
        print("  结论：⚠ 没有会蓝屏/开不了机的隐患，但有 %d 项建议处理" % warn)
    else:
        print("  结论：✅ 干净 —— 没有蓝屏或开机失败的隐患")
    print("-" * 74)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
