#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cleanup_driver — 清理 WinDivert 驱动残留，解决「用完之后文件夹删不掉」。

背景（实测于 2026-10-13）：

    WinDivert 2.2 的 DLL **不导出任何卸载接口**（WinDivertUninstall 之类都不存在），
    驱动装卸完全藏在 WinDivertOpen/WinDivertClose 内部。于是有两个坑：

    1. WinDivertOpen 会创建名为 `WinDivert` 的内核服务，它的 ImagePath 直接指向
       **本仓库里的 third_party/windivert/WinDivert64.sys**。驱动一旦加载，
       内核就锁住这个文件 —— 整个文件夹删不掉、也移不走。
    2. WinDivertOpen 失败时（例如被「内存完整性」HVCI 拦下，Win32=1450），
       服务已经建好了却**不会回滚**，留下一个 STOPPED 的孤儿服务。

本脚本做两件事：报告状态 / 停掉并删除该服务。
**不会**碰正在被使用的驱动（服务处于 RUNNING 时会拒绝，避免打断别的程序）。

用法：
    python tools/cleanup_driver.py            # 只看状态
    python tools/cleanup_driver.py --clean    # 停掉并删除残留服务
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORE = os.path.join(ROOT, "core")
if CORE not in sys.path:
    sys.path.insert(0, CORE)

import fragcore as fc                                          # noqa: E402

STATE_NAME = {1: "STOPPED（已停止）", 2: "START_PENDING", 3: "STOP_PENDING",
              4: "RUNNING（正在运行）", 5: "CONTINUE_PENDING",
              6: "PAUSE_PENDING", 7: "PAUSED"}


# 文件占用检测统一走 fragcore.driver_file_locked()，这里不再自己实现一份
# （曾经各写一份，导致两处判据可能漂移）


def show():
    d = fc.driver_leftovers()
    sysfile = os.path.join(ROOT, "third_party", "windivert", "WinDivert64.sys")
    locked = fc.driver_file_locked(sysfile)
    cfg = fc.driver_service_config()

    print("=" * 68)
    print("  FragDPI 驱动残留检查")
    print("=" * 68)
    print("  管理员权限   : %s" % ("是" if fc.is_admin() else "否（清理需要管理员）"))
    print("  驱动服务     : %s" % (
        "存在 · " + STATE_NAME.get(d["service_state"], str(d["service_state"]))
        if d["service_exists"] else "不存在 ✅"))
    if cfg:
        print("  启动类型     : Start=%s %s" % (
            cfg.get("start"),
            {0: "🔴 随内核启动（危险）", 1: "🔴 随系统启动（危险）",
             2: "⚠ 自动启动", 3: "✅ 按需启动（开机不加载，安全）",
             4: "已禁用"}.get(cfg.get("start"), "?")))
        print("  失败策略     : ErrorControl=%s %s" % (
            cfg.get("error_control"),
            {0: "IGNORE", 1: "✅ NORMAL（只记日志）", 2: "SEVERE",
             3: "🔴 CRITICAL（加载失败会蓝屏）"}.get(cfg.get("error_control"), "?")))
        print("  服务指向     : %s" % cfg.get("resolved_path"))
        print("  该文件存在   : %s" % ("是" if cfg.get("file_exists") else "否"))
    print("  System32 驱动: %s" % (d["sys32_driver"] or "无"))
    print("  仓库 .sys 锁 : %s" % (
        "—（文件不存在）" if locked is None else
        ("🔴 被锁住（这就是文件夹删不掉的原因）" if locked else "未锁 ✅")))
    print("  内存完整性   : %s" % (
        "🔴 已启用 —— WinDivert 驱动会被拦下（WinDivertOpen 报 1450），拦截功能用不了"
        if d["hvci"] else ("未启用 ✅" if d["hvci"] is False else "读取不到")))
    print()

    # ---- 开机安全结论（用户最关心的：会不会重启蓝屏 / 开不了机）
    print("-" * 68)
    print("  开机安全")
    print("-" * 68)
    if d.get("boot_hazard"):
        print("  🔴 有隐患！重启后可能卡在启动阶段：")
        for r in d.get("boot_hazard_reasons", []):
            print("     · " + r)
        print("     处理：以管理员运行  python tools/cleanup_driver.py --clean")
    elif d["service_exists"]:
        print("  ✅ 没有开机隐患。")
        print("     当前服务是 Start=%s（按需启动）—— **开机根本不会加载它**，"
              % (d.get("start_type"),))
        print("     所以删驱动文件、删整个 FragDPI 文件夹都不会影响开机。")
        print("     （这一点有实测支撑：WinDivert 注册的就是 Start=3 + ErrorControl=1）")
    else:
        print("  ✅ 没有开机隐患 —— 压根没有驱动服务注册。")
    print("-" * 68)
    print()

    if not d["service_exists"] and not locked and not d["hvci"]:
        print("  一切正常，没有需要处理的东西。")
    elif d["service_exists"] and d["service_running"]:
        print("  ⚠ 驱动服务正在运行 —— 说明有程序正在使用它（可能是本程序，也可能是")
        print("    别的 WinDivert 应用）。先关掉那个程序，再运行本脚本 --clean。")
    elif d["service_exists"] or locked:
        print("  可以清理：python tools/cleanup_driver.py --clean")
        print("  或直接双击仓库根目录的 cleanup_driver.cmd（会自动提权）")
    print()
    print("  想删掉整个文件夹的话，顺序是：先关程序 → 再跑 --clean → 然后就能删了。")
    print("  ⚠ 顺序不能反：先删文件会让服务注册指向一个不存在的文件，")
    print("    如果哪天启动类型被改成 0/1/2，那就是开不了机的成因。")
    print("=" * 68)
    return 0


def clean():
    d = fc.driver_leftovers()
    if not d["service_exists"]:
        print("驱动服务不存在，无需清理。")
    elif d["service_running"]:
        print("✗ 驱动服务正在运行（有程序在用），拒绝清理以免打断别的程序。")
        print("  ⚠️ 这一点是刻意的：强行停用一个正在工作的内核驱动，")
        print("     可能让持有它的进程异常退出甚至引发蓝屏。请先关掉那个程序。")
        return 1
    else:
        if not fc.is_admin():
            print("✗ 清理需要管理员权限。请用 cleanup_driver.cmd（会自动提权）")
            print("  或以管理员身份运行：python tools/cleanup_driver.py --clean")
            return 1
        # 用 safe_uninstall_driver：它保证「先摘服务注册，再等文件解锁」的顺序
        ok, msg = fc.safe_uninstall_driver()
        print(("✓ " if ok else "✗ ") + msg)
        if not ok:
            return 1

    sysfile = os.path.join(ROOT, "third_party", "windivert", "WinDivert64.sys")
    if fc.driver_file_locked(sysfile):
        print("⚠ 仓库里的 WinDivert64.sys 仍被锁 —— 可能还有进程在用它。")
        print("  用任务管理器结束残留的 python.exe 后再试，或重启一次。")
        print("  （服务注册已摘除，所以**重启是安全的**，不会因此开不了机）")
    elif os.path.exists(sysfile):
        print("✓ 仓库里的 WinDivert64.sys 已解锁，文件夹现在删得掉了。")
    print()
    print("✓ 服务注册已摘除 —— 不存在「服务指向已删除文件」的悬空引用，开机安全。")
    return 0


def main():
    fc.init_console()
    if "--clean" in sys.argv or "-c" in sys.argv:
        return clean()
    return show()


if __name__ == "__main__":
    sys.exit(main())
