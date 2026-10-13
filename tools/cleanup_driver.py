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


def is_locked(path):
    """试着重命名来判断文件有没有被锁（改名失败 = 被占用）。"""
    if not os.path.exists(path):
        return None
    tmp = path + ".locktest"
    try:
        os.rename(path, tmp)
        os.rename(tmp, path)
        return False
    except OSError:
        return True


def show():
    d = fc.driver_leftovers()
    sysfile = os.path.join(ROOT, "third_party", "windivert", "WinDivert64.sys")
    locked = is_locked(sysfile)

    print("=" * 68)
    print("  FragDPI 驱动残留检查")
    print("=" * 68)
    print("  管理员权限   : %s" % ("是" if fc.is_admin() else "否（清理需要管理员）"))
    print("  驱动服务     : %s" % (
        "存在 · " + STATE_NAME.get(d["service_state"], str(d["service_state"]))
        if d["service_exists"] else "不存在 ✅"))
    print("  System32 驱动: %s" % (d["sys32_driver"] or "无"))
    print("  仓库 .sys 锁 : %s" % (
        "—（文件不存在）" if locked is None else
        ("🔴 被锁住（这就是文件夹删不掉的原因）" if locked else "未锁 ✅")))
    print("  内存完整性   : %s" % (
        "🔴 已启用 —— WinDivert 驱动会被拦下（WinDivertOpen 报 1450），拦截功能用不了"
        if d["hvci"] else ("未启用 ✅" if d["hvci"] is False else "读取不到")))
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
    print("=" * 68)
    return 0


def clean():
    d = fc.driver_leftovers()
    if not d["service_exists"]:
        print("驱动服务不存在，无需清理。")
    elif d["service_running"]:
        print("✗ 驱动服务正在运行（有程序在用），拒绝清理以免打断别的程序。")
        print("  请先关闭使用 WinDivert 的程序，再重试。")
        return 1
    else:
        if not fc.is_admin():
            print("✗ 清理需要管理员权限。请用 cleanup_driver.cmd（会自动提权）")
            print("  或以管理员身份运行：python tools/cleanup_driver.py --clean")
            return 1
        ok, msg = fc.uninstall_driver()
        print(("✓ " if ok else "✗ ") + msg)
        if not ok:
            return 1

    sysfile = os.path.join(ROOT, "third_party", "windivert", "WinDivert64.sys")
    locked = is_locked(sysfile)
    if locked:
        print("⚠ 仓库里的 WinDivert64.sys 仍被锁 —— 可能还有进程在用它。")
        print("  用任务管理器结束残留的 python.exe 后再试，或重启一次。")
    elif locked is False:
        print("✓ 仓库里的 WinDivert64.sys 已可自由删除，文件夹现在删得掉了。")
    return 0


def main():
    fc.init_console()
    if "--clean" in sys.argv or "-c" in sys.argv:
        return clean()
    return show()


if __name__ == "__main__":
    sys.exit(main())
