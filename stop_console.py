#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""停止控制台 —— 找到监听 8899 的进程并结束它。

控制台是提权运行的，普通权限结束不了，所以本脚本也要提权跑
（由 stop_console.cmd 自动提权）。

用 ctypes 直接调 TerminateProcess，不依赖 taskkill / netstat 外部命令。
"""
import ctypes
import os
import socket
import sys

PORT = 8899
PROCESS_TERMINATE = 0x0001

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.OpenProcess.restype = ctypes.c_void_p
_k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
_k32.TerminateProcess.restype = ctypes.c_int
_k32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
_k32.CloseHandle.restype = ctypes.c_int
_k32.CloseHandle.argtypes = [ctypes.c_void_p]

# GetExtendedTcpTable —— 不依赖 netstat，直接问内核要 TCP 表
AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5


def listening_pids(port):
    size = ctypes.c_uint32(0)
    _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    _iphlpapi.GetExtendedTcpTable.restype = ctypes.c_uint32
    _iphlpapi.GetExtendedTcpTable.argtypes = [ctypes.c_void_p,
                                              ctypes.POINTER(ctypes.c_uint32),
                                              ctypes.c_int, ctypes.c_uint32,
                                              ctypes.c_int, ctypes.c_uint32]
    # 第一次调用拿所需长度
    if _iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False,
                                     AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 122:
        pass
    buf = ctypes.create_string_buffer(size.value)
    if _iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False,
                                     AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0:
        return set()
    n = ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32)).contents.value
    pids = set()
    row = 24                                     # MIB_TCPROW_OWNER_PID 结构大小
    base = ctypes.addressof(buf) + 4
    for i in range(n):
        r = ctypes.string_at(base + i * row, row)
        state = int.from_bytes(r[0:4], "little")
        lport = socket.ntohs(int.from_bytes(r[8:12], "little") & 0xFFFF)
        pid = int.from_bytes(r[20:24], "little")
        if state == 2 and lport == port:          # 2 = LISTEN
            pids.add(pid)
    return pids


def kill(pid):
    h = _k32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        return False, "OpenProcess 失败，错误码 %d（多半是权限不足）" % ctypes.get_last_error()
    try:
        if not _k32.TerminateProcess(h, 1):
            return False, "TerminateProcess 失败，错误码 %d" % ctypes.get_last_error()
        return True, "已结束"
    finally:
        _k32.CloseHandle(h)


def init_console():
    """把 stdout/stderr 切到 UTF-8，避免中文在「被重定向」时把脚本弄崩。

    真控制台上 Python 走 WriteConsoleW、本来就是 UTF-8；但输出被重定向到管道/文件时，
    编码会退化成系统 ANSI 代码页（英文 Windows 的 cp1252 编不了中文 → UnicodeEncodeError）。
    实现与 core/fragcore.py 的同名函数一致。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            try:
                stream.reconfigure(errors="replace")
            except Exception:
                pass


def main():
    init_console()
    pids = listening_pids(PORT)
    if not pids:
        print("没有进程在监听 %d，无需停止。" % PORT)
        return 0
    ok_all = True
    for pid in sorted(pids):
        ok, msg = kill(pid)
        print("  pid=%-7d %s%s" % (pid, msg, "" if ok else "  ✗"))
        ok_all = ok_all and ok
    if not ok_all:
        print("\n  提示：控制台是提权运行的，请用 stop_console.cmd 提权后再试。")
        return 1
    print("\n控制台已停止。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
