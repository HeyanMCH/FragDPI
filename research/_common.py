# -*- coding: utf-8 -*-
"""research/ 下各探测脚本的公共工具。

这些脚本最初是在一台具体机器上写的，里面硬编码过本机网关地址和绝对输出路径。
开源后统一改成「自动探测 + 脚本相对路径」，这样换台机器也能直接跑，
也避免把作者的局域网信息带进仓库。
"""
import os
import re
import subprocess

RESEARCH_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(RESEARCH_DIR)

# 国内常用的公共 DNS，作为对比基准（不依赖本机网络）
PUBLIC_DNS = ["223.5.5.5", "119.29.29.29", "114.114.114.114"]


def default_gateway():
    """自动探测默认网关，失败返回 None。"""
    try:
        if os.name == "nt":
            out = subprocess.run(
                ["ipconfig"], capture_output=True, text=True,
                encoding="gbk", errors="replace", timeout=15).stdout
            for line in out.splitlines():
                # 中英文 Windows 的字段名都覆盖
                if ("Default Gateway" in line or "默认网关" in line
                        or "缺省网关" in line):
                    ips = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
                    if ips:
                        return ips[0]
        else:
            out = subprocess.run(["ip", "route"], capture_output=True,
                                 text=True, timeout=10).stdout
            for line in out.splitlines():
                if line.startswith("default"):
                    return line.split()[2]
    except Exception:
        pass
    return None


def dns_servers(include_gateway=True):
    """返回探测用的 DNS 服务器列表：本机网关（可选）+ 公共 DNS。"""
    servers = []
    if include_gateway:
        gw = default_gateway()
        if gw:
            servers.append(gw)
    return servers + PUBLIC_DNS


def out_path(name):
    """结果文件统一写在本脚本所在目录，而不是写死在作者机器的绝对路径。"""
    return os.path.join(RESEARCH_DIR, name)


if __name__ == "__main__":
    print("默认网关:", default_gateway())
    print("DNS 列表:", dns_servers())
    print("输出目录:", RESEARCH_DIR)
