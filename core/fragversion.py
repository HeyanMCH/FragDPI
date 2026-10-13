#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fragversion — 版本号的**唯一来源**读取器。

版本号写在仓库根目录的 `VERSION` 文件里（纯文本，一行，如 `1.1.0`）。
Python 侧、控制台 UI、升级器、以及 GitHub Actions 的发行流水线全都读它 ——
避免「代码里写 1.1.0、tag 打成 v1.2.0」这种漂移。

为什么不用 `__version__` 硬编码在某个模块里：流水线要在打包前就知道版本号，
而且用户看到的是发行包名 `FragDPI-1.1.0-win-x64.zip`。一个纯文本文件对
Python 和 shell 都最好读。
"""
import os
import re

FALLBACK = "0.0.0"
_HERE = os.path.dirname(os.path.abspath(__file__))


def find_version_file():
    """从本文件起向上找 VERSION（兼容 core/ 与打包后扁平放置两种布局）。"""
    d = _HERE
    for _ in range(4):
        p = os.path.join(d, "VERSION")
        if os.path.isfile(p):
            return p
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def get_version():
    """返回版本号字符串。读不到就回退到 FALLBACK（绝不让它抛异常）。"""
    p = find_version_file()
    if not p:
        return FALLBACK
    try:
        with open(p, encoding="utf-8") as f:
            v = f.read().strip()
        return v or FALLBACK
    except OSError:
        return FALLBACK


def parse_version(text):
    """把 'v1.2.3' / '1.2.3' / '1.2.3-beta.1' 解析成可比较的元组。

    返回 (major, minor, patch, pre) —— pre 为空串表示正式版，
    正式版永远大于同号预发布版（1.2.0 > 1.2.0-beta）。
    """
    s = (text or "").strip().lstrip("vV")
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:[-+](.*))?$", s)
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    return (int(major), int(minor), int(patch), pre or "")


def is_newer(candidate, current):
    """candidate 是否比 current 新。任一个解析不了时返回 False（宁可不升级）。"""
    a, b = parse_version(candidate), parse_version(current)
    if a is None or b is None:
        return False
    if a[:3] != b[:3]:
        return a[:3] > b[:3]
    if a[3] == b[3]:
        return False
    if not a[3]:
        return True                    # 正式版 > 预发布版
    if not b[3]:
        return False
    return a[3] > b[3]


__version__ = get_version()

if __name__ == "__main__":
    print(__version__)
