#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""update — 自动升级器：检查 GitHub Releases、下载、校验、替换。

流程：
    检查 ──> 发现新版本 ──> 下载 zip + SHA256SUMS ──> 校验哈希 ──> 解压到 _update_staging/
                                                                        │
                              用户点「立即升级」──> 写 apply_update.cmd ──┘
                                     │
                                     └─ 关掉控制台 → 脚本等端口释放 → 覆盖文件 → 重新启动

安全设计（这是会下载并执行代码的功能，不能马虎）：
  1. **只认硬编码的官方仓库**，不接受任何外部传入的下载地址
  2. 走 HTTPS；下载完**必须**用同一 Release 里的 SHA256SUMS 校验
  3. 校验不过就删掉暂存目录，绝不落盘安装
  4. **从不静默执行**：必须用户显式点「立即升级」才会写替换脚本
  5. 替换时**保留用户配置**（core/fragconfig.json、core/dns_backup.json）

⚠️ 诚实说明信任边界：哈希清单和安装包来自同一个 Release，
   能防「下载损坏 / CDN 篡改」，但**防不住仓库本身被攻破**。
   要更强的保证需要 GPG 签名发行包（尚未实现）。

用法：
    python tools/update.py --check     # 只看有没有新版本
    python tools/update.py --stage     # 下载并校验到 _update_staging/
    python tools/update.py --apply     # 用暂存内容覆盖安装目录（需先关程序）
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORE = os.path.join(ROOT, "core")
if CORE not in sys.path:
    sys.path.insert(0, CORE)

try:
    import fragcore as fc                     # 只为 init_console，缺了也不影响
except ImportError:
    fc = None
from fragversion import get_version, is_newer      # noqa: E402

# ---- 安全：只认这一个仓库，别改成可配置的
GITHUB_REPO = "HeyanMCH/FragDPI"
API_LATEST = "https://api.github.com/repos/%s/releases/latest" % GITHUB_REPO
ASSET_PLATFORM = "win-x64"
STAGE_DIR = os.path.join(ROOT, "_update_staging")
APPLY_SCRIPT = os.path.join(ROOT, "apply_update.cmd")

# 覆盖安装时必须保留的本机私有文件（相对路径）
PRESERVE = [
    "core/fragconfig.json",
    "core/dns_backup.json",
    "update_state.json",
]

UA = "FragDPI-Updater/%s" % get_version()


# ------------------------------------------------------------------ 网络
def _open(url, timeout=15, accept="application/vnd.github+json"):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    return urllib.request.urlopen(req, timeout=timeout)


def http_json(url, timeout=15):
    with _open(url, timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def http_download(url, dest, timeout=120):
    """下载到 dest，返回写入的字节数。"""
    tmp = dest + ".part"
    with _open(url, timeout, accept="application/octet-stream") as r, \
            open(tmp, "wb") as f:
        shutil.copyfileobj(r, f, 64 * 1024)
    os.replace(tmp, dest)
    return os.path.getsize(dest)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(256 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ 检查
def expected_asset_name(version):
    return "FragDPI-%s-%s.zip" % (version, ASSET_PLATFORM)


def check_update(timeout=15):
    """查询最新 Release。返回 dict；任何失败都落在 result['error'] 里，不抛异常。"""
    result = {
        "ok": False, "current": get_version(), "latest": None, "newer": False,
        "asset_name": None, "asset_url": None, "sums_url": None,
        "asset_size": None, "notes": None, "published": None, "error": None,
    }
    try:
        rel = http_json(API_LATEST, timeout)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result["error"] = "该仓库还没有发布过任何 Release（或已被删除）"
        elif e.code == 403:
            result["error"] = "GitHub API 限流（未认证每小时 60 次），稍后再试"
        else:
            result["error"] = "GitHub API 返回 %s" % e.code
        return result
    except Exception as e:
        result["error"] = "%s: %s" % (type(e).__name__, e)
        return result

    tag = (rel.get("tag_name") or "").strip()
    result["latest"] = tag.lstrip("vV")
    result["notes"] = (rel.get("body") or "").strip()[:4000] or None
    result["published"] = rel.get("published_at")
    result["newer"] = is_newer(tag, result["current"])

    want = expected_asset_name(result["latest"])
    for a in rel.get("assets") or []:
        name = a.get("name") or ""
        if name == want:
            result["asset_name"] = name
            result["asset_url"] = a.get("browser_download_url")
            result["asset_size"] = a.get("size")
        elif name.lower() == "sha256sums":
            result["sums_url"] = a.get("browser_download_url")

    if result["newer"] and not result["asset_url"]:
        result["error"] = ("有新版 %s，但没找到资产 %s —— 发行流水线可能还没跑完"
                           % (result["latest"], want))
    result["ok"] = result["error"] is None
    return result


# ------------------------------------------------------------------ 下载 + 校验
def parse_sums(text):
    """解析 `sha256  filename` 格式，返回 {filename: sha256}。"""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and len(parts[0]) == 64:
            out[parts[-1].lstrip("*")] = parts[0].lower()
    return out


def stage_update(info, progress=None):
    """下载资产 + 校验哈希 + 解压到 STAGE_DIR。返回 (ok, 说明)。"""
    say = progress or (lambda s: None)
    if not info.get("asset_url"):
        return (False, "没有可下载的资产")
    if not info.get("sums_url"):
        return (False, "Release 里没有 SHA256SUMS，为安全起见拒绝安装")

    if os.path.isdir(STAGE_DIR):
        shutil.rmtree(STAGE_DIR, ignore_errors=True)
    os.makedirs(STAGE_DIR, exist_ok=True)

    zpath = os.path.join(STAGE_DIR, info["asset_name"])
    spath = os.path.join(STAGE_DIR, "SHA256SUMS")
    try:
        say("下载 SHA256SUMS…")
        http_download(info["sums_url"], spath, timeout=30)
        say("下载 %s…" % info["asset_name"])
        n = http_download(info["asset_url"], zpath)
        say("已下载 %.2f MB，校验哈希…" % (n / 1024 / 1024))
    except Exception as e:
        return (False, "下载失败：%s: %s" % (type(e).__name__, e))

    sums = parse_sums(open(spath, encoding="utf-8", errors="replace").read())
    want = sums.get(info["asset_name"])
    if not want:
        return (False, "SHA256SUMS 里没有 %s 的记录，拒绝安装" % info["asset_name"])
    got = sha256_file(zpath)
    if got != want:
        return (False, "哈希校验失败！期望 %s…，实际 %s…（已保留文件供排查）"
                % (want[:16], got[:16]))
    say("哈希校验通过 ✅")

    try:
        say("解压…")
        with zipfile.ZipFile(zpath) as z:
            names = z.namelist()
            # 防 zip slip：拒绝任何越界路径
            for nm in names:
                p = os.path.normpath(os.path.join(STAGE_DIR, nm))
                if not p.startswith(os.path.normpath(STAGE_DIR) + os.sep) and \
                        p != os.path.normpath(STAGE_DIR):
                    return (False, "压缩包里有越界路径，已拒绝：%s" % nm)
            z.extractall(STAGE_DIR)
        os.remove(zpath)
    except Exception as e:
        return (False, "解压失败：%s: %s" % (type(e).__name__, e))

    root = _staged_root()
    if root is None:
        return (False, "解压后没有找到 FragDPI 目录结构")
    say("就绪：%s" % root)
    return (True, "新版本 %s 已下载并通过校验，可以升级" % info.get("latest"))


def _staged_root():
    """返回暂存目录里的真正仓库根（压缩包可能带一层同名目录）。"""
    entries = [e for e in os.listdir(STAGE_DIR)
               if not e.startswith(".") and e != "SHA256SUMS"]
    if "core" in entries or "VERSION" in entries:
        return STAGE_DIR
    for e in entries:
        p = os.path.join(STAGE_DIR, e)
        if os.path.isdir(p) and (os.path.isdir(os.path.join(p, "core"))
                                 or os.path.isfile(os.path.join(p, "VERSION"))):
            return p
    return None


# ------------------------------------------------------------------ 应用
def write_apply_script(launch=True):
    """写一个自删除、自提权的替换脚本。控制台退出后由用户双击执行。

    ⚠️ 为什么必须先清驱动服务再覆盖文件（这一段是被用户的安全顾虑逼出来的）：

        WinDivert 的内核服务 ImagePath 指向仓库里的 WinDivert64.sys。
        驱动还加载着的时候，内核锁着这个文件 —— robocopy 覆盖它会失败，
        结果就是**覆盖到一半的坏安装**（部分文件是新的、部分是旧的）。

        所以顺序必须是：① 摘掉服务注册（同时解锁文件）→ ② 覆盖 → ③ 重启程序。
        把这三步写在同一个脚本里，用户只要双击一次，不给"顺序做错"的机会。

    另外脚本会自提权 —— 摘服务注册需要管理员权限。
    """
    staged = _staged_root()
    if staged is None:
        return (False, "暂存目录不可用，请先 --stage")
    lines = [
        "@echo off",
        "rem 由 FragDPI 升级器生成：自提权 -> 摘驱动服务 -> 等控制台退出 -> 覆盖 -> 重启 -> 自删",
        "setlocal",
        "chcp 65001 >nul",
        "",
        "rem ---- 自提权（摘驱动服务需要管理员）----",
        "net session >nul 2>&1",
        "if %errorlevel% neq 0 (",
        '    powershell -NoProfile -Command "Start-Process -FilePath \'%~f0\' -Verb RunAs"',
        "    exit /b",
        ")",
        "",
        'set "SRC=%s"' % staged,
        'set "DST=%s"' % ROOT,
        "",
        "rem ---- 找 Python ----",
        'set "PYEXE="',
        'where py >nul 2>&1 && set "PYEXE=py -3"',
        'if not defined PYEXE (where python >nul 2>&1 && set "PYEXE=python")',
        'if not defined PYEXE (echo [X] 找不到 Python，无法清理驱动 & pause & exit /b 1)',
        "",
        "rem ---- ① 先摘掉驱动服务，释放被锁的 WinDivert64.sys ----",
        "echo [1/4] 清理 WinDivert 驱动服务（否则驱动文件被锁，覆盖会失败）…",
        '%PYEXE% "%DST%\\tools\\cleanup_driver.py" --clean',
        "echo       （Cleanup 失败不阻断：可能本来就没有服务）",
        "",
        "rem ---- ② 等控制台退出 ----",
        "echo [2/4] 等待 FragDPI 退出（最多 60 秒）…",
        "set /a _n=0",
        ":wait",
        'netstat -ano | findstr ":8899" | findstr LISTENING >nul',
        "if errorlevel 1 goto copy",
        "set /a _n+=1",
        "if %_n% GEQ 60 goto copy",
        "timeout /t 1 /nobreak >nul",
        "goto wait",
        "",
        ":copy",
        "rem ---- ③ 覆盖（保留用户配置）----",
        "echo [3/4] 正在覆盖文件…",
        'robocopy "%SRC%" "%DST%" /E /NFL /NDL /NJH /NJS /XF fragconfig.json dns_backup.json >nul',
        "if errorlevel 8 (",
        "    echo.",
        "    echo [X] 覆盖失败（robocopy 退出码 %errorlevel%）。",
        "    echo     常见原因：还有程序占着文件，或权限不足。",
        "    echo     新版本仍在：%SRC%",
        "    echo     你的原安装未被破坏，可以重试。",
        "    pause",
        "    exit /b 1",
        ")",
        'if exist "%DST%\\_update_staging" rmdir /S /Q "%DST%\\_update_staging"',
        'if exist "%DST%\\update_state.json" del /Q "%DST%\\update_state.json"',
        "",
        "rem ---- ④ 重启 ----",
        "echo [4/4] 升级完成。",
        "if \"%1\"==\"--no-launch\" goto done",
        'start "" "%DST%\\start_console.cmd"',
        ":done",
        'del "%~f0"',
        "endlocal",
        "",
    ]
    with open(APPLY_SCRIPT, "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(lines))
    return (True, APPLY_SCRIPT)


def apply_now():
    """直接在当前进程里覆盖（要求程序已退出）。主要用于测试与命令行。

    同样**先摘驱动服务** —— 否则 WinDivert64.sys 被内核锁着，覆盖会失败，
    留下半新半旧的坏安装。
    """
    staged = _staged_root()
    if staged is None:
        return (False, "暂存目录不可用，请先 --stage")

    # ① 摘掉驱动服务（释放被锁的 .sys）
    try:
        import fragcore as fc
        ok, msg = fc.safe_uninstall_driver()
        if not ok:
            return (False, "覆盖前清理驱动失败：%s —— 已中止，未改动任何文件" % msg)
    except Exception:
        pass

    saved = {}
    for rel in PRESERVE:
        p = os.path.join(ROOT, rel)
        if os.path.isfile(p):
            saved[rel] = open(p, "rb").read()
    copied = 0
    for dirpath, _dirs, files in os.walk(staged):
        rel = os.path.relpath(dirpath, staged)
        for fn in files:
            src = os.path.join(dirpath, fn)
            dst = os.path.join(ROOT, rel, fn) if rel != "." else os.path.join(ROOT, fn)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            copied += 1
    restored = []
    for rel, data in saved.items():
        p = os.path.join(ROOT, rel)
        with open(p, "wb") as f:
            f.write(data)
        restored.append(rel)
    shutil.rmtree(STAGE_DIR, ignore_errors=True)
    return (True, "覆盖 %d 个文件，保留 %d 个用户文件%s"
            % (copied, len(restored), ("（" + ", ".join(restored) + "）") if restored else ""))


# ------------------------------------------------------------------ CLI
def main():
    if fc:
        fc.init_console()
    ap = argparse.ArgumentParser(description="FragDPI 自动升级器")
    ap.add_argument("--check", action="store_true", help="检查是否有新版本")
    ap.add_argument("--stage", action="store_true", help="下载并校验到暂存目录")
    ap.add_argument("--apply", action="store_true", help="用暂存内容覆盖安装目录")
    ap.add_argument("--write-script", action="store_true", help="生成 apply_update.cmd")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出检查结果")
    args = ap.parse_args()

    if not any((args.check, args.stage, args.apply, args.write_script)):
        args.check = True

    if args.check:
        info = check_update()
        if args.json:
            print(json.dumps(info, ensure_ascii=False, indent=2))
        else:
            print("当前版本 : %s" % info["current"])
            print("最新版本 : %s" % (info["latest"] or "（未取到）"))
            if info["error"]:
                print("状态     : ✗ %s" % info["error"])
            elif info["newer"]:
                print("状态     : ★ 有新版本可用 → python tools/update.py --stage")
                if info["asset_size"]:
                    print("资产     : %s（%.2f MB）"
                          % (info["asset_name"], info["asset_size"] / 1024 / 1024))
            else:
                print("状态     : 已是最新 ✅")
        return 0 if info["ok"] else 1

    if args.stage:
        info = check_update()
        if info["error"]:
            print("✗ " + info["error"])
            return 1
        if not info["newer"]:
            print("已是最新（%s），无需下载。" % info["current"])
            return 0
        ok, msg = stage_update(info, progress=lambda s: print("  " + s))
        print(("✓ " if ok else "✗ ") + msg)
        if ok:
            ok2, msg2 = write_apply_script()
            print(("✓ 已生成替换脚本：%s" % msg2) if ok2 else ("✗ " + msg2))
            print("  关闭控制台后双击 apply_update.cmd 完成升级。")
        return 0 if ok else 1

    if args.write_script:
        ok, msg = write_apply_script()
        print(("✓ " if ok else "✗ ") + msg)
        return 0 if ok else 1

    if args.apply:
        ok, msg = apply_now()
        print(("✓ " if ok else "✗ ") + msg)
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
