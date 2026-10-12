@echo off
rem ============================================================
rem  restore_dns.cmd - 一键复原系统 DNS
rem
rem  加密 DNS（DoT/DoH）接管系统时会把原配置备份到
rem  core\dns_backup.json。正常退出会自动复原；这个脚本用于
rem  控制台异常退出后的手动恢复。
rem
rem  需要管理员权限（会自动提权）。
rem ============================================================
setlocal

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] 需要管理员权限，正在请求提权...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "HERE=%~dp0"
set "PYEXE="

rem 按优先级找 Python（与 stop_console.cmd 同一套探测逻辑）
where py >nul 2>&1 && (py -3 -c "import sys" >nul 2>&1 && set "PYEXE=py -3")

if not defined PYEXE (
    where python >nul 2>&1 && set "PYEXE=python"
)

if not defined PYEXE (
    echo [X] 找不到可用的 Python 3，请安装后重试。
    pause
    exit /b 1
)

chcp 65001 >nul

if not exist "%HERE%core\dns_backup.json" (
    echo [i] 没有找到 DNS 备份文件 —— 当前没有待复原的接管。
    pause
    exit /b 0
)

echo [*] 正在按备份复原系统 DNS...
%PYEXE% "%HERE%tools\doh_stub.py" --off
if %errorlevel% neq 0 (
    echo [X] 复原失败。请手动执行：
    echo     %PYEXE% "%HERE%tools\doh_stub.py" --off
    pause
    exit /b 1
)

echo.
echo [✓] 系统 DNS 已复原。
echo     若个别网卡仍异常，可到「设置 - 网络 - 适配器选项」里把 DNS 改回自动。
pause
