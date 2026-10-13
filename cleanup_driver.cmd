@echo off
rem ============================================================
rem  cleanup_driver.cmd - 清理 WinDivert 驱动残留
rem
rem  解决「用过 FragDPI 之后，文件夹删不掉 / 移不走」的问题。
rem  原因：WinDivert 的内核服务 ImagePath 指向本仓库里的
rem  third_party\windivert\WinDivert64.sys，驱动加载期间该文件被内核锁住。
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

echo.
%PYEXE% "%HERE%tools\cleanup_driver.py" --clean
set "RC=%errorlevel%"

echo.
if "%RC%"=="0" (
    echo [i] 现在可以删除或移动 FragDPI 文件夹了。
) else (
    echo [i] 未能完成清理，请看上面的提示。
    echo     也可只查看状态： %PYEXE% "%HERE%tools\cleanup_driver.py"
)
pause
exit /b %RC%
