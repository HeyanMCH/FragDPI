@echo off
chcp 65001 >nul
title fragdpi - 命令行版首包分片
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo.
  echo  [!] 需要管理员权限来加载 WinDivert 驱动，正在申请提权...
  echo.
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "PYCMD="
where py.exe >nul 2>&1
if not errorlevel 1 set "PYCMD=py -3"
if not defined PYCMD (
  where python.exe >nul 2>&1
  if not errorlevel 1 set "PYCMD=python"
)
if not defined PYCMD (
  echo  [X] 未找到 Python，请安装 Python 3.8+ 并加入 PATH。
  pause
  exit /b 1
)

echo  ============================================================
echo   fragdpi  -  命令行版首包分片^(无 GUI^)
echo ------------------------------------------------------------
echo   过滤 : 出站 TCP 443，所有程序生效，无需代理
echo   停止 : 本窗口按 Ctrl+C
echo   提示 : 想要图形界面请用根目录的 start_console.cmd
echo  ============================================================
echo.

%PYCMD% "%~dp0fragdpi.py" --selftest %*

echo.
echo fragdpi 已退出，按任意键关闭窗口...
pause >nul
