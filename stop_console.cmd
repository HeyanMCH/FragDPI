@echo off
chcp 65001 >nul
title FRAG//DPI 控制台 - 停止
cd /d "%~dp0"

rem 控制台是提权运行的，普通权限结束不了它的进程
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo.
  echo  [!] 需要管理员权限才能结束提权运行的控制台，正在申请提权...
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
echo   FRAG//DPI  -  停止控制台^(结束占用 8899 的进程^)
echo  ============================================================
echo.
%PYCMD% "%~dp0stop_console.py"
echo.
echo 按任意键关闭窗口...
pause >nul
