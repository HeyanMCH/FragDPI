@echo off
chcp 65001 >nul
title fragproxy - 本地分片代理
cd /d "%~dp0"

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

echo.
echo  ============================================================
echo   fragproxy  -  本地首包分片代理^(不需要管理员权限^)
echo ------------------------------------------------------------
echo   代理地址 : 127.0.0.1:8888
echo   PAC 地址 : http://127.0.0.1:8888/proxy.pac
echo   停止     : 本窗口按 Ctrl+C
echo   注意     : 只对走 HTTP 代理的程序生效；要覆盖全部程序
echo              请改用根目录的 start_console.cmd
echo  ============================================================
echo.

%PYCMD% "%~dp0fragproxy.py" %*

echo.
echo 代理已退出，按任意键关闭窗口...
pause >nul
