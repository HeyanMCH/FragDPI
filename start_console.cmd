@echo off
chcp 65001 >nul
title FRAG//DPI 控制台
cd /d "%~dp0"

rem ============================================================
rem  需要管理员权限才能加载 WinDivert 内核驱动
rem ============================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo.
  echo  [!] 需要管理员权限来加载 WinDivert 驱动，正在申请提权...
  echo.
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

rem ============================================================
rem  定位 Python 3：优先用 py 启动器，其次用 PATH 里的 python
rem ============================================================
set "PYCMD="
where py.exe >nul 2>&1
if not errorlevel 1 set "PYCMD=py -3"
if not defined PYCMD (
  where python.exe >nul 2>&1
  if not errorlevel 1 set "PYCMD=python"
)
if not defined PYCMD (
  echo.
  echo  [X] 未找到 Python。请先安装 Python 3.8 或更高版本，
  echo      安装时务必勾选 "Add python.exe to PATH"。
  echo      https://www.python.org/downloads/windows/
  echo.
  pause
  exit /b 1
)
%PYCMD% -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if errorlevel 1 (
  echo.
  echo  [X] Python 版本过低，需要 3.8 或更高版本。
  echo.
  pause
  exit /b 1
)

echo  ============================================================
echo   FRAG//DPI  -  首包分片控制台
echo ------------------------------------------------------------
echo   控制台   : http://127.0.0.1:8899/   ^(自动打开浏览器^)
echo   引擎     : 拦截出站 TCP 443，所有程序自动生效，无需设置代理
echo   工作模式 : 关闭 / 规则模式^(内置游戏预设^) / 全局模式
echo   参数     : 分片参数与规则均可在网页上实时修改
echo   停止     : 本窗口按 Ctrl+C，或双击 stop_console.cmd
echo  ============================================================
echo.

%PYCMD% "%~dp0core\fragserver.py" %*

echo.
echo 控制台已退出，按任意键关闭窗口...
pause >nul
