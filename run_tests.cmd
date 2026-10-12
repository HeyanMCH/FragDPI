@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem ---------------------------------------------------------------- 找 Python
set "PYCMD="
where py.exe >nul 2>&1
if not errorlevel 1 set "PYCMD=py -3"
if not defined PYCMD (
  where python.exe >nul 2>&1
  if not errorlevel 1 set "PYCMD=python"
)
if not defined PYCMD (
  echo.
  echo   [X] 没有找到 Python。请先安装 Python 3.8 或更高版本，安装时勾选 "Add to PATH"。
  echo.
  pause
  exit /b 1
)

echo ============================================================
echo   FragDPI 测试  -  不需要管理员权限
echo ============================================================
echo.

echo [1/3] 单元测试（SNI 解析 / 规则匹配 / 分片与还原 / seq 连续性）
%PYCMD% -m unittest discover -s tests -v
if errorlevel 1 goto fail
echo.

echo [2/3] 离线算法 + 校验和验证（加载捆绑的 WinDivert.dll）
%PYCMD% "tools\fragdpi.py" --packettest
if errorlevel 1 goto fail
echo.

echo [3/3] 二进制与权限自检（拦截功能需要管理员权限）
%PYCMD% "tools\fragdpi.py" --selfcheck
echo.

echo ============================================================
echo   全部通过 ✅
echo ============================================================
echo.
pause
exit /b 0

:fail
echo.
echo ============================================================
echo   有测试失败 ❌  见上方输出
echo ============================================================
echo.
pause
exit /b 1
