# third_party/windivert

本目录里的两个二进制文件不是本项目的代码，而是 **WinDivert 2.2（x64）官方发行版**的原始文件，
原样打包进来，未做任何修改。FragDPI 的所有拦截/注入能力都建立在它们之上。

| 文件 | 大小 | 说明 |
|---|---|---|
| `WinDivert.dll` | 47,616 B | 用户态 DLL，通过 `ctypes` 动态加载 |
| `WinDivert64.sys` | 94,144 B | 内核态驱动（已由上游数字签名，否则 x64 Windows 不会加载） |
| `LICENSE.LGPL-3.0.txt` | 40,941 B | LGPL-3.0 许可证全文（官方以 LGPL+GPL 合并文档形式发布） |

- 上游：<https://reqrypt.org/windivert.html> · 源码：<https://github.com/basil00/Divert>
- 版权：Copyright (C) 2011-2022 Basil
- 许可证：**GNU LGPL-3.0**

## SHA-256（请自行校验）

```text
WinDivert.dll           c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2
WinDivert64.sys         8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2
LICENSE.LGPL-3.0.txt    e5453b2e71e4c4dcdb89a2539655add3a63202521cf3012b768e8bfeda199312
```

```bat
certutil -hashfile WinDivert.dll SHA256
```

## 为什么可以直接打包

LGPL-3.0 允许在**不分发库源码**的情况下随应用一起分发库的二进制，只要满足：

1. 告知使用者这是 LGPL 库、并附上许可证全文 → 见本文件与 `LICENSE.LGPL-3.0.txt`；
2. 使用者能用自己的版本替换掉这个库 → 这里是「独立 DLL + 运行时动态加载」，
   直接覆盖同名文件即可，天然满足；
3. 提供获取库源码的途径 → 上面已给出上游地址。

FragDPI 自身代码与 WinDivert 是**动态加载、进程内链接**的关系（`ctypes.WinDLL`），
不是静态链接、也没有改动过它的代码，因此 **LGPL 不会传染到本项目**。
本项目自己的代码使用 Apache-2.0，详见仓库根目录的 `LICENSE` 与 `NOTICE`。

## 想自己重新下载/升级

1. 到 <https://reqrypt.org/windivert.html> 或 <https://github.com/basil00/Divert/releases>
   下载 **WinDivert-2.2.x-A.zip**（x64）；
2. 从 `x64/` 目录里取出 `WinDivert.dll` 与 `WinDivert64.sys` 覆盖本目录；
3. 跑一次 `python tools/fragdpi.py --selfcheck` 确认新版本仍能正常加载。

> 只替换 `.dll` 而不替换 `.sys`（或反过来）版本不匹配时会加载失败，
> 请成对替换。升级后请更新本文件的哈希值与 `../NOTICE`。
