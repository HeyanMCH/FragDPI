# FragDPI · Android 版

> **状态：v0.1.0 能用但覆盖有限。** 请先读完「能力边界」再决定要不要装。

把桌面版的「首包分片」核心搬到了 Android。核心逻辑（SNI 解析 + 切点计算 + 分段）
是纯 Java，**不碰任何 Android API**，所以能在普通 JVM 上跑单测 ——
这部分有 **86 项单测 + 19 项真实 socket 端到端验证**守着。

---

## 能力边界（重要，别跳过）

| 场景 | 是否覆盖 | 原因 |
|---|---|---|
| 走**系统代理**的应用（浏览器、多数 App） | ✅ 覆盖 | 把 Wi-Fi 代理指向本机端口即可 |
| **不走系统代理**的应用（多数游戏客户端用裸 socket） | ❌ 不覆盖 | 需要 VpnService + 用户态 TCP 栈，见「路线图」 |
| 需要 root | ❌ 不需要 | 本方案完全不依赖 root |

**为什么不做 VpnService 就当没做**：Android 上用 VpnService 无根接管全量流量，
必须把 TUN 里的 IP 包交给一个用户态 TCP 栈（tun2socks 之类）再转发给本地代理。
没做完就把 TUN 挂上，用户流量会被**黑洞掉** —— 那比不做更糟。
所以这一版刻意只做「本地代理 + 手动指系统代理」这个能真跑通的子集。

---

## 怎么用

1. 安装 APK（见下）
2. 打开 App → 点「启动」（默认监听 `127.0.0.1:8443`，可在界面改）
3. 打开 **Wi-Fi 设置 → 当前网络 → 代理 → 手动**
   - 主机名 `127.0.0.1`，端口填 App 里显示的那个
4. 回浏览器试被拦的站点

> ⚠️ Wi-Fi 代理只对**当前网络**生效，换网络要重设，用完记得关掉。
> ⚠️ 手机上装东西前请自行确认合规性 —— 见仓库根 README 的免责声明。

---

## 怎么构建

**不需要 Gradle**（本仓库刻意不依赖它）。用 Android SDK 自带的
`aapt2 + javac + d8 + zipalign + apksigner` 直接出签名 APK：

```bash
# 需要：JDK 17+、Android SDK（设置 ANDROID_SDK_ROOT 或 ANDROID_HOME）
bash android/build_apk.sh
# 产物：android/dist/FragDPI-android-0.1.0.apk
```

脚本会按平台自动选 `aapt2.exe`/`aapt2`，并在缺密钥库时生成一个本地调试 keystore
（`android/debug.keystore`，**不要用于正式发布**）。

安装：
```bash
adb install -r android/dist/FragDPI-android-0.1.0.apk
```
或把 APK 拷到手机点开安装（需允许「安装未知来源应用」）。

---

## 怎么跑测试

核心逻辑不依赖 Android，可以直接用 JVM 跑：

```bash
mkdir -p out
# ⚠️ 只编这 4 个文件。MainActivity / ProxyService 依赖 android.jar，
#    用 *.java 通配把它们带进来会炸出上百个 "package android.app does not exist"。
javac -encoding UTF-8 -d out \
  android/app/src/com/fragdpi/android/FragCore.java \
  android/app/src/com/fragdpi/android/FragProxy.java \
  android/app/src/com/fragdpi/android/FragCoreTest.java \
  android/app/src/com/fragdpi/android/FragProxyTest.java

# SNI 解析 / 切点 / 分片 / 还原 / MTU / seq 回绕（86 项）
java -cp out com.fragdpi.android.FragCoreTest

# 分段代理端到端（loopback 真 socket，19 项）
java -cp out com.fragdpi.android.FragProxyTest
```

（`MainActivity` / `ProxyService` 能不能编过，由 `build_apk.sh` 用 android.jar 验证。）

`FragProxyTest` 是「分片到底有没有生效」的硬证据：它在**服务端侧**记录
第一次 `read()` 拿到多少字节 —— 若代理确实把首段和其余部分分两次 write，
服务端第一次 read 就应该只拿到切点长度，而不是整段 ClientHello。

CI 里也在跑（`.github/workflows/android.yml`），并且会产出 APK 制品。

---

## 目录

```
android/
├── build_apk.sh                     手工构建脚本（跨平台，不需要 Gradle）
├── app/
│   ├── AndroidManifest.xml
│   ├── res/values/strings.xml
│   └── src/com/fragdpi/android/
│       ├── FragCore.java            ★ 核心：SNI 解析 + 切点 + 分片（纯函数，可单测）
│       ├── FragCoreTest.java        ★ 86 项单测（纯 JVM）
│       ├── FragProxy.java           本地分段代理（SOCKS5 + HTTP CONNECT）
│       ├── FragProxyTest.java       ★ 19 项端到端验证（loopback 真 socket）
│       ├── ProxyService.java        前台服务（避免被系统回收）
│       └── MainActivity.java        极简界面（纯代码搭 UI，不依赖 layout XML）
```

---

## 与桌面版的关系

| 部分 | 桌面版 | Android 版 |
|---|---|---|
| 引擎核心 | `core/fragcore.py`（Python） | `FragCore.java` |
| 分段方式 | WinDivert 内核驱动改包 | 用户态代理分两次 write |
| 权限 | 需要管理员 | 不需要 root |
| 覆盖范围 | 全系统所有程序 | 仅走系统代理的应用 |

两份实现用**同一批测试向量**对拍。这个做法已经赚回成本了：移植时发现了一个
**两边共有的潜在 bug** —— 切点下限校验原本写的是 `min(min_cut, 设备阈值)`，
导致 `min_cut` 一旦被调到阈值以下（比如 60），就会放行低于阈值 114 的切点
（分片照样被设备拦，等于白切）。已同时改成 `max(...)`，两侧单测都补了用例。

---

## 路线图

- [x] **v0.1** 核心逻辑移植 + 本地分段代理 + 可安装 APK
- [ ] **v0.2** VpnService + 用户态 TCP 栈（tun2socks）→ 覆盖不走系统代理的应用
- [ ] **v0.3** 规则系统（按域名后缀/关键词决定是否分片，同桌面版）
- [ ] **v0.4** 快速设置磁贴（一拉即开）、开机自启
- [ ] 加密 DNS（DoH）—— 对应桌面版的 `tools/doh_stub.py`
- [ ] 应用图标（当前没有，桌面显示默认图标）
