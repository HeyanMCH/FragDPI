# research/ — 实测研究脚本与原始数据

这个目录是整个项目的**依据**。README 里所有关于「设备怎么查、阈值多少、开销多大」的
结论都来自这里的脚本，脚本与它的原始输出都在仓库里，可以逐条复核。

## 测量环境（很重要）

| 项目 | 值 |
|---|---|
| 时间 | 2026-10-12 |
| 链路 | 某校园网 **WiFi**，出口走运营商线路（华东地区），中间有「上网行为管理」设备 |
| 客户端 | Windows x64 单机，Python 3.13 |
| 目标 | 米哈游系 / Steam / 暴雪战备 / PUBG 等游戏相关域名 |

**换一个网络，这些数字大概率不成立。** 不同厂商设备的阈值、是否做流重组、要不要查 UDP
都可能不同。所以本目录的价值不在「结论」，而在「方法」—— 拿这套脚本去测你自己的网络。

### ⚠️ 先跑对照组，再相信任何一个「通过 / 被拦」

这是本项目踩过最深的坑，写在最前面：

> **方法不对时，超时不是封锁的证据；设备不在了，同样可以把结论带偏。**

两个真实例子：

1. 最初拿 STUN 包去打 UDP 443，全部超时，差点写成「UDP 443 被封」。
   实际上 QUIC 服务器**会直接忽略非 QUIC 报文**。换成 QUIC 版本协商探针，结论立刻反转。
2. 2026-10-12 当天稍晚换到另一条链路（同城、另一个出口）再测时，
   `frag_bypass_test.py` 的 **0 号对照组（整包一次发）也通过了** —— 说明那台设备根本不在
   这条链路上，于是 8 个实验全部"成功"，而此时任何"分片有效"的结论都是假的。
   同一次 `sweep_cut.py` 也从 cut=1 起全部通过，一个 RST 都没有。

所以正确顺序永远是：

```bat
python frag_bypass_test.py     :: ① 先看 0 号对照组有没有被 RST
                               ::    没被 RST → 这台设备不在，后面所有结论都不成立，收工
python gamelist_probe.py       :: ② 有 RST 才有必要往下做，先摸清封锁面
python ..\tools\sweep_cut.py   :: ③ 再扫阈值
```

`gamelist_probe.py` 里的 `verdict` 字段也是为这个目的设计的 ——
`RST` 才是封锁证据，`DNS_FAIL` / `TCP_FAIL` 都不是。

## 脚本

| 脚本 | 做什么 | 产出 |
|---|---|---|
| `_common.py` | 公共工具：自动探测默认网关、DNS 列表、统一输出路径。**没有任何硬编码的内网地址** | — |
| `frag_bypass_test.py` | ★ **决定性实验**：同一个 ClientHello 用 8 种方式发送，判定设备只看首包、不做流重组 | 终端输出 |
| `gamelist_probe.py` | 57 个游戏域名逐一做真实 SNI 的 TLS 握手，分类 通 / RST / DNS失败 | `gamelist_result.json` |
| `gamelist2_probe.py` | 第二批 55 个域名 | `gamelist2_result.json` |
| `sweep_cut.py`（在 `../tools/`） | 扫首段切点，找到设备真正放行的长度区间 | 终端输出 |
| `quic_probe.py` | UDP 443 可达性：发保留版本号的 QUIC Initial，等 Version Negotiation 回复。**不需要任何加密** | 终端输出 |
| `udp_probe.py` | UDP 出网：DNS(53) / STUN(3478) / QUIC(443) | 终端输出 |
| `probe_fast.py` | 把延迟拆成 DNS / TCP / TLS / 代理四段，定位瓶颈 | `probe_fast_result.json` |
| `ping_battery.py` | 同一主机 A/B 对比（分片 vs 不分片）的延迟分布 | 终端输出 |
| `zzz_web_probe.py` | 多维度取证：DNS 答案对比、TLS 矩阵、HTTP 80、UDP 出网、网关 ping | `zzz_probe_result.json` |

## 原始数据

| 文件 | 内容 |
|---|---|
| `gamelist_result.json` / `gamelist2_result.json` | 112 条探测记录（去重 103 个域名），每条含 `host` / `dns` / `ms` / `verdict` / `detail` |
| `rules_verify_result.txt` | 规则模式下的绕过验证：**36 / 36 通过**，附引擎统计与规则命中数 |
| `ab_fragment.txt` | 分片 vs 不分片的 A/B 延迟原始值 |
| `latency_diag.txt` | 延迟诊断分组（被分片的海外 / 未被分片的海外对照 / 国内） |
| `zzz_probe_result.json` | DNS、TLS 矩阵、UDP 出网、网关质量 |
| `live_test_result.txt` | 端到端直连测试结论（http_code / TLS 耗时） |

### 判决字段的含义

| `verdict` | 含义 |
|---|---|
| `OK` | TLS 握手成功 |
| `RST` | 收到注入的 TCP RST —— 判定为**被封锁** |
| `DNS_FAIL` | 域名解析不到（已下线 / 仅内网解析），与封锁无关 |
| `TCP_FAIL` | TCP 建连超时，属我方网络问题，与封锁无关 |

## 数据脱敏说明

整理仓库时已做过一轮扫描，确认：

* **没有**任何本机用户名、绝对路径、MAC 地址、Wi-Fi SSID、内网 IP；
* 网关地址与 DNS 服务器列表由 `_common.py` **运行时自动探测**，不落盘、不入库；
* `.json` 里的 IP 都是**公网 DNS 应答**（CDN 边缘节点），不含私有地址；
* 原来的 `live_test_result.txt` 里附带了一整份目标站点首页的 HTML 抓取（含该站自己前端
  的 APM token 与编码乱码），与测量结论无关，已删除、只保留结论行。

## 复现

```bat
:: 0) 无依赖，直接用系统 Python 跑
python frag_bypass_test.py         :: ① 先看 0 号对照组：有没有 RST？没有就说明设备不在，收工
python gamelist_probe.py           :: ② 有 RST 才继续，先摸清封锁面
python ..\tools\sweep_cut.py       :: ③ 扫出你这台设备的放行区间（它自己会打印分界点）
python quic_probe.py               :: ④ 顺带确认 UDP 有没有被单独限制
python probe_fast.py               :: ⑤ 定位延迟瓶颈（DNS / TCP / TLS / 代理 分段）
python ping_battery.py             :: ⑥ A/B 对比分片开销
```

> 这些脚本都**不做任何注入或篡改**，只是主动发起连接、观察对端/中间设备的反应。
> 请仅在你拥有或已获授权的网络上运行。
>
> `frag_bypass_test.py` 与 `sweep_cut.py` 里都留了一个 `FALLBACK_IP`（2026-10-12 当天的
> DNS 解析结果），只在域名解析失败时兜底 —— 正常情况下每次都会重新解析。
