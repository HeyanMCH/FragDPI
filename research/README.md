# research/ — 实测研究脚本与原始数据

这个目录是整个项目的**依据**。README 里所有关于「设备怎么查、阈值多少、开销多大」的
结论都来自这里的脚本，脚本与它的原始输出都在仓库里，可以逐条复核。

## 测量环境（很重要）

| 项目 | 值 |
|---|---|
| 时间 | 2026-10-12 |
| 链路 | 某校园网 **WiFi**，出口为运营商家庭宽带（浙江），中间有「上网行为管理」设备 |
| 客户端 | Windows x64 单机，Python 3.13 |
| 目标 | 米哈游系 / Steam / 暴雪战备 / PUBG 等游戏相关域名 |

**换一个网络，这些数字大概率不成立。** 不同厂商设备的阈值、是否做流重组、要不要查 UDP
都可能不同。所以本目录的价值不在「结论」，而在「方法」—— 拿这套脚本去测你自己的网络。

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
python frag_bypass_test.py         :: 先确认这台设备"只看首包"
python gamelist_probe.py           :: 再测封锁面
python ..\tools\sweep_cut.py       :: 扫出你这台设备的放行区间
python quic_probe.py               :: 顺带确认 UDP 有没有被单独限制
python probe_fast.py               :: 定位延迟瓶颈
python ping_battery.py             :: A/B 对比分片开销
```

> 这些脚本都**不做任何注入或篡改**，只是主动发起连接、观察对端/中间设备的反应。
> 请仅在你拥有或已获授权的网络上运行。
