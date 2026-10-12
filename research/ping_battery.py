import subprocess, re, json, socket, time, statistics, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import default_gateway, out_path, init_console
init_console()

def ping_series(host, count, timeout_ms=1500):
    r = subprocess.run(["ping", "-n", str(count), "-w", str(timeout_ms), host],
                       capture_output=True)
    txt = r.stdout.decode("utf-8", errors="replace")
    # English Windows: "Reply from 1.2.3.4: bytes=32 time=2ms TTL=64", "Request timed out."
    times = [int(m.group(1)) for m in re.finditer(r"time[=<](\d+)\s*ms", txt)]
    timeouts = len(re.findall(r"Request timed out|General failure", txt))
    if not times and timeouts == 0:
        # maybe Chinese output, retry gbk decode
        txt2 = r.stdout.decode("gbk", errors="replace")
        times = [int(m.group(1)) for m in re.finditer(r"时间[=<](\d+)\s*ms", txt2)]
        timeouts = len(re.findall(r"请求超时|无法访问", txt2))
    sent = count
    recv = len(times)
    loss_pct = round((sent - recv) / sent * 100, 1)
    if times:
        ts = sorted(times)
        st = {
            "host": host, "sent": sent, "recv": recv, "loss_pct": loss_pct,
            "min": min(times), "avg": round(statistics.mean(times), 1),
            "max": max(times), "jitter": round(statistics.pstdev(times), 1),
            "p95": ts[int(len(ts) * 0.95) - 1] if len(ts) >= 20 else ts[-1],
        }
    else:
        st = {"host": host, "sent": sent, "recv": 0, "loss_pct": 100.0}
    return st, times

def main():
    out = {"started": time.strftime("%H:%M:%S")}
    # resolve zzz cdn ip first
    ip = None
    try:
        ip = socket.gethostbyname("zzz.mihoyo.com")
    except Exception:
        pass
    out["zzz_ip"] = ip

    series = []
    timelines = {}
    # 1) gateway = pure wifi link quality（网关自动探测，不写死）
    gw = default_gateway()
    if gw:
        st, tl = ping_series(gw, 50)
        series.append(("wifi_link_gateway", st)); timelines["wifi_link_gateway"] = tl
    else:
        print("[!] 未探测到默认网关，跳过链路质量测试")
    # 2) zzz cdn end-to-end
    if ip:
        st, tl = ping_series(ip, 40)
        series.append(("zzz_cdn_e2e", st)); timelines["zzz_cdn_e2e"] = tl
    # 3) aliyun dns (public internet baseline)
    st, tl = ping_series("223.5.5.5", 15)
    series.append(("ali_dns_223", st)); timelines["ali_dns_223"] = tl
    # 4) 114 dns
    st, tl = ping_series("114.114.114.114", 15)
    series.append(("dns_114", st)); timelines["dns_114"] = tl

    out["series"] = {name: s for name, s in series}
    out["timelines"] = timelines
    out["ended"] = time.strftime("%H:%M:%S")
    with open(out_path("ping_results.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps(out["series"], indent=1, ensure_ascii=False))

if __name__ == "__main__":
    main()
