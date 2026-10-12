import socket, ssl, time, json, struct, random, subprocess, re, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import default_gateway, out_path

R = {"ts": time.strftime("%F %T")}

def log(label, val):
    print(f"[{label}] {json.dumps(val, ensure_ascii=False)}")
    R[label] = val

# ============ 1. DNS 对比（不同解析器答案是否一致） ============
def dns_query(server, name, timeout=2.5):
    tid = random.randint(0, 65535)
    pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + \
          b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00" + \
          struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(2048)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        ips, idx, n = [], 12, struct.unpack(">H", data[6:8])[0]
        while data[idx] != 0: idx += data[idx] + 1
        idx += 5
        for _ in range(n):
            if data[idx] & 0xC0 == 0xC0: idx += 2
            else:
                while data[idx] != 0: idx += data[idx] + 1
                idx += 1
            t, c, ttl, dl = struct.unpack(">HHIH", data[idx:idx + 10]); idx += 10
            if t == 1 and dl == 4: ips.append(socket.inet_ntoa(data[idx:idx + 4]))
            idx += dl
        return {"ms": ms, "ips": ips}
    except Exception as e:
        return {"error": type(e).__name__ + ": " + str(e)}
    finally:
        s.close()

dns_res = {}
_servers = [("ali_223", "223.5.5.5"),
            ("dnspod_119", "119.29.29.29"), ("dns_114", "114.114.114.114")]
_gw = default_gateway()
if _gw:
    _servers.insert(0, ("router", _gw))       # 本机网关自动探测
for name, srv in _servers:
    dns_res[name] = dns_query(srv, "zzz.mihoyo.com")
log("dns_compare", dns_res)

zzz_ips = []
for r in dns_res.values():
    for ip in r.get("ips", []):
        if ip not in zzz_ips: zzz_ips.append(ip)
zzz_ips = zzz_ips[:3]

# ============ 2. TCP/TLS 交叉矩阵 ============
def tls_test(ip, sni, verify, timeout=6):
    out = {"ip": ip, "sni": sni}
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((ip, 443), timeout=timeout)
        out["tcp_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    except Exception as e:
        out["tcp_fail"] = type(e).__name__
        return out
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = verify
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    t1 = time.perf_counter()
    try:
        with ctx.wrap_socket(s, server_hostname=sni) as ss:
            out["tls_ms"] = round((time.perf_counter() - t1) * 1000, 1)
            cert = ss.getpeercert()
            if cert:
                out["cert_subject"] = dict(x[0] for x in cert.get("subject", []))
                out["cert_issuer"] = dict(x[0] for x in cert.get("issuer", []))
            out["alpn"] = ss.selected_alpn_protocol()
    except Exception as e:
        out["tls_fail"] = type(e).__name__ + (": " + str(e)[:120] if "RESET" in str(e).upper() or "reset" in str(e) else "")
        out["tls_ms"] = round((time.perf_counter() - t1) * 1000, 1)
    return out

baidu_ip = None
try:
    baidu_ip = socket.gethostbyname("www.baidu.com")
except Exception:
    pass

matrix = []
for ip in zzz_ips:
    matrix.append(tls_test(ip, "zzz.mihoyo.com", True))          # 正路：真SNI+验证证书
if zzz_ips:
    matrix.append(tls_test(zzz_ips[0], "www.baidu.com", False))  # 同IP换SNI
if baidu_ip:
    matrix.append(tls_test(baidu_ip, "zzz.mihoyo.com", False))   # 同SNI换IP（百度的IP）
    matrix.append(tls_test(baidu_ip, "www.baidu.com", True))     # 对照组
log("tls_matrix", matrix)

# 其他 mihoyo 域名 SNI 是否也被断
other = []
for d in ["www.mihoyo.com", "bbs.mihoyo.com", "webstatic.mihoyo.com"]:
    try:
        ip = socket.gethostbyname(d)
    except Exception:
        other.append({"domain": d, "resolve_fail": True}); continue
    r = tls_test(ip, d, False)
    r["domain"] = d
    other.append(r)
log("other_mihoyo_sni", other)

# ============ 3. HTTP :80 测试 ============
http_res = []
for ip in zzz_ips[:2]:
    try:
        s = socket.create_connection((ip, 80), timeout=4)
        s.sendall(b"GET / HTTP/1.1\r\nHost: zzz.mihoyo.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
        s.settimeout(4)
        data = s.recv(512)
        http_res.append({"ip": ip, "reply": data[:120].decode("latin1").replace("\r\n", " | ")})
        s.close()
    except Exception as e:
        http_res.append({"ip": ip, "fail": type(e).__name__})
log("http80", http_res)

# ============ 4. UDP 出网测试（游戏关键） ============
def ntp_test(ip, timeout=3):
    pkt = b"\x1b" + b"\x00" * 47
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.sendto(pkt, (ip, 123))
        data, _ = s.recvfrom(1024)
        return {"ok": True, "reply_bytes": len(data), "ms": round((time.perf_counter() - t0) * 1000, 1)}
    except Exception as e:
        return {"ok": False, "fail": type(e).__name__}
    finally:
        s.close()

udp_res = {"ntp_aliyun_203.107.6.88": ntp_test("203.107.6.88"),
           "ntp_tencent_119.28.183.184": ntp_test("119.28.183.184"),
           "ext_dns_udp53": {"ali": dns_res["ali_223"], "dnspod": dns_res["dnspod_119"]}}
log("udp_egress", udp_res)

# ============ 5. 网关 WiFi 链路质量（20 包快测，网关自动探测） ============
_gw = default_gateway()
if _gw:
    r = subprocess.run(["ping", "-n", "20", "-w", "1200", _gw], capture_output=True)
    txt = r.stdout.decode("utf-8", errors="replace")
    times = [int(m.group(1)) for m in re.finditer(r"time[=<](\d+)\s*ms", txt)]
    if times:
        import statistics as st
        log("wifi_gateway_ping", {"target": _gw, "sent": 20, "recv": len(times),
                                  "loss_pct": round((20 - len(times)) / 20 * 100, 1),
                                  "min": min(times), "avg": round(st.mean(times), 1),
                                  "max": max(times), "jitter": round(st.pstdev(times), 1)})
    else:
        log("wifi_gateway_ping", {"target": _gw, "sent": 20, "recv": 0, "loss_pct": 100})
else:
    log("wifi_gateway_ping", {"error": "未探测到默认网关"})

with open(out_path("zzz_probe_result.json"), "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print("DONE")
