# -*- coding: utf-8 -*-
"""UDP 443 QUIC 可达性：发「不支持版本」的 Initial，服务器应回 Version Negotiation（version=0）。
   此方法不需要加密，能干净地区分「UDP443 被封」和「服务器不理非法报文」。"""
import sys, io, socket, struct, os, time
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

def quic_probe(host, port=443, timeout=6):
    dcid, scid = os.urandom(8), os.urandom(8)
    pkt  = b"\xc0"                       # long header + fixed bit
    pkt += bytes.fromhex("1a2a3a4a")     # 保留版本 → 触发 Version Negotiation
    pkt += bytes([len(dcid)]) + dcid
    pkt += bytes([len(scid)]) + scid
    pkt += b"\x00\x40\x40" + os.urandom(16)
    pkt += os.urandom(1200)              # 客户端 Initial 需 ≥1200B 才不被丢弃
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return f"DNS_FAIL {type(e).__name__}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
        t0 = time.perf_counter(); s.sendto(pkt, (ip, port))
        d, _ = s.recvfrom(4096); s.close()
        ver = d[1:5] if len(d) >= 5 else b""
        tag = "Version Negotiation ✅" if ver == b"\x00\x00\x00\x00" else f"其他响应 ver={ver.hex()}"
        return f"OK   {len(d)}B {round((time.perf_counter()-t0)*1000)}ms  {tag}  ip={ip}"
    except Exception as e:
        return f"FAIL {type(e).__name__}  ip={ip}（UDP443 无任何回包）"

print("== UDP 443 QUIC 可达性 ==")
for h in ["cloudflare.com","www.taobao.com","dns.google","www.bilibili.com","github.com","www.mihoyo.com"]:
    print(f"  {h:22s} {quic_probe(h)}")
