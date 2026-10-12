# -*- coding: utf-8 -*-
"""验证 UDP 出网：DNS(53) / STUN(3478) / QUIC(443) —— 游戏本体走 UDP，需确认没被单独限制"""
import sys, socket, struct, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import dns_servers, init_console
init_console()

def dns_query(server, port=53, name="zzz.mihoyo.com", timeout=5):
    tid = os.urandom(2)
    q = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for lab in name.split("."):
        q += bytes([len(lab)]) + lab.encode()
    q += b"\x00\x00\x01\x00\x01"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
        t0=time.perf_counter(); s.sendto(q, (server, port))
        d,_ = s.recvfrom(2048); s.close()
        return f"OK  {len(d)}B  {round((time.perf_counter()-t0)*1000)}ms"
    except Exception as e:
        return f"FAIL {type(e).__name__}"

def stun_bind(host, port=3478, timeout=5):
    """标准 STUN Binding Request（0x0001），期待 0x0101 响应"""
    tid = os.urandom(12)
    req = struct.pack(">HHI", 0x0001, 0, 0x2112A442) + tid
    try:
        ip = socket.gethostbyname(host)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
        t0=time.perf_counter(); s.sendto(req, (ip, port))
        d,addr = s.recvfrom(2048); s.close()
        if len(d) >= 20:
            mtype = struct.unpack(">H", d[:2])[0]
            return f"OK  响应 type=0x{mtype:04x} {len(d)}B {round((time.perf_counter()-t0)*1000)}ms ip={ip}"
        return f"OK  {len(d)}B（短于 STUN 头）ip={ip}"
    except Exception as e:
        return f"FAIL {type(e).__name__}"

print("== UDP DNS 53 ==")
for srv in dns_servers():
    print(f"  {srv:16s} {dns_query(srv)}")
print("== STUN 3478（游戏 NAT 穿透常用，真实服务器往返）==")
for h in ["stun.miwifi.com","stun.qq.com","stun.chat.bilibili.com","stun.syncthing.net"]:
    print(f"  {h:24s} {stun_bind(h)}")
print("== UDP 443（QUIC/HTTP3 常用端口）==")
for h in ["www.taobao.com","cloudflare.com","dns.google"]:
    print(f"  {h:24s} {stun_bind(h, 443)}")
print("== UDP 高位端口（游戏自选端口常见范围）==")
for h,p in [("stun.miwifi.com",19302),("stun.qq.com",3479)]:
    print(f"  {h}:{p:<6d} {stun_bind(h,p)}")
