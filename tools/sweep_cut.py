import socket, ssl, time, sys

HOST = "zzz.mihoyo.com"
IP = "60.163.131.14"
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
obj = ctx.wrap_bio(incoming, outgoing, server_hostname=HOST)
try:
    obj.do_handshake()
except ssl.SSLWantReadError:
    pass
hello = outgoing.read()
kw = hello.find(b"mihoyo")
print(f"ClientHello {len(hello)}B, 关键词 @ {kw}B")
print(f"{'cut':>5} | 结果")
print("-" * 46)

def try_cut(cut, delay=0.01):
    s = socket.socket(); s.settimeout(4)
    try:
        s.connect((IP, 443))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(hello[:cut])
        time.sleep(delay)
        s.sendall(hello[cut:])
        try:
            data = s.recv(2048)
        except socket.timeout:
            return "无响应"
        if not data:
            return "空包/被关闭"
        return "✅ 通过（收到服务端响应）" if data[0:1] == b"\x16" else f"其他 {data[:2].hex()}"
    except ConnectionResetError:
        return "❌ RST（被拦截）"
    except Exception as e:
        return f"❌ {type(e).__name__}"
    finally:
        s.close()

for cut in [1, 16, 32, 48, 64, 80, 96, 100, 104, 108, 112, 116, 120, 124, 128, 129, 130, 132, 134]:
    if cut >= len(hello):
        continue
    print(f"{cut:>5} | {try_cut(cut)}")
    sys.stdout.flush()
