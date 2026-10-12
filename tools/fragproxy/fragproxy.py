#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fragproxy.py — 首包分片代理

用途：绕过"只检查连接首个 TCP 报文里的关键词、且不做 TCP 流重组"的中间设备
      （本机实测：某教室网络对 *.mihoyo.com 注入 RST）。

原理：把客户端发给服务器的第一段数据（TLS ClientHello / HTTP 请求头）拆成两个
      TCP 段先后发送，使关键词落在第二段里，从而躲过首包检测。
      全程不解密、不签发证书、不做中间人；TLS 仍然是客户端与真实服务器端到端加密。

用法：
    python fragproxy.py                      # 监听 127.0.0.1:8888（默认 guard=6）
    python fragproxy.py --guard 9            # 切割点微调（建议 3~12）
    python fragproxy.py --port 8889 --verbose

重要：切割点不能随便放。实测本网络设备会解析 TLS 记录与扩展结构，
      切割点必须落在 SNI 扩展内部（关键词前约 6 字节）才会让它"看到但拿不全"；
      切太早（如前 64 字节）或只发 1 字节，设备会攒包复检，反而被拦。

客户端设置二选一：
    1) 把 HTTP/HTTPS 代理设为 127.0.0.1:8888
    2) 把"自动代理配置(PAC)"设为 http://127.0.0.1:8888/proxy.pac（只让目标域名走本代理）

无第三方依赖，Python 3.8+ 即可。
"""
import argparse
import socket
import sys
import threading
import time

BUFSIZE = 65536
_print_lock = threading.Lock()


def log(msg, verbose_only=False, args=None):
    if verbose_only and args is not None and not args.verbose:
        return
    with _print_lock:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


PAC_TEMPLATE = """function FindProxyForURL(url, host) {
  if (shExpMatch(host, "*.mihoyo.com") || shExpMatch(host, "*.hoyoverse.com")
      || host == "mihoyo.com" || host == "hoyoverse.com") {
    return "PROXY 127.0.0.1:%(port)d; DIRECT";
  }
  return "DIRECT";
}
"""


def make_frag(args):
    """返回 (data) -> (cut, note)。cut 为 0 表示不分片。

    实测约束（本网络设备，2026-10-12）：
      - 切割点必须落在 SNI 扩展结构内部（关键词前约 6 字节处最稳）；
      - 切得太早（如前 64 字节处）设备会攒包复检，反而被拦；
      - 首段只发 1 字节同样会被拦。
      所以默认 guard=6；若失效可在 3~12 之间试。
    """
    kw = args.keyword.encode("ascii")

    def frag(data):
        pos = data.find(kw)
        if pos < 0:
            return (0, "未见关键词，原样转发")
        cut = pos - args.guard
        if cut <= 0 or cut >= len(data):
            return (0, "关键词位置异常，原样转发")
        return (cut, f"关键词@{pos}B，在 {cut}B 处切")

    return frag


def pipe(src, dst, fragfn=None, delay=0.0, label="", logit=True, args=None, initial=b""):
    """单向转发；fragfn 只作用于第一段。"""
    first = True
    pending = initial
    total = 0
    try:
        while True:
            if pending:
                data, pending = pending, b""
            else:
                data = src.recv(BUFSIZE)
                if not data:
                    break
            total += len(data)
            if first and fragfn:
                first = False
                cut, note = fragfn(data)
                if cut and 0 < cut < len(data):
                    dst.sendall(data[:cut])
                    if delay:
                        time.sleep(delay)
                    dst.sendall(data[cut:])
                    log(f"{label} 首段 {len(data)}B → {cut}B + {len(data) - cut}B（{note}）", args=args)
                else:
                    dst.sendall(data)
                    log(f"{label} 首段 {len(data)}B 原样转发（{note}）", verbose_only=True, args=args)
            else:
                first = False
                dst.sendall(data)
    except (ConnectionResetError, ConnectionAbortedError, OSError):
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        log(f"{label} 结束，共转发 {total}B", verbose_only=True, args=args)


def close_quietly(sock):
    try:
        sock.close()
    except OSError:
        pass


def serve_pac(conn, args):
    body = PAC_TEMPLATE % {"port": args.port}
    head = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/x-ns-proxy-autoconfig\r\n"
        f"Content-Length: {len(body.encode())}\r\n"
        "Connection: close\r\n\r\n"
    )
    conn.sendall(head.encode() + body.encode())


def handle(conn, addr, args):
    conn.settimeout(20)
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                close_quietly(conn)
                return
            buf += chunk
            if len(buf) > 65536:
                close_quietly(conn)
                return
    except OSError:
        close_quietly(conn)
        return

    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    try:
        method, target, _ = lines[0].decode("latin1").split(" ", 2)
    except ValueError:
        close_quietly(conn)
        return
    method = method.upper()

    if method == "GET" and target.rstrip("/").endswith("proxy.pac"):
        serve_pac(conn, args)
        close_quietly(conn)
        log("已下发 PAC")
        return

    if method == "CONNECT":
        host, _, port_s = target.rpartition(":")
        port = int(port_s or 443)
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError as e:
            try:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except OSError:
                pass
            close_quietly(conn)
            log(f"CONNECT {host}:{port} 失败：{type(e).__name__}")
            return
        upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        conn.settimeout(None)
        log(f"CONNECT {host}:{port} 隧道已建立")
        frag = make_frag(args)
        up_thread = threading.Thread(
            target=pipe,
            args=(conn, upstream, frag, args.delay, f"C→S {host}", True, args, rest),
            daemon=True,
        )
        up_thread.start()
        pipe(upstream, conn, None, 0.0, f"S→C {host}", False, args)
        up_thread.join(timeout=5)
        close_quietly(upstream)
        close_quietly(conn)
        return

    # 普通 HTTP 转发
    host_hdr, port = None, 80
    for line in lines[1:]:
        k, _, v = line.decode("latin1").partition(":")
        if k.lower() == "host":
            host_hdr = v.strip()
    if not host_hdr:
        try:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        except OSError:
            pass
        close_quietly(conn)
        return
    host, _, port_s = host_hdr.rpartition(":")
    port = int(port_s) if port_s.isdigit() else 80
    try:
        upstream = socket.create_connection((host, port), timeout=10)
    except OSError as e:
        try:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except OSError:
            pass
        close_quietly(conn)
        log(f"HTTP {host}:{port} 失败：{type(e).__name__}")
        return
    upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    conn.settimeout(None)
    frag = make_frag(args)
    # 首段已经是完整请求头，直接按策略分片转发
    cut, note = frag(buf)
    if cut and 0 < cut < len(buf):
        upstream.sendall(buf[:cut])
        if args.delay:
            time.sleep(args.delay)
        upstream.sendall(buf[cut:])
        log(f"HTTP {host}:{port} 首段 {len(buf)}B → {cut}B + {len(buf) - cut}B（{note}）", args=args)
    else:
        upstream.sendall(buf)
    up_thread = threading.Thread(
        target=pipe,
        args=(conn, upstream, None, 0.0, f"C→S {host}", False, args),
        daemon=True,
    )
    up_thread.start()
    pipe(upstream, conn, None, 0.0, f"S→C {host}", False, args)
    up_thread.join(timeout=5)
    close_quietly(upstream)
    close_quietly(conn)


def main():
    ap = argparse.ArgumentParser(description="首包分片代理（绕过仅查首包的 SNI 关键词检测）")
    ap.add_argument("--port", type=int, default=8888, help="监听端口，默认 8888")
    ap.add_argument("--bind", default="127.0.0.1", help="监听地址，默认 127.0.0.1")
    ap.add_argument("--keyword", default="mihoyo", help="要藏到第二段的关键词，默认 mihoyo")
    ap.add_argument("--guard", type=int, default=6,
                    help="在关键词前几个字节处切开（建议 3~12，默认 6，实测最稳）")
    ap.add_argument("--delay", type=float, default=0.02, help="两段之间的间隔秒数，默认 0.02")
    ap.add_argument("--no-fallback", action="store_true", help="首段找不到关键词时不分片")
    ap.add_argument("--verbose", action="store_true", help="输出更多日志")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(128)

    print("=" * 62)
    print(" fragproxy 首包分片代理已启动")
    print(f" 代理地址 : http://{args.bind}:{args.port}")
    print(f" PAC 地址 : http://{args.bind}:{args.port}/proxy.pac")
    print(f" 策略     : keyword={args.keyword!r}, guard={args.guard}B, delay={args.delay}s")
    print(" 停止     : 按 Ctrl+C")
    print("=" * 62)

    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr, args), daemon=True).start()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        srv.close()


if __name__ == "__main__":
    sys.exit(main())
