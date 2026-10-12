#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""frag_bypass_test — 判定「中间设备到底怎么查」的决定性对照实验。

这是整个项目里最重要的一次测量：同一个 ClientHello，用 8 种不同的发送方式发出去，
看哪一种能过、哪一种被 RST。结论直接决定了引擎的实现方向。

判读方式（对应下面 0~7 号实验）：
  0  整包一次发                  → 被 RST（对照组：说明域名确实在名单里）
  1  TCP 切两段、SNI 之前断开    → 若通过，说明设备**不做流重组**，只看首包
  2  TCP 切三段、关键词中间切开  → 看是否只查首段
  3  从 SNI 处逐字节发           → 看设备对碎小段的容忍度
  4  TLS 记录层拆成两条 record   → 验证「必须是 TCP 层分片」还是「TLS 层拆开也行」
  5  record 拆 + 间隔 50ms       → 时间维度是否参与判定
  6  TCP 切两段 + 间隔 300ms
  7  TCP 切两段 + 间隔 1500ms

本机实测结论（2026-10-12）：设备只看**第一个 TCP 报文**，且有个「攒够字节数才查」的
水位线；**不做流重组**，因此 TCP 层分片有效，TLS 记录层拆开无效。
详见 README 的「它是怎么做到的」一节。

用法：
    python frag_bypass_test.py
"""
import socket
import ssl
import struct
import sys
import time

HOST = "zzz.mihoyo.com"

# 2026-10-12 当天该域名的 DNS 解析结果。正常情况下会重新解析；解析失败时用它兜底，
# 这样即便域名早已下线，这份实验脚本仍然能被复现。
FALLBACK_IP = "60.163.131.14"


def resolve(host):
    try:
        ip = socket.gethostbyname(host)
        print(f"DNS  {host} -> {ip}（本次解析）")
        return ip
    except Exception as e:
        print(f"DNS  {host} 解析失败（{type(e).__name__}），回退到记录值 {FALLBACK_IP}")
        return FALLBACK_IP


def build_client_hello(host):
    """用 MemoryBIO 让标准库真的生成一个 ClientHello，而不是手搓。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=host)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def main():
    ip = resolve(HOST)
    hello = build_client_hello(HOST)
    idx = hello.find(b"mihoyo")
    print(f"ClientHello {len(hello)} bytes，关键词 'mihoyo' 在偏移 {idx}"
          f"（TLS record 头 5B + 握手头 4B 之后是 body）")
    if idx < 0:
        print("注意：本机 OpenSSL 生成的 ClientHello 里没找到 'mihoyo'，"
              "下面的实验仍然有效，但偏移量需要重新解读。")
        idx = hello.find(b"zzz")
        if idx < 0:
            print("连域名都没找到 —— 可能被 ECH/加密 SNI 了，本次实验结论不可用。")
            return 1
    print()

    def run(label, sends, delay=0.0):
        s = socket.socket()
        s.settimeout(5)
        try:
            s.connect((ip, 443))
        except Exception as e:
            return f"{label:34s} TCP-FAIL {type(e).__name__}"
        try:
            for chunk in sends:
                s.sendall(chunk)
                if delay:
                    time.sleep(delay)
            s.settimeout(5)
            try:
                data = s.recv(4096)
            except socket.timeout:
                return f"{label:34s} 无响应（也没 RST，可能只是慢）"
            if not data:
                return f"{label:34s} 连接被关闭(空包)"
            if data[0:1] == b"\x16":
                kind = "ServerHello/TLS 记录"
            elif data[0:1] == b"\x15":
                kind = "Alert"
            else:
                kind = "unknown"
            return f"{label:34s} 收到 {len(data)}B  {data[:5].hex()}  <- {kind}"
        except ConnectionResetError:
            return f"{label:34s} RST（被封）"
        except Exception as e:
            return f"{label:34s} {type(e).__name__}: {str(e)[:50]}"
        finally:
            s.close()

    print(run("0  对照：整包一次发", [hello]))
    print()
    print(run("1  TCP 切两段：SNI 前断开", [hello[:idx], hello[idx:]]))
    print(run("2  TCP 切三段：关键词中间切开",
              [hello[:idx + 3], hello[idx + 3:idx + 6], hello[idx + 6:]]))
    print(run("3  从 SNI 开始逐字节发",
              [hello[:idx]] + [hello[idx + i:idx + i + 1] for i in range(14)]
              + [hello[idx + 14:]]))
    print()

    def reframe(h, cut):
        """TLS 记录层拆分：保持 TCP 段不变，把载荷拆成两条 TLS record。"""
        hdr, payload = h[:5], h[5:]
        r1 = hdr[:3] + struct.pack(">H", cut) + payload[:cut]
        r2 = b"\x16" + hdr[1:3] + struct.pack(">H", len(payload) - cut) + payload[cut:]
        return r1, r2

    r1, r2 = reframe(hello, idx)
    print(run("4  TLS 记录层拆成两条 record", [r1 + r2]))
    print(run("5  record 拆 + 两段间隔 50ms", [r1, r2], delay=0.05))
    print()
    print(run("6  TCP 切两段 + 间隔 300ms", [hello[:idx], hello[idx:]], delay=0.3))
    print(run("7  TCP 切两段 + 间隔 1500ms", [hello[:idx], hello[idx:]], delay=1.5))
    return 0


if __name__ == "__main__":
    sys.exit(main())
