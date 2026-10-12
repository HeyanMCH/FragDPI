# -*- coding: utf-8 -*-
"""对游戏相关域名做真实 SNI 的 TLS 握手，分类「通 / 被RST / DNS失败」"""
import sys, socket, ssl, time, json, os
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import init_console
init_console()

DOMAINS = [
 # ---- 米哈游 国服 ----
 "www.mihoyo.com","zzz.mihoyo.com","act.mihoyo.com","user.mihoyo.com","cloud.mihoyo.com",
 "api-takumi.mihoyo.com","api-takumi-record.mihoyo.com","hk4e-api.mihoyo.com","hk4e-sdk.mihoyo.com",
 "hk4e-sdk-os.mihoyo.com","hyp-api.mihoyo.com","passport-api.mihoyo.com",
 "sdk-static.mihoyo.com","pc-static.mihoyo.com","fastcdn.mihoyo.com","webstatic.mihoyo.com",
 "uploadstatic.mihoyo.com","bbs-api.mihoyo.com","bbs.mihoyo.com","mi18n.mihoyo.com",
 "ys.mihoyo.com","sr.mihoyo.com","bh3.mihoyo.com","wd.mihoyo.com","miyoushe.com",
 # ---- 米哈游 国际服 ----
 "www.hoyoverse.com","hoyolab.com","act.hoyoverse.com","sg-hoyolab.com","sdk.hoyoverse.com",
 "api-takumi.hoyoverse.com","hk4e-api-os.hoyoverse.com","api-os-takumi.hoyoverse.com",
 "fastcdn.hoyoverse.com","sg-public-api-static.hoyoverse.com",
 # ---- 其他游戏平台 ----
 "steamcommunity.com","store.steampowered.com","api.steampowered.com","cdn.steamstatic.com",
 "epicgames.com","store.epicgames.com","riotgames.com","leagueoflegends.com",
 "battle.net","blizzard.com","ea.com","ubisoft.com","playstation.com","xboxlive.com",
 "nintendo.net","pubg.com","minecraft.net","mojang.com","roblox.com","uu.163.com",
 # ---- 对照 ----
 "www.baidu.com","github.com",
]

def probe(host, timeout=7):
    r = {"host": host, "dns": None, "ms": None, "verdict": None, "detail": ""}
    t0 = time.perf_counter()
    try:
        r["dns"] = socket.gethostbyname(host)
    except Exception as e:
        r["verdict"] = "DNS_FAIL"; r["detail"] = type(e).__name__
        r["ms"] = round((time.perf_counter()-t0)*1000); return r
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((r["dns"], 443), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                r["verdict"] = "OK"
    except ConnectionResetError:
        r["verdict"] = "RST"; r["detail"] = "ConnectionResetError(注入RST)"
    except ssl.SSLError as e:
        r["verdict"] = "SSL_ERR"; r["detail"] = str(e)[:60]
    except Exception as e:
        r["verdict"] = "TCP_FAIL"; r["detail"] = f"{type(e).__name__}: {str(e)[:50]}"
    r["ms"] = round((time.perf_counter()-t0)*1000)
    return r

with ThreadPoolExecutor(max_workers=12) as ex:
    res = list(ex.map(probe, DOMAINS))

order = {"RST":0,"TCP_FAIL":1,"SSL_ERR":2,"DNS_FAIL":3,"OK":4}
res.sort(key=lambda x: (order.get(x["verdict"],9), x["host"]))
for x in res:
    print(f"{x['verdict']:9s} {x['host']:38s} {str(x['ms']):>5s}ms  {x['dns'] or '-':16s} {x['detail']}")

json.dump(res, open("gamelist_result.json","w",encoding="utf-8"), ensure_ascii=False, indent=1)
from collections import Counter
c = Counter(x["verdict"] for x in res)
print("\n统计:", dict(c))
print("被 RST 的域名:", [x["host"] for x in res if x["verdict"]=="RST"])
