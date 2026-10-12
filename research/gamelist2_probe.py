# -*- coding: utf-8 -*-
import sys, socket, ssl, time, json, os
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import init_console
init_console()

DOMAINS = [
 # 腾讯游戏
 "game.qq.com","lol.qq.com","dnf.qq.com","cf.qq.com","pvp.qq.com","speed.qq.com","smoba.qq.com",
 "honorofkings.com","pubgmobile.com",
 # 网易
 "www.163.com","music.163.com","game.163.com","uu.163.com","netease.com","neteasegames.com",
 # 其他厂商
 "kurogame.com","kurobbs.com","hypergryph.com","papergames.cn","lilithgames.com",
 "xoyo.com","jx3.xoyo.com","wanmei.com","sdo.com","changyou.com","4399.com","ztgame.com",
 # 加速器
 "uu.163.com","xunyou.com","leigod.com","qiyou.com","biubiu.com",
 # Steam / 平台全家
 "steamcommunity.com","steamstatic.com","steamcontent.com","steamusercontent.com",
 "steamgames.com","steam-chat.com","steamserver.net","store.steampowered.com",
 # Battle.net / 暴雪
 "us.battle.net","eu.battle.net","blzstatic.com","blizzard.com",
 # Epic / UE / Riot / 主机
 "epicgames.dev","unrealengine.com","riotgames.com","valorant.com","playstation.net",
 "xbox.com","nintendo.com","nintendo.net",
 # 关键词验证：看设备是不是按子串杀
 "miyoushe.com","hoyolab.com","baidu.com",
]
def probe(host, timeout=7):
    r={"host":host,"dns":None,"ms":None,"verdict":None,"detail":""}
    t0=time.perf_counter()
    try: r["dns"]=socket.gethostbyname(host)
    except Exception as e:
        r["verdict"]="DNS_FAIL"; r["detail"]=type(e).__name__
        r["ms"]=round((time.perf_counter()-t0)*1000); return r
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        with socket.create_connection((r["dns"],443),timeout=timeout) as s:
            with ctx.wrap_socket(s,server_hostname=host): r["verdict"]="OK"
    except ConnectionResetError: r["verdict"]="RST"; r["detail"]="ConnectionResetError"
    except ssl.SSLError as e: r["verdict"]="SSL_ERR"; r["detail"]=str(e)[:50]
    except Exception as e: r["verdict"]="TCP_FAIL"; r["detail"]=f"{type(e).__name__}:{str(e)[:40]}"
    r["ms"]=round((time.perf_counter()-t0)*1000); return r

with ThreadPoolExecutor(max_workers=12) as ex: res=list(ex.map(probe,DOMAINS))
order={"RST":0,"TCP_FAIL":1,"SSL_ERR":2,"DNS_FAIL":3,"OK":4}
res.sort(key=lambda x:(order.get(x["verdict"],9),x["host"]))
for x in res: print(f"{x['verdict']:9s} {x['host']:30s} {str(x['ms']):>5s}ms  {x['dns'] or '-':16s} {x['detail']}")
json.dump(res,open("gamelist2_result.json","w",encoding="utf-8"),ensure_ascii=False,indent=1)
print("\n被 RST:", [x["host"] for x in res if x["verdict"]=="RST"])
