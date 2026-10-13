#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FragDPI 核心逻辑单测 —— 不需要管理员权限，不需要 WinDivert 驱动。

覆盖：
  · parse_sni        —— TLS ClientHello 里 SNI 的解析与偏移定位（含截断包）
  · Rule / RuleSet   —— suffix / keyword 匹配，四种模式，命中计数
  · inspect          —— IPv4 / IPv6 + TCP 头部解析与长度字段
  · split_packet     —— 分片切点、分片数、payload 逐字节还原、seq 连续性、
                        首段不含完整域名、首段不低于设备阈值、MTU 上限、
                        跳过分片的边界情况
  · privacy 模式     —— domain 不外泄、事件文本不含域名、对规则外的域名也分片、
                        不触碰命中计数（防间接泄露）
  · 随机切点         —— 1000 次都落在 [max(min_cut,114), 域名起点-1] 内、
                        窗口为空时安全回退、默认关闭
  · 多端口           —— build_filter 表达式、去重与顺序
  · 内置规则集的不变量

运行：
    python -m unittest discover -s tests -v
或：
    python tests/test_fragcore.py
"""
import os
import re
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORE = os.path.join(ROOT, "core")
if CORE not in sys.path:
    sys.path.insert(0, CORE)

import fragcore as fc  # noqa: E402


# ------------------------------------------------------------------ 测试用构造器
def build_client_hello(host=b"zzz.mihoyo.com", pad_len=64, alpn=True):
    """造一个结构真实（含填充扩展）的 TLS ClientHello 记录。"""
    rand = bytes(range(32))
    sid = b"\x20" + bytes(range(32))
    ciphers = b"\x00\x3a" + bytes(58)          # TLS_AES_256_GCM_SHA384 等
    exts = b""
    if pad_len:
        exts += b"\x00\x15" + struct.pack(">H", pad_len) + bytes(pad_len)
    if alpn:
        exts += b"\x00\x10\x00\x05\x00\x03\x02h2"
    exts += (b"\x00\x00" + struct.pack(">H", len(host) + 5) +
             struct.pack(">H", len(host) + 3) + b"\x00" +
             struct.pack(">H", len(host)) + host)
    exts += b"\x00\x33\x00\x24\x00\x1d\x00\x20" + bytes(32)
    body = (b"\x03\x03" + rand + sid + ciphers + b"\x01\x00" +
            struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def build_hello_with_domain_at(min_offset, host=b"zzz.mihoyo.com"):
    """造 ClientHello，保证域名起始偏移 >= min_offset。"""
    pad = 0
    while True:
        hello = build_client_hello(host, pad_len=pad)
        _, start, _ = fc.parse_sni(hello)
        if start is not None and start >= min_offset:
            return hello, start
        pad += 8
        if pad > 4000:
            raise AssertionError("构造失败：无法把域名推到偏移 %d" % min_offset)


def build_short_client_hello(host=b"zzz.mihoyo.com"):
    """极简 ClientHello：空 session id + 2 字节密码套件。

    这样域名起始偏移只有 ~61B，会落在实测阈值 114B 之前 —— 用来覆盖
    「域名位置太靠前、无法在不泄露域名的前提下凑够首段长度」这个边界。
    """
    exts = (b"\x00\x00" + struct.pack(">H", len(host) + 5) +
            struct.pack(">H", len(host) + 3) + b"\x00" +
            struct.pack(">H", len(host)) + host)
    body = (b"\x03\x03" + bytes(32) +            # version + random
            b"\x00" +                            # session_id len = 0
            b"\x00\x02\x13\x01" +                # cipher_suites len=2
            b"\x01\x00" +                        # compression len=1, null
            struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


IPV4_SRC, IPV4_DST = b"\xc0\xa8\x1f\x4c", b"\x3c\xa3\x4e\x18"
IPV6_SRC = bytes.fromhex("00000000000000000000000000000001")
IPV6_DST = bytes.fromhex("20010db8000000000000000000000001")


def cksum(b):
    """标准 16 位反码校验和。"""
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def tcp_segment(sport, dport, seq, payload):
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 2000, (5 << 4), 0x18,
                      65535, 0, 0) + payload
    return tcp


def build_ipv4_packet(payload, seq=1000, sport=54321, dport=443, ident=1234):
    tcp = tcp_segment(sport, dport, seq, payload)
    pseudo = IPV4_SRC + IPV4_DST + b"\x00\x06" + struct.pack(">H", len(tcp))
    tcp = tcp[:16] + struct.pack(">H", cksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), ident,
                     0x4000, 64, 6, 0, IPV4_SRC, IPV4_DST)
    ip = ip[:10] + struct.pack(">H", cksum(ip)) + ip[12:]
    return ip + tcp


def build_ipv6_packet(payload, seq=1000, sport=54321, dport=443):
    tcp = tcp_segment(sport, dport, seq, payload)
    pseudo = IPV6_SRC + IPV6_DST + struct.pack(">I", len(tcp)) + b"\x00\x00\x00\x06"
    tcp = tcp[:16] + struct.pack(">H", cksum(pseudo + tcp)) + tcp[18:]
    ip = (struct.pack(">IHBB", 0x60000000, len(tcp), 6, 64) +
          IPV6_SRC + IPV6_DST)
    return ip + tcp


# ------------------------------------------------------------------ 解包助手
def strip_and_split(packet, ver):
    """返回 (payload_off, tcp_off, payload, seq)"""
    tcp_off = 20 if ver == 4 else 40
    doff = (packet[tcp_off + 12] >> 4) * 4
    payload_off = tcp_off + doff
    total = (struct.unpack_from(">H", packet, 2)[0] if ver == 4
             else 40 + struct.unpack_from(">H", packet, 4)[0])
    return payload_off, tcp_off, packet[payload_off:total], \
        struct.unpack_from(">I", packet, tcp_off + 4)[0]


def reassemble_and_check(packets, ver=4):
    """把分片拼回去，同时校验长度字段 / seq 连续性 / 各段校验和。

    返回 dict(payload, seqs, sizes, ip_len_ok, tcp_ck_ok, seq_ok)
    """
    payload = b""
    seqs, sizes = [], []
    ip_len_ok = tcp_ck_ok = True
    for p in packets:
        if ver == 4:
            if struct.unpack_from(">H", p, 2)[0] != len(p):
                ip_len_ok = False
        else:
            if 40 + struct.unpack_from(">H", p, 4)[0] != len(p):
                ip_len_ok = False
        _, _, seg, sq = strip_and_split(p, ver)
        payload += seg
        seqs.append(sq)
        sizes.append(len(p))
        # 独立复算 TCP 校验和：保持原校验和字段，验算应为 0
        if ver == 4:
            ps = p[12:20] + b"\x00\x06" + struct.pack(">H", len(p) - 20)
            if cksum(ps + p[20:]) != 0:
                tcp_ck_ok = False
        else:
            ps = p[8:40] + struct.pack(">I", len(p) - 40) + b"\x00\x00\x00\x06"
            if cksum(ps + p[40:]) != 0:
                tcp_ck_ok = False
    # seq 必须严格连续：后一段的 seq = 前一段 seq + 前一段负载长度
    plens = [len(strip_and_split(p, ver)[2]) for p in packets]
    seq_ok = all(seqs[i + 1] == (seqs[i] + plens[i]) & 0xFFFFFFFF
                 for i in range(len(seqs) - 1))
    return {"payload": payload, "seqs": seqs, "sizes": sizes, "plens": plens,
            "ip_len_ok": ip_len_ok, "tcp_ck_ok": tcp_ck_ok, "seq_ok": seq_ok}


# ================================================================== parse_sni
class TestParseSNI(unittest.TestCase):

    def test_basic_domain_and_offset(self):
        hello = build_client_hello(b"zzz.mihoyo.com")
        dom, start, end = fc.parse_sni(hello)
        self.assertEqual(dom, "zzz.mihoyo.com")
        self.assertIsNotNone(start)
        self.assertEqual(hello[start:end], b"zzz.mihoyo.com")
        # 域名必须落在 SNI 扩展结构内部：前面应有 扩展类型(00 00) + 两层长度 + name_type
        sni_ext_at = hello.find(b"\x00\x00" + struct.pack(">H", 21))
        self.assertGreaterEqual(start, sni_ext_at)

    def test_various_domains(self):
        for host in (b"a.co", b"www.mihoyo.com", b"sg-public-api-static.hoyoverse.com",
                     b"store.steampowered.com", b"x" * 60 + b".com"):
            with self.subTest(host=host):
                hello = build_client_hello(host)
                dom, start, end = fc.parse_sni(hello)
                self.assertEqual(dom, host.decode())
                self.assertEqual(hello[start:end], host)

    def test_truncated_domain_returns_partial_and_none_end(self):
        hello = build_client_hello(b"zzz.mihoyo.com")
        _, start, _ = fc.parse_sni(hello)
        cut = start + 3
        dom, s2, e2 = fc.parse_sni(hello[:cut])
        self.assertEqual(s2, start)
        self.assertIsNone(e2, "域名不完整时 host_end 必须为 None")
        self.assertEqual(dom, "zzz")

    def test_truncated_before_domain_returns_none(self):
        hello = build_client_hello(b"zzz.mihoyo.com")
        _, start, _ = fc.parse_sni(hello)
        self.assertEqual(fc.parse_sni(hello[:start]), (None, None, None))

    def test_non_tls_inputs(self):
        for bad in (b"", b"\x17\x03\x03\x00\x10" + bytes(20),      # 非握手记录
                    b"\x16\x03\x01\x00\x10",                        # 长度不足
                    bytes(200)):                                    # 全零
            with self.subTest(bad=bad[:6]):
                self.assertEqual(fc.parse_sni(bad), (None, None, None))

    def test_server_hello_is_not_client_hello(self):
        # 握手类型 0x02（ServerHello）不应被当成 ClientHello
        hello = bytearray(build_client_hello())
        hello[5] = 0x02
        self.assertEqual(fc.parse_sni(bytes(hello)), (None, None, None))

    def test_payload_shorter_than_declared_body(self):
        """body_len 声明得比实际长，也不能崩，只能少解析或不解析。"""
        hello = build_client_hello(b"zzz.mihoyo.com")
        dom, start, end = fc.parse_sni(hello[:len(hello) - 10])
        self.assertIn(dom, (None, "zzz.mihoyo.com"))
        if dom is not None:
            self.assertEqual(hello[start:start + len(dom)], dom.encode())


# ================================================================== 规则系统
class TestRules(unittest.TestCase):

    def test_suffix_matches_subdomain_and_apex(self):
        r = fc.Rule("t", "suffix", "mihoyo.com")
        for d in ("mihoyo.com", "www.mihoyo.com", "zzz.mihoyo.com",
                  "a.b.c.mihoyo.com", "WWW.MIHOYO.COM", "mihoyo.com."):
            with self.subTest(d=d):
                self.assertTrue(r.match(d, None))
        for d in ("notmihoyo.com", "mihoyo.com.evil.net", "miyoushe.com", "", None):
            with self.subTest(d=d):
                self.assertFalse(r.match(d, None))

    def test_suffix_multiple_values_and_wildcard_prefix(self):
        r = fc.Rule("t", "suffix", "*.hoyoverse.com, battle.net ,foo.com")
        self.assertTrue(r.match("api-os-takumi.hoyoverse.com", None))
        self.assertTrue(r.match("battle.net", None))
        self.assertTrue(r.match("eu.battle.net", None))
        self.assertTrue(r.match("foo.com", None))
        self.assertFalse(r.match("hoyoverse.com.evil.ru", None))

    def test_keyword_matches_domain_and_raw_bytes(self):
        r = fc.Rule("t", "keyword", "mihoyo")
        self.assertTrue(r.match("zzz.mihoyo.com", None))
        # 域名被截断在首包外：靠原始字节兜底
        self.assertTrue(r.match(None, b"\x16\x03\x01....mihoyo.com..."))
        self.assertFalse(r.match("miyoushe.com", None))

    def test_disabled_rule_never_matches(self):
        r = fc.Rule("t", "suffix", "mihoyo.com", enabled=False)
        self.assertFalse(r.match("zzz.mihoyo.com", None))

    def test_invalid_type_falls_back_to_suffix(self):
        self.assertEqual(fc.Rule("t", "regex", "a.com").type, "suffix")

    def test_roundtrip_dict(self):
        """name/type/value/enabled 往返一致；hits 是运行期状态，不参与往返。"""
        r = fc.Rule("游戏 · X", "keyword", "a,b", True)
        r.hits = 7
        d = fc.Rule.from_dict(r.to_dict())
        self.assertEqual((d.name, d.type, d.value, d.enabled),
                         (r.name, r.type, r.value, r.enabled))
        self.assertEqual(d.hits, 0, "hits 是运行期计数，重建后应归零")

    def test_hits_survive_dict_serialization_for_display(self):
        """to_dict 必须带上 hits —— 控制台靠它显示命中次数。"""
        r = fc.Rule("x", "suffix", "a.com")
        r.hits = 42
        self.assertEqual(r.to_dict()["hits"], 42)

    def test_ruleset_modes(self):
        rs = fc.RuleSet("off")
        self.assertEqual(rs.decide("zzz.mihoyo.com", None), (False, None))
        rs = fc.RuleSet("rules")
        ok, name = rs.decide("zzz.mihoyo.com", None)
        self.assertTrue(ok)
        self.assertIn("米哈游", name)
        rs = fc.RuleSet("global")
        self.assertEqual(rs.decide("anything.example", None), (True, "全局模式"))

    def test_ruleset_off_does_not_count_hits(self):
        rs = fc.RuleSet("off")
        rs.decide("zzz.mihoyo.com", None)
        self.assertEqual(sum(r.hits for r in rs.rules), 0)

    def test_hits_accumulate_in_order_first_match_wins(self):
        rs = fc.RuleSet("rules", [
            fc.Rule("first", "suffix", "mihoyo.com"),
            fc.Rule("second", "suffix", "mihoyo.com"),
        ])
        rs.decide("zzz.mihoyo.com", None)
        self.assertEqual((rs.rules[0].hits, rs.rules[1].hits), (1, 0))

    def test_invalid_mode_falls_back(self):
        self.assertEqual(fc.RuleSet("banana").mode, "rules")

    def test_from_dict_empty_uses_defaults(self):
        rs = fc.RuleSet.from_dict({})
        self.assertEqual(len(rs.rules), len(fc.default_rules()))


class TestDefaultRuleSet(unittest.TestCase):

    def test_preset_invariants(self):
        rules = fc.default_rules()
        self.assertGreaterEqual(len(rules), 12)
        for r in rules:
            self.assertIn(r.type, fc.Rule.TYPES)
            self.assertTrue(r.value.strip(), "规则内容不能为空：%s" % r.name)
            for v in r.values():
                self.assertNotIn(" ", v, "域名里不应有空格：%r" % v)
                self.assertFalse(v.startswith("*."), "值里不要带 *.（会自行剥离）")

    def test_blocked_families_are_enabled(self):
        """实测被 RST 的 5 个域名族必须在预设里且启用。"""
        rs = fc.RuleSet("rules")
        for d in ("zzz.mihoyo.com", "act.hoyoverse.com", "store.steampowered.com",
                  "eu.battle.net", "pubgmobile.com", "uu.163.com"):
            with self.subTest(domain=d):
                ok, name = rs.decide(d, None)
                self.assertTrue(ok, "%s 应在预设中被拦截" % d)

    def test_unrelated_domains_not_matched(self):
        """与游戏无关的域名不应命中任何启用规则（避免无谓分片）。"""
        rs = fc.RuleSet("rules")
        for d in ("www.baidu.com", "github.com", "www.taobao.com",
                  "music.163.com", "cloudflare.com", "www.google.com",
                  "example.org"):
            with self.subTest(domain=d):
                ok, name = rs.decide(d, None)
                self.assertFalse(ok, "%s 不该被规则命中（命中：%s）" % (d, name))

    def test_keyword_rule_is_loose_substring_by_design(self):
        """关键词兜底规则是**子串**匹配，比 suffix 规则松 —— 这是刻意的取舍。

        `notmihoyo.com` / `mihoyo.com.evil.net` 会被兜底规则接住（多切一个包），
        换来的是「SNI 被截断在首包之外」时仍然能被识别。域名级的精确性由排在前面的
        suffix 规则提供（suffix 匹配是锚定的，不会被上面的域名骗到）。
        """
        rs = fc.RuleSet("rules")
        for d in ("notmihoyo.com", "mihoyo.com.evil.net"):
            with self.subTest(domain=d):
                ok, name = rs.decide(d, None)
                self.assertTrue(ok)
                self.assertIn("兜底", name, "应当由关键词兜底规则命中，而非 suffix 规则")

        suffix_rule = rs.rules[0]                      # 米哈游系（suffix）
        self.assertFalse(suffix_rule.match("notmihoyo.com", None))
        self.assertFalse(suffix_rule.match("mihoyo.com.evil.net", None))

    def test_measured_allowed_game_domains_are_intentionally_covered(self):
        """这些域名实测放行，但**故意**留在预设里做备用覆盖。

        分片代价只是每个连接多一个包（实测无延迟差异），换来的是设备黑名单变化时
        不用改配置。这个测试把「它们确实被覆盖」固定下来 —— 如果你想去掉这层冗余
        覆盖、只保留实测被封的 6 组，需要同时改这里和 README。
        """
        rs = fc.RuleSet("rules")
        for d in ("miyoushe.com", "hoyolab.com", "blizzard.com", "blzstatic.com",
                  "pubg.com", "lol.qq.com", "dnf.qq.com", "nintendo.com",
                  "playstation.com", "epicgames.com", "kurogame.com",
                  "hypergryph.com", "wanmei.com", "xunyou.com"):
            with self.subTest(domain=d):
                ok, name = rs.decide(d, None)
                self.assertTrue(ok, "%s 应在预设的备用覆盖里" % d)

    def test_example_rule_is_disabled(self):
        matches = [r for r in fc.default_rules() if "example.com" in r.value]
        self.assertTrue(matches)
        self.assertTrue(all(not r.enabled for r in matches))


# ================================================================== inspect
class TestInspect(unittest.TestCase):

    def test_ipv4(self):
        hello = build_client_hello()
        pkt = build_ipv4_packet(hello, seq=4242)
        r = fc.inspect(pkt)
        self.assertIsNotNone(r)
        ver, payload_off, payload, seq, tcp_off, total = r
        self.assertEqual((ver, tcp_off, seq, total), (4, 20, 4242, len(pkt)))
        self.assertEqual(payload_off, 40)
        self.assertEqual(payload, hello)

    def test_ipv6(self):
        hello = build_client_hello()
        pkt = build_ipv6_packet(hello, seq=9999)
        r = fc.inspect(pkt)
        self.assertIsNotNone(r)
        ver, payload_off, payload, seq, tcp_off, total = r
        self.assertEqual((ver, tcp_off, seq, total), (6, 40, 9999, len(pkt)))
        self.assertEqual(payload_off, 60)
        self.assertEqual(payload, hello)

    def test_non_tcp_rejected(self):
        pkt = bytearray(build_ipv4_packet(build_client_hello()))
        pkt[9] = 17                      # UDP
        self.assertIsNone(fc.inspect(bytes(pkt)))

    def test_too_short_rejected(self):
        self.assertIsNone(fc.inspect(b"\x45" * 39))
        self.assertIsNone(fc.inspect(b""))

    def test_tcp_options_shift_payload_offset(self):
        """带 TCP 选项（data offset = 32B）时 payload_off 要跟着走。"""
        hello = build_client_hello()
        opt = b"\x01" * 12                        # 12 字节选项 → doff = 32
        tcp = struct.pack(">HHIIBBHHH", 54321, 443, 1000, 2000, (8 << 4), 0x18,
                          65535, 0, 0) + opt + hello
        pseudo = IPV4_SRC + IPV4_DST + b"\x00\x06" + struct.pack(">H", len(tcp))
        tcp = tcp[:16] + struct.pack(">H", cksum(pseudo + tcp)) + tcp[18:]
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1,
                         0x4000, 64, 6, 0, IPV4_SRC, IPV4_DST)
        ip = ip[:10] + struct.pack(">H", cksum(ip)) + ip[12:]
        pkt = ip + tcp
        r = fc.inspect(pkt)
        self.assertIsNotNone(r)
        self.assertEqual(r[1], 20 + 32)
        self.assertEqual(r[2], hello)


# ================================================================== split_packet
class TestSplitPacket(unittest.TestCase):

    def setUp(self):
        self.params = fc.Params(guard=6, min_cut=124, mtu=1500, port=443)
        self.ruleset = fc.RuleSet("rules")

    # ---- 不应当被改动的包
    def test_no_match_returns_original_bytes(self):
        hello = build_client_hello(b"www.baidu.com")
        pkt = build_ipv4_packet(hello)
        res = fc.split_packet(pkt, self.ruleset, self.params)
        self.assertEqual(res["packets"], [pkt])
        self.assertIsNone(res["info"])
        self.assertEqual(res["domain"], "www.baidu.com")
        self.assertIsNone(res["rule"])

    def test_mode_off_returns_original_bytes(self):
        hello = build_client_hello(b"zzz.mihoyo.com")
        pkt = build_ipv4_packet(hello)
        res = fc.split_packet(pkt, fc.RuleSet("off"), self.params)
        self.assertEqual(res["packets"], [pkt])
        self.assertIsNone(res["info"])

    def test_non_clienthello_untouched(self):
        pkt = build_ipv4_packet(b"\x17\x03\x03\x00\x10" + bytes(64))
        res = fc.split_packet(pkt, fc.RuleSet("global"), self.params)
        self.assertEqual(res["packets"], [pkt])
        self.assertIsNone(res["info"])

    def test_ack_without_payload_untouched(self):
        pkt = build_ipv4_packet(b"")
        res = fc.split_packet(pkt, fc.RuleSet("global"), self.params)
        self.assertEqual(res["packets"], [pkt])
        self.assertIsNone(res["info"])

    def test_domain_before_device_threshold_is_skipped(self):
        """域名位置太靠前（< 设备阈值），无法在不泄露域名的前提下凑够首段 → 应跳过。

        极简 ClientHello 的域名偏移只有 ~61B，低于实测阈值 114B，所以引擎必须
        放弃分片而不是把完整域名留在首段。
        """
        hello = build_short_client_hello(b"zzz.mihoyo.com")
        _, start, _ = fc.parse_sni(hello)
        self.assertLess(start, fc.MEASURED_DEVICE_THRESHOLD,
                        "构造前提：域名偏移应小于设备阈值")
        pkt = build_ipv4_packet(hello)
        res = fc.split_packet(pkt, self.ruleset, self.params)
        self.assertEqual(res["packets"], [pkt], "不应改动这个包")
        self.assertIsNotNone(res["info"], "应当给出「跳过」说明")
        self.assertIn("跳过", res["info"])

    # ---- 正确分片
    def test_ipv4_split_core_invariants(self):
        hello, start = build_hello_with_domain_at(200, b"zzz.mihoyo.com")
        pkt = build_ipv4_packet(hello, seq=7000)
        res = fc.split_packet(pkt, self.ruleset, self.params)
        self.assertIsNotNone(res["info"])
        self.assertEqual(len(res["packets"]), 2)
        self.assertEqual(res["domain"], "zzz.mihoyo.com")

        chk = reassemble_and_check(res["packets"], ver=4)
        first = strip_and_split(res["packets"][0], 4)[2]
        cut = len(first)

        self.assertEqual(chk["payload"], hello, "两段拼回必须逐字节相同")
        self.assertTrue(chk["ip_len_ok"], "IPv4 total length 字段必须更新")
        self.assertTrue(chk["seq_ok"], "seq 必须严格连续")

        self.assertGreaterEqual(cut, fc.MEASURED_DEVICE_THRESHOLD,
                               "首段必须 >= 设备阈值 %d" % fc.MEASURED_DEVICE_THRESHOLD)
        self.assertGreaterEqual(cut, self.params.min_cut)
        self.assertLess(cut, start, "切点必须落在域名之前")
        self.assertNotIn(b"mihoyo", first, "首段不得出现完整关键词")
        self.assertNotIn(b"zzz.mihoyo.com", first)
        # 两段承载的总负载 == 原负载；第二段非空
        self.assertEqual(chk["plens"][0] + chk["plens"][1], len(hello))
        self.assertGreater(chk["plens"][1], 0, "第二段不应为空")

    def test_headers_preserved_except_length_and_seq(self):
        hello, _ = build_hello_with_domain_at(200)
        pkt = build_ipv4_packet(hello, seq=500)
        res = fc.split_packet(pkt, self.ruleset, self.params)
        p0, p1 = res["packets"]
        # IP 头部：只有 total length(2:4) 允许变
        self.assertEqual(p0[:2], pkt[:2])
        self.assertEqual(p0[4:20], pkt[4:20])
        # TCP 头部：只有 seq(24:28) 允许变，端口/flags/window 等保持
        self.assertEqual(p0[20:24], pkt[20:24])
        self.assertEqual(p0[28:40], pkt[28:40])
        self.assertEqual(p1[20:24], pkt[20:24])
        self.assertEqual(p1[28:40], pkt[28:40])
        # 第二段的 seq = 第一段 seq + 第一段负载长度
        self.assertEqual(struct.unpack_from(">I", p1, 24)[0],
                         (struct.unpack_from(">I", p0, 24)[0] + len(p0) - 40) & 0xFFFFFFFF)

    def test_ipv6_split_core_invariants(self):
        hello, start = build_hello_with_domain_at(200)
        pkt = build_ipv6_packet(hello, seq=123456)
        res = fc.split_packet(pkt, self.ruleset, self.params)
        self.assertIsNotNone(res["info"])
        chk = reassemble_and_check(res["packets"], ver=6)
        self.assertEqual(chk["payload"], hello)
        self.assertTrue(chk["ip_len_ok"], "IPv6 payload length 字段必须更新")
        self.assertTrue(chk["seq_ok"])
        first = strip_and_split(res["packets"][0], 6)[2]
        self.assertGreaterEqual(len(first), fc.MEASURED_DEVICE_THRESHOLD)
        self.assertLess(len(first), start)

    def test_seq_wraparound(self):
        """seq 接近 2^32 时不能回绕出错。"""
        hello, _ = build_hello_with_domain_at(200)
        near_max = 0xFFFFFFFF - 60
        pkt = build_ipv4_packet(hello, seq=near_max)
        res = fc.split_packet(pkt, self.ruleset, self.params)
        self.assertEqual(len(res["packets"]), 2)
        p0, p1 = res["packets"]
        s0 = struct.unpack_from(">I", p0, 24)[0]
        s1 = struct.unpack_from(">I", p1, 24)[0]
        self.assertEqual(s0, near_max)
        self.assertEqual(s1, (near_max + len(p0) - 40) & 0xFFFFFFFF)
        self.assertLess(s1, s0, "应当发生回绕")

    def test_checksums_left_stale_for_injector(self):
        """契约：split_packet 只负责切分 + 改长度字段 + 改 seq，不重算校验和。

        重注入前由 WinDivert（WinDivertHelperCalcChecksums）统一重算 —— 这里把这个
        契约固定下来，避免以后有人"顺手"在核心逻辑里算一遍反而和注入路径冲突。
        """
        hello, _ = build_hello_with_domain_at(200)
        pkt = build_ipv4_packet(hello, seq=11)
        # 前提：原始包自身的校验和是正确的
        self.assertEqual(cksum(pkt[:20]), 0, "测试构造的原始 IP 校验和应有效")
        self.assertEqual(cksum(pkt[12:20] + b"\x00\x06" +
                               struct.pack(">H", len(pkt) - 20) + pkt[20:]), 0,
                         "测试构造的原始 TCP 校验和应有效")

        res = fc.split_packet(pkt, self.ruleset, self.params)
        p0 = res["packets"][0]
        # 长度字段变了 → 原 IP 校验和必然失效（说明核心没有偷偷重算）
        self.assertNotEqual(cksum(p0[:20]), 0,
                            "长度字段已改，IP 校验和应处于待重算状态")
        # 但我们自己重算后就应恢复有效
        fixed = bytearray(p0)
        struct.pack_into(">H", fixed, 10, 0)
        struct.pack_into(">H", fixed, 10, cksum(bytes(fixed[:20])))
        self.assertEqual(cksum(bytes(fixed[:20])), 0)

    def test_large_payload_resegmented_under_mtu(self):
        """模拟网卡 LSO：一个 8000B 的段应被拆成多段且每段 <= MTU。"""
        hello, start = build_hello_with_domain_at(200)
        big = hello + b"\x17\x03\x03\x1f\x00" + bytes(6000)
        pkt = build_ipv4_packet(big, seq=1)
        res = fc.split_packet(pkt, self.ruleset, self.params)
        self.assertGreater(len(res["packets"]), 2)
        chk = reassemble_and_check(res["packets"], ver=4)
        self.assertEqual(chk["payload"], big)
        self.assertTrue(chk["ip_len_ok"])
        self.assertTrue(chk["seq_ok"])
        self.assertTrue(all(s <= self.params.mtu for s in chk["sizes"]),
                        "所有分段都必须 <= MTU，实际：%s" % chk["sizes"])
        first = strip_and_split(res["packets"][0], 4)[2]
        self.assertLess(len(first), start)

    def test_custom_mtu_respected(self):
        hello, _ = build_hello_with_domain_at(200)
        big = hello + bytes(4000)
        pkt = build_ipv4_packet(big)
        p = fc.Params(mtu=576)
        res = fc.split_packet(pkt, self.ruleset, p)
        chk = reassemble_and_check(res["packets"], ver=4)
        self.assertEqual(chk["payload"], big)
        self.assertTrue(all(s <= 576 for s in chk["sizes"]), chk["sizes"])

    def test_guard_zero_still_excludes_domain(self):
        hello, start = build_hello_with_domain_at(200)
        pkt = build_ipv4_packet(hello)
        p = fc.Params(guard=0, min_cut=124)
        res = fc.split_packet(pkt, self.ruleset, p)
        first = strip_and_split(res["packets"][0], 4)[2]
        self.assertNotIn(b"zzz.mihoyo.com", first)

    def test_guard_never_exposes_full_domain(self):
        """任意 guard 下，首段都不能出现完整域名，也不能出现完整关键词。

        注意 guard=0 时 `cut = domain_start`，引擎会主动改成 `domain_start + 1`
        （切在域名内部第 1 个字节），所以切点不保证 < domain_start，
        真正的保证是「完整域名/关键词不出现在首段」。
        """
        for guard in (0, 1, 6, 12, 20, 40):
            hello, start = build_hello_with_domain_at(200)
            pkt = build_ipv4_packet(hello)
            p = fc.Params(guard=guard, min_cut=124)
            res = fc.split_packet(pkt, self.ruleset, p)
            self.assertIsNotNone(res["info"], "guard=%d 应当分片" % guard)
            first = strip_and_split(res["packets"][0], 4)[2]
            with self.subTest(guard=guard):
                self.assertGreaterEqual(len(first), fc.MEASURED_DEVICE_THRESHOLD)
                self.assertNotIn(b"zzz.mihoyo.com", first, "完整域名不得出现在首段")
                self.assertNotIn(b"mihoyo", first, "完整关键词不得出现在首段")
                chk = reassemble_and_check(res["packets"], ver=4)
                self.assertEqual(chk["payload"], hello)
                self.assertTrue(chk["seq_ok"])
                # guard >= 1 时切点应严格早于域名
                if guard >= 1:
                    self.assertLess(len(first), start)

    def test_keyword_fallback_when_domain_truncated(self):
        """域名被截断在首包外 → suffix 规则失效，必须由 keyword 兜底规则接住。"""
        hello, start = build_hello_with_domain_at(200, b"zzz.mihoyo.com")
        truncated = hello[:start + 10]          # 只到 "zzz.mihoyo"
        dom, s2, e2 = fc.parse_sni(truncated)
        self.assertEqual(dom, "zzz.mihoyo", "应解析出域名前缀")
        self.assertEqual(s2, start)
        self.assertIsNone(e2, "域名不完整 → host_end 必须为 None")

        # suffix 规则匹配不到（"zzz.mihoyo" 不以 ".mihoyo.com" 结尾）
        rs = fc.RuleSet("rules")
        self.assertFalse(rs.rules[0].match(dom, truncated))
        # 但 keyword 兜底规则能命中（靠报文原始字节）
        kw_rule = [r for r in rs.rules if r.type == "keyword"][0]
        self.assertTrue(kw_rule.match(dom, truncated))

        pkt = build_ipv4_packet(truncated)
        res = fc.split_packet(pkt, rs, self.params)
        self.assertIsNotNone(res["info"], "截断的域名也要被识别并分片")
        self.assertEqual(res["domain"], "zzz.mihoyo")
        self.assertIn("兜底", res["rule"])
        chk = reassemble_and_check(res["packets"], ver=4)
        self.assertEqual(chk["payload"], truncated, "分片后仍应无损")
        self.assertTrue(chk["seq_ok"])

    def test_global_mode_splits_allowed_domain(self):
        hello, start = build_hello_with_domain_at(200, b"www.baidu.com")
        pkt = build_ipv4_packet(hello)
        res = fc.split_packet(pkt, fc.RuleSet("global"), self.params)
        self.assertEqual(res["rule"], "全局模式")
        self.assertEqual(len(res["packets"]), 2)

    def test_reassembly_is_lossless_for_many_offsets(self):
        """不同域名长度 / 填充长度下，分片都必须无损。"""
        for host in (b"a.mihoyo.com", b"zzz.mihoyo.com",
                     b"api-takumi-record.mihoyo.com",
                     b"sg-public-api-static.hoyoverse.com"):
            hello, start = build_hello_with_domain_at(180, host)
            pkt = build_ipv4_packet(hello, seq=31337)
            res = fc.split_packet(pkt, self.ruleset, self.params)
            with self.subTest(host=host):
                self.assertIsNotNone(res["info"])
                chk = reassemble_and_check(res["packets"], ver=4)
                self.assertEqual(chk["payload"], hello)
                self.assertTrue(chk["seq_ok"])
                self.assertLess(len(strip_and_split(res["packets"][0], 4)[2]), start)


# ================================================================== Params
class TestParams(unittest.TestCase):

    def test_roundtrip(self):
        p = fc.Params(guard=9, min_cut=200, mtu=1400, port=8443)
        d = fc.Params.from_dict(p.to_dict())
        self.assertEqual((d.guard, d.min_cut, d.mtu, d.port), (9, 200, 1400, 8443))

    def test_defaults(self):
        p = fc.Params()
        self.assertEqual((p.guard, p.min_cut, p.mtu, p.port), (6, 124, 1500, 443))

    def test_defaults_above_device_threshold(self):
        self.assertGreater(fc.Params().min_cut, fc.MEASURED_DEVICE_THRESHOLD,
                           "默认 min_cut 必须高于实测设备阈值，否则会被拦")

    def test_from_dict_missing_keys(self):
        d = fc.Params.from_dict({})
        self.assertEqual((d.guard, d.min_cut), (6, 124))


# ================================================================== 其它
class TestModuleLevel(unittest.TestCase):

    def test_find_dll_locates_bundled_binary(self):
        """仓库里应当能定位到 third_party/windivert/WinDivert.dll。"""
        path = fc.find_dll()
        self.assertIsNotNone(path, "找不到 WinDivert.dll")
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(os.path.basename(path).lower(), "windivert.dll")
        self.assertEqual(os.path.dirname(os.path.abspath(path)),
                         os.path.join(ROOT, "third_party", "windivert"))

    def test_engine_constructs_without_admin(self):
        eng = fc.Engine(fc.RuleSet("rules"), fc.Params(), on_event=lambda *a: None)
        self.assertFalse(eng.running)
        self.assertEqual(eng.stats["split"], 0)


# ================================================================== privacy 模式
HOSTNAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+", re.I)


class TestPrivacyMode(unittest.TestCase):
    """隐私保护模式的契约：domain 不外泄、事件文本不含域名、对全部 TLS 生效。

    这些用例守着「隐私模式绝不记录域名」这条底线 —— 别为了方便调试把它们删掉。
    """

    def setUp(self):
        self.params = fc.Params(guard=6, min_cut=124, mtu=1500, port=443)
        self.privacy = fc.RuleSet("privacy")
        self.rules = fc.RuleSet("rules")

    def test_mode_is_registered(self):
        self.assertIn("privacy", fc.RuleSet.MODES)
        self.assertEqual(fc.RuleSet("privacy").decide("anything.example", None),
                         (True, "隐私模式"))

    def test_domain_is_never_exposed(self):
        hello, _ = build_hello_with_domain_at(200, b"www.some-private-site.com")
        pkt = build_ipv4_packet(hello)
        res = fc.split_packet(pkt, self.privacy, self.params)
        self.assertIsNotNone(res["info"], "隐私模式应当分片")
        self.assertIsNone(res["domain"], "privacy 模式下 domain 必须为 None")

    def test_info_text_contains_no_hostname(self):
        """事件文本里不得出现任何域名 —— 这是隐私模式的核心承诺。"""
        for dom in (b"www.some-private-site.com", b"zzz.mihoyo.com", b"a.co"):
            hello, _ = build_hello_with_domain_at(200, dom)
            pkt = build_ipv4_packet(hello)
            res = fc.split_packet(pkt, self.privacy, self.params)
            with self.subTest(dom=dom):
                self.assertIsNotNone(res["info"])
                self.assertNotIn(dom.decode(), res["info"])
                self.assertIsNone(HOSTNAME_RE.search(res["info"]),
                                  "事件文本出现了疑似域名：%r" % res["info"])

    def test_splits_domains_that_rules_would_ignore(self):
        """规则模式放行的域名，隐私模式也必须分片。"""
        hello, _ = build_hello_with_domain_at(200, b"www.some-private-site.com")
        pkt = build_ipv4_packet(hello)
        self.assertEqual(len(fc.split_packet(pkt, self.rules, self.params)["packets"]), 1)
        res = fc.split_packet(pkt, self.privacy, self.params)
        self.assertEqual(len(res["packets"]), 2)

    def test_does_not_touch_rule_hit_counters(self):
        """隐私模式不遍历规则 —— hits 必须保持 0，避免间接暴露访问了哪一类站点。"""
        hello, _ = build_hello_with_domain_at(200, b"zzz.mihoyo.com")
        pkt = build_ipv4_packet(hello)
        for _ in range(5):
            fc.split_packet(pkt, self.privacy, self.params)
        self.assertEqual(sum(r.hits for r in self.privacy.rules), 0)

    def test_skip_message_also_hides_domain(self):
        """域名位置太靠前而跳过分片时，说明文本也不能带域名。"""
        pkt = build_ipv4_packet(build_short_client_hello(b"zzz.mihoyo.com"))
        res = fc.split_packet(pkt, self.privacy, self.params)
        self.assertIsNotNone(res["info"])
        self.assertIn("跳过", res["info"])
        self.assertNotIn("zzz.mihoyo.com", res["info"])
        self.assertIsNone(res["domain"])

    def test_privacy_still_reassembles_losslessly(self):
        hello, _ = build_hello_with_domain_at(200, b"secret.example.net")
        pkt = build_ipv4_packet(hello, seq=4242)
        res = fc.split_packet(pkt, self.privacy, self.params)
        chk = reassemble_and_check(res["packets"], ver=4)
        self.assertEqual(chk["payload"], hello)
        self.assertTrue(chk["seq_ok"])
        self.assertTrue(chk["ip_len_ok"])
        first = strip_and_split(res["packets"][0], 4)[2]
        self.assertNotIn(b"secret.example.net", first)
        self.assertGreaterEqual(len(first), fc.MEASURED_DEVICE_THRESHOLD)

    def test_privacy_covers_ipv6_too(self):
        hello, _ = build_hello_with_domain_at(200, b"secret.example.net")
        pkt = build_ipv6_packet(hello)
        res = fc.split_packet(pkt, self.privacy, self.params)
        self.assertIsNotNone(res["info"])
        self.assertIsNone(res["domain"])
        chk = reassemble_and_check(res["packets"], ver=6)
        self.assertEqual(chk["payload"], hello)

    def test_global_records_domain_but_privacy_does_not(self):
        """固定住 global 与 privacy 的语义差异 —— 这正是加 privacy 的理由。"""
        hello, _ = build_hello_with_domain_at(200, b"www.some-private-site.com")
        pkt = build_ipv4_packet(hello)
        g = fc.split_packet(pkt, fc.RuleSet("global"), self.params)
        p = fc.split_packet(pkt, self.privacy, self.params)
        self.assertEqual(g["domain"], "www.some-private-site.com")
        self.assertIn("www.some-private-site.com", g["info"])
        self.assertIsNone(p["domain"])
        self.assertNotIn("www.some-private-site.com", p["info"])


class TestRandomCut(unittest.TestCase):
    """随机切点：必须始终落在合法窗口内，且不能泄露完整域名。"""

    def _first_len(self, res):
        return len(strip_and_split(res["packets"][0], 4)[2])

    def test_cut_always_inside_legal_window(self):
        hello, start = build_hello_with_domain_at(200, b"zzz.mihoyo.com")
        pkt = build_ipv4_packet(hello)
        p = fc.Params(min_cut=124, random_cut=True)
        rs = fc.RuleSet("privacy")
        lo = max(p.min_cut, fc.MEASURED_DEVICE_THRESHOLD)
        seen = set()
        for _ in range(1000):
            res = fc.split_packet(pkt, rs, p)
            self.assertIsNotNone(res["info"])
            first = strip_and_split(res["packets"][0], 4)[2]
            cut = len(first)
            self.assertGreaterEqual(cut, lo, "cut 低于实测阈值，会被设备拦")
            self.assertLessEqual(cut, start - 1, "cut 越过了域名起点")
            self.assertNotIn(b"zzz.mihoyo.com", first)
            seen.add(cut)
        self.assertGreater(len(seen), 1, "随机切点应当产生多个不同的值")

    def test_random_cut_covers_the_window(self):
        hello, start = build_hello_with_domain_at(240, b"zzz.mihoyo.com")
        pkt = build_ipv4_packet(hello)
        p = fc.Params(min_cut=124, random_cut=True)
        rs = fc.RuleSet("privacy")
        cuts = {self._first_len(fc.split_packet(pkt, rs, p)) for _ in range(300)}
        lo = max(p.min_cut, fc.MEASURED_DEVICE_THRESHOLD)
        expected = start - lo
        self.assertGreater(len(cuts), max(2, expected // 2),
                           "随机覆盖度过低：%d/%d" % (len(cuts), expected))

    def test_empty_window_falls_back_without_crash(self):
        """域名起始位置太靠前 → 窗口为空 → 回退固定逻辑，不抛异常也不泄露域名。"""
        hello = build_short_client_hello(b"zzz.mihoyo.com")
        _, start, _ = fc.parse_sni(hello)
        self.assertLess(start, max(124, fc.MEASURED_DEVICE_THRESHOLD))
        res = fc.split_packet(build_ipv4_packet(hello), fc.RuleSet("privacy"),
                              fc.Params(min_cut=124, random_cut=True))
        self.assertIsNotNone(res["info"])
        self.assertIsNone(res["domain"])

    def test_random_cut_off_by_default(self):
        self.assertFalse(fc.Params().random_cut,
                         "随机切点必须默认关闭（「窗口内均匀放行」这一前提尚未实测）")

    def test_deterministic_when_disabled(self):
        """关闭随机时，同一输入必须给出同一个切点（与改造前逐字节等价）。"""
        hello, _ = build_hello_with_domain_at(200)
        pkt = build_ipv4_packet(hello)
        p = fc.Params(min_cut=124, random_cut=False)
        rs = fc.RuleSet("privacy")
        outs = {self._first_len(fc.split_packet(pkt, rs, p)) for _ in range(20)}
        self.assertEqual(len(outs), 1)


class TestMultiPort(unittest.TestCase):

    def test_ports_default_single(self):
        self.assertEqual(fc.Params().port_list(), [443])
        self.assertEqual(fc.build_filter(fc.Params()),
                         "outbound and tcp and (tcp.DstPort == 443)")

    def test_build_filter_multi_port(self):
        f = fc.build_filter(fc.Params(port=443, ports=[8443, 2053]))
        for port in (443, 8443, 2053):
            self.assertIn("tcp.DstPort == %d" % port, f)
        self.assertEqual(f.count(" or "), 2)
        self.assertTrue(f.startswith("outbound and tcp and ("))

    def test_port_list_dedupes_and_preserves_order(self):
        p = fc.Params(port=443, ports=[8443, 443, 2053, 8443])
        self.assertEqual(p.port_list(), [443, 8443, 2053])

    def test_params_roundtrip_with_privacy_fields(self):
        p = fc.Params(guard=9, min_cut=200, mtu=1400, port=443,
                      random_cut=True, ports=[8443, 2053])
        d = fc.Params.from_dict(p.to_dict())
        self.assertEqual((d.guard, d.min_cut, d.mtu, d.port), (9, 200, 1400, 443))
        self.assertTrue(d.random_cut)
        self.assertEqual(d.ports, [8443, 2053])
        self.assertEqual(d.port_list(), [443, 8443, 2053])


class TestDriverManagement(unittest.TestCase):
    """驱动残留管理 API 的形状与跨平台安全性。

    这些函数碰的是 Windows 专有接口（SCM / 注册表），所以这里**不**断言具体宿主机的
    状态（CI 上跑在 Linux，本机可能装没装驱动都不同）——只验证：
      · 任何平台上调用都不抛异常
      · 返回值形状稳定（UI 和 CLI 直接吃这些字段）
    真正「造残留 → 清理 → 验证」的闭环需要管理员权限，在
    tools/cleanup_driver.py 里手工跑。
    """

    def test_driver_service_state_returns_none_or_int(self):
        st = fc.driver_service_state()
        self.assertTrue(st is None or isinstance(st, int),
                        "应返回 None 或状态码，实际 %r" % (st,))

    def test_hvci_returns_tristate(self):
        v = fc.hvci_enabled()
        self.assertIn(v, (True, False, None),
                      "内存完整性读取应返回 True/False/None，实际 %r" % (v,))

    def test_driver_leftovers_shape(self):
        d = fc.driver_leftovers()
        for key in ("service_exists", "service_state", "service_state_name",
                    "service_running", "sys32_driver", "hvci"):
            self.assertIn(key, d, "缺少字段 %s" % key)
        self.assertIsInstance(d["service_exists"], bool)
        self.assertIsInstance(d["service_running"], bool)
        if not d["service_exists"]:
            self.assertIsNone(d["service_state"])
            self.assertFalse(d["service_running"])

    def test_cleanup_stale_driver_is_safe_and_idempotent(self):
        """没有残留时必须幂等返回成功；不抛异常。"""
        ok, msg = fc.cleanup_stale_driver()
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(msg, str)
        self.assertTrue(msg)
        if not fc.driver_leftovers()["service_exists"]:
            self.assertTrue(ok, "无残留时应视为成功：%s" % msg)

    def test_cleanup_stale_driver_never_touches_running_driver(self):
        """服务 RUNNING 时必须拒绝动手（别的程序可能在用）。"""
        d = fc.driver_leftovers()
        if not d["service_running"]:
            self.skipTest("当前没有正在运行的 WinDivert 服务，跳过")
        ok, msg = fc.cleanup_stale_driver()
        self.assertTrue(ok)
        self.assertIn("跳过", msg)
        self.assertTrue(fc.driver_leftovers()["service_exists"],
                        "RUNNING 的服务不该被删掉")


if __name__ == "__main__":
    unittest.main(verbosity=2)
