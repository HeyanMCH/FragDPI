package com.fragdpi.android;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * FragCore 的纯 JVM 单测（不需要 Android / 模拟器 / 真机）。
 *
 * <p>刻意用普通 main() 而不是 JUnit：本机没有 Gradle/JUnit，但**必须能真的跑起来**。
 * 这些测试向量与桌面版 tests/test_fragcore.py 是同一批 —— 端口的一致性靠它们对齐。
 *
 * 运行：
 *   javac -d out android/app/src/com/fragdpi/android/FragCore*.java
 *   java  -cp out com.fragdpi.android.FragCoreTest
 */
public final class FragCoreTest {

    private static int passed = 0;
    private static final List<String> failures = new ArrayList<String>();

    private static void check(String name, boolean cond, String extra) {
        if (cond) {
            passed++;
        } else {
            failures.add(name + (extra == null || extra.isEmpty() ? "" : "   [" + extra + "]"));
            System.out.println("  FAIL  " + name + (extra == null ? "" : "   " + extra));
        }
    }

    private static void check(String name, boolean cond) { check(name, cond, ""); }

    // ------------------------------------------------------------ 构造器
    private static void be16(ByteArrayOutputStream o, int v) {
        o.write((v >> 8) & 0xFF);
        o.write(v & 0xFF);
    }

    private static void be24(ByteArrayOutputStream o, int v) {
        o.write((v >> 16) & 0xFF);
        o.write((v >> 8) & 0xFF);
        o.write(v & 0xFF);
    }

    /** 造一个结构真实的 TLS ClientHello 记录（含填充扩展），对应 Python 的 build_client_hello。 */
    static byte[] buildClientHello(byte[] host, int padLen, boolean alpn) {
        ByteArrayOutputStream exts = new ByteArrayOutputStream();
        if (padLen > 0) {                       // padding 扩展 0x0015
            exts.write(0x00); exts.write(0x15);
            be16(exts, padLen);
            for (int i = 0; i < padLen; i++) exts.write(0);
        }
        if (alpn) {                             // 0x0010
            byte[] a = new byte[]{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2'};
            exts.write(a, 0, a.length);
        }
        // server_name 扩展 0x0000
        exts.write(0x00); exts.write(0x00);
        be16(exts, host.length + 5);
        be16(exts, host.length + 3);
        exts.write(0x00);
        be16(exts, host.length);
        exts.write(host, 0, host.length);
        // 0x0033 key_share
        byte[] ks = new byte[]{0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20};
        exts.write(ks, 0, ks.length);
        for (int i = 0; i < 32; i++) exts.write(0);

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x03); body.write(0x03);                     // version
        for (int i = 0; i < 32; i++) body.write(i);             // random
        body.write(0x20);                                        // session_id len = 32
        for (int i = 0; i < 32; i++) body.write(i);
        be16(body, 58);                                          // cipher_suites len
        for (int i = 0; i < 58; i++) body.write(0);
        body.write(0x01); body.write(0x00);                      // compression
        byte[] ex = exts.toByteArray();
        be16(body, ex.length);
        body.write(ex, 0, ex.length);

        byte[] bd = body.toByteArray();
        ByteArrayOutputStream hs = new ByteArrayOutputStream();
        hs.write(0x01);
        be24(hs, bd.length);
        hs.write(bd, 0, bd.length);

        byte[] h = hs.toByteArray();
        ByteArrayOutputStream rec = new ByteArrayOutputStream();
        rec.write(0x16); rec.write(0x03); rec.write(0x01);
        be16(rec, h.length);
        rec.write(h, 0, h.length);
        return rec.toByteArray();
    }

    /** 极简 ClientHello：域名偏移只有 ~61B，低于设备阈值 114。 */
    static byte[] buildShortClientHello(byte[] host) {
        ByteArrayOutputStream exts = new ByteArrayOutputStream();
        exts.write(0x00); exts.write(0x00);
        be16(exts, host.length + 5);
        be16(exts, host.length + 3);
        exts.write(0x00);
        be16(exts, host.length);
        exts.write(host, 0, host.length);

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x03); body.write(0x03);
        for (int i = 0; i < 32; i++) body.write(0);
        body.write(0x00);                                        // session_id len = 0
        be16(body, 2); body.write(0x13); body.write(0x01);
        body.write(0x01); body.write(0x00);
        byte[] ex = exts.toByteArray();
        be16(body, ex.length);
        body.write(ex, 0, ex.length);

        byte[] bd = body.toByteArray();
        ByteArrayOutputStream hs = new ByteArrayOutputStream();
        hs.write(0x01);
        be24(hs, bd.length);
        hs.write(bd, 0, bd.length);
        byte[] h = hs.toByteArray();
        ByteArrayOutputStream rec = new ByteArrayOutputStream();
        rec.write(0x16); rec.write(0x03); rec.write(0x01);
        be16(rec, h.length);
        rec.write(h, 0, h.length);
        return rec.toByteArray();
    }

    static byte[] buildHelloWithDomainAt(int minOffset, byte[] host) {
        for (int pad = 0; pad <= 4000; pad += 8) {
            byte[] hello = buildClientHello(host, pad, true);
            FragCore.Sni s = FragCore.parseSni(hello);
            if (s != null && s.hostStart >= minOffset) return hello;
        }
        throw new IllegalStateException("无法把域名推到偏移 " + minOffset);
    }

    private static final byte[] SRC = new byte[]{(byte) 0xc0, (byte) 0xa8, 0x1f, 0x4c};
    private static final byte[] DST = new byte[]{0x3c, (byte) 0xa3, 0x4e, 0x18};

    private static byte[] tcpSegment(int sport, int dport, long seq, byte[] payload) {
        // TCP 头 20 字节：sport(2) dport(2) seq(4) ack(4) doff(1) flags(1) win(2) ck(2) urg(2)
        // 注意 ack 是 **4** 字节 —— 少写 2 字节会让 data offset 落到错误位置、整个头错位。
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        be16(o, sport);
        be16(o, dport);
        o.write((int) ((seq >> 24) & 0xFF)); o.write((int) ((seq >> 16) & 0xFF));
        o.write((int) ((seq >> 8) & 0xFF)); o.write((int) (seq & 0xFF));
        o.write(0); o.write(0);                 // ack = 2000
        o.write((2000 >> 8) & 0xFF); o.write(2000 & 0xFF);
        o.write(5 << 4);                        // data offset = 5 * 4 = 20
        o.write(0x18);                          // PSH | ACK
        be16(o, 65535);                         // window
        be16(o, 0);                             // checksum（稍后回填）
        be16(o, 0);                             // urgent
        o.write(payload, 0, payload.length);
        return o.toByteArray();
    }

    static byte[] buildIpv4Packet(byte[] payload, long seq) {
        byte[] tcp = tcpSegment(54321, 443, seq, payload);
        byte[] pseudo = concat(SRC, DST, new byte[]{0x00, 0x06}, u16b(tcp.length));
        byte[] tcpFixed = tcp.clone();
        int ck = FragCore.checksum(pseudo, tcp);
        tcpFixed[16] = (byte) ((ck >> 8) & 0xFF);
        tcpFixed[17] = (byte) (ck & 0xFF);

        ByteArrayOutputStream ip = new ByteArrayOutputStream();
        ip.write(0x45); ip.write(0x00);
        ip.write(((20 + tcpFixed.length) >> 8) & 0xFF);
        ip.write((20 + tcpFixed.length) & 0xFF);
        ip.write(0x04); ip.write(0xD2);        // id
        ip.write(0x40); ip.write(0x00);
        ip.write(64); ip.write(6); ip.write(0); ip.write(0);
        ip.write(SRC, 0, 4); ip.write(DST, 0, 4);
        byte[] iph = ip.toByteArray();
        int ipck = FragCore.checksum(iph);
        iph[10] = (byte) ((ipck >> 8) & 0xFF);
        iph[11] = (byte) (ipck & 0xFF);
        return concat(iph, tcpFixed);
    }

    static byte[] buildIpv6Packet(byte[] payload, long seq) {
        byte[] src = new byte[16]; src[15] = 1;
        byte[] dst = new byte[16]; dst[0] = 0x20; dst[1] = 0x01; dst[2] = 0x0d; dst[3] = (byte) 0xb8;
        dst[15] = 1;
        byte[] tcp = tcpSegment(54321, 443, seq, payload);
        byte[] pseudo = concat(src, dst, u32b(tcp.length), new byte[]{0, 0, 0, 6});
        byte[] tcpFixed = tcp.clone();
        int ck = FragCore.checksum(pseudo, tcp);
        tcpFixed[16] = (byte) ((ck >> 8) & 0xFF);
        tcpFixed[17] = (byte) (ck & 0xFF);

        ByteArrayOutputStream ip = new ByteArrayOutputStream();
        ip.write(0x60); ip.write(0); ip.write(0); ip.write(0);
        be16(ip, tcpFixed.length);
        ip.write(6); ip.write(64);
        ip.write(src, 0, 16); ip.write(dst, 0, 16);
        return concat(ip.toByteArray(), tcpFixed);
    }

    private static byte[] u16b(int v) { return new byte[]{(byte) ((v >> 8) & 0xFF), (byte) (v & 0xFF)}; }
    private static byte[] u32b(int v) {
        return new byte[]{(byte) ((v >> 24) & 0xFF), (byte) ((v >> 16) & 0xFF),
                (byte) ((v >> 8) & 0xFF), (byte) (v & 0xFF)};
    }

    private static byte[] concat(byte[]... arrs) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] a : arrs) o.write(a, 0, a.length);
        return o.toByteArray();
    }

    private static boolean contains(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }

    private static byte[] firstPayload(List<byte[]> pkts) {
        return FragCore.inspect(pkts.get(0)).payload;
    }

    // ------------------------------------------------------------ 用例
    static void testParseSni() {
        byte[] hello = buildClientHello(bytes("zzz.mihoyo.com"), 64, true);
        FragCore.Sni s = FragCore.parseSni(hello);
        check("parseSni 解析出域名", s != null && "zzz.mihoyo.com".equals(s.domain),
                s == null ? "null" : s.domain);
        check("parseSni 偏移可回读原文", s != null
                && new String(hello, s.hostStart, s.hostEnd - s.hostStart).equals("zzz.mihoyo.com"));

        for (String d : new String[]{"a.co", "www.mihoyo.com", "store.steampowered.com"}) {
            FragCore.Sni r = FragCore.parseSni(buildClientHello(bytes(d), 64, true));
            check("parseSni " + d, r != null && d.equals(r.domain));
        }

        // 截断：域名不完整 → hostEnd < 0
        FragCore.Sni s2 = FragCore.parseSni(hello);
        byte[] cut = new byte[s2.hostStart + 3];
        System.arraycopy(hello, 0, cut, 0, cut.length);
        FragCore.Sni t = FragCore.parseSni(cut);
        check("截断包 domain 为前缀", t != null && "zzz".equals(t.domain));
        check("截断包 hostEnd < 0（不完整）", t != null && t.hostEnd < 0);

        // 非 TLS / 全零 / 长度不足
        check("非握手记录返回 null", FragCore.parseSni(new byte[]{0x17, 0x03, 0x03, 0, 16}) == null);
        check("长度不足返回 null", FragCore.parseSni(new byte[]{0x16, 0x03, 0x01, 0, 16}) == null);
        check("全零返回 null", FragCore.parseSni(new byte[200]) == null);

        // ServerHello（握手类型 0x02）不该被当 ClientHello
        byte[] sh = buildClientHello(bytes("zzz.mihoyo.com"), 64, true).clone();
        sh[5] = 0x02;
        check("ServerHello 不被当 ClientHello", FragCore.parseSni(sh) == null);
    }

    static void testSplitIpv4() {
        FragCore.Params p = new FragCore.Params(6, 124, 1500, 443);
        byte[] host = bytes("zzz.mihoyo.com");
        byte[] hello = buildHelloWithDomainAt(200, host);
        FragCore.Sni sni = FragCore.parseSni(hello);
        byte[] pkt = buildIpv4Packet(hello, 7000);

        List<byte[]> segs = FragCore.splitPacket(pkt, p);
        check("IPv4 应当分片", segs != null);
        if (segs == null) return;
        check("分成 2 段", segs.size() == 2, "实际 " + segs.size());

        byte[] back = FragCore.reassemble(segs);
        check("两段拼回逐字节相同", java.util.Arrays.equals(back, hello));

        byte[] first = firstPayload(segs);
        int cut = first.length;
        check("首段 >= 设备阈值", cut >= FragCore.MEASURED_DEVICE_THRESHOLD, "cut=" + cut);
        check("首段 >= min_cut", cut >= p.minCut, "cut=" + cut);
        check("切点在域名之前", cut < sni.hostStart, "cut=" + cut + " host=" + sni.hostStart);
        check("首段不含完整域名", !contains(first, host));
        check("首段不含关键词 mihoyo", !contains(first, bytes("mihoyo")));

        // 长度字段
        boolean lenOk = true;
        for (byte[] s : segs) {
            int tot = ((s[2] & 0xFF) << 8) | (s[3] & 0xFF);
            if (tot != s.length) lenOk = false;
        }
        check("IPv4 total length 已更新", lenOk);

        // seq 严格连续
        long s0 = FragCore.inspect(segs.get(0)).seq;
        long s1 = FragCore.inspect(segs.get(1)).seq;
        check("seq 连续", s1 == ((s0 + first.length) & 0xFFFFFFFFL),
                s0 + " -> " + s1);
        check("第二段非空", FragCore.inspect(segs.get(1)).payload.length > 0);
    }

    static void testSeqWrap() {
        FragCore.Params p = new FragCore.Params(6, 124, 1500, 443);
        byte[] hello = buildHelloWithDomainAt(200, bytes("zzz.mihoyo.com"));
        long nearMax = 0xFFFFFFFFL - 60;
        List<byte[]> segs = FragCore.splitPacket(buildIpv4Packet(hello, nearMax), p);
        check("回绕场景仍分片", segs != null && segs.size() == 2);
        if (segs == null || segs.size() != 2) return;
        long s0 = FragCore.inspect(segs.get(0)).seq;
        long s1 = FragCore.inspect(segs.get(1)).seq;
        check("起始 seq 正确", s0 == nearMax);
        check("已发生回绕（s1 < s0）", s1 < s0, s0 + " -> " + s1);
    }

    static void testIpv6() {
        FragCore.Params p = new FragCore.Params(6, 124, 1500, 443);
        byte[] hello = buildHelloWithDomainAt(200, bytes("zzz.mihoyo.com"));
        List<byte[]> segs = FragCore.splitPacket(buildIpv6Packet(hello, 123456), p);
        check("IPv6 应当分片", segs != null);
        if (segs == null) return;
        check("IPv6 两段拼回一致", java.util.Arrays.equals(FragCore.reassemble(segs), hello));
        byte[] first = firstPayload(segs);
        check("IPv6 首段 >= 阈值", first.length >= FragCore.MEASURED_DEVICE_THRESHOLD);
        boolean lenOk = true;
        for (byte[] s : segs) {
            int pl = ((s[4] & 0xFF) << 8) | (s[5] & 0xFF);
            if (40 + pl != s.length) lenOk = false;
        }
        check("IPv6 payload length 已更新", lenOk);
    }

    static void testSkips() {
        FragCore.Params p = new FragCore.Params(6, 124, 1500, 443);
        // 域名太靠前 → 必须放弃分片，而不是把域名留在首段
        byte[] shortHello = buildShortClientHello(bytes("zzz.mihoyo.com"));
        FragCore.Sni s = FragCore.parseSni(shortHello);
        check("短包域名偏移 < 阈值（构造前提）",
                s != null && s.hostStart < FragCore.MEASURED_DEVICE_THRESHOLD,
                s == null ? "null" : ("hostStart=" + s.hostStart));
        check("域名太靠前时跳过分片",
                FragCore.splitPacket(buildIpv4Packet(shortHello, 1000), p) == null);

        // 非 ClientHello
        byte[] notHello = buildIpv4Packet(concat(new byte[]{0x17, 0x03, 0x03, 0x00, 0x10}, new byte[64]), 1);
        check("非 ClientHello 不动", FragCore.splitPacket(notHello, p) == null);

        // 空负载
        check("空负载不动", FragCore.splitPacket(buildIpv4Packet(new byte[0], 1), p) == null);
    }

    static void testMtuResegmentation() {
        FragCore.Params p = new FragCore.Params(6, 124, 1500, 443);
        byte[] hello = buildHelloWithDomainAt(200, bytes("zzz.mihoyo.com"));
        byte[] big = concat(hello, new byte[]{0x17, 0x03, 0x03, 0x1f, 0x00}, new byte[6000]);
        List<byte[]> segs = FragCore.splitPacket(buildIpv4Packet(big, 1), p);
        check("大负载被多段切分", segs != null && segs.size() > 2,
                segs == null ? "null" : ("段数=" + segs.size()));
        if (segs == null) return;
        check("多段拼回无损", java.util.Arrays.equals(FragCore.reassemble(segs), big));
        boolean underMtu = true;
        for (byte[] s : segs) if (s.length > p.mtu) underMtu = false;
        check("每段 <= MTU", underMtu);

        FragCore.Params p2 = new FragCore.Params(6, 124, 576, 443);
        List<byte[]> segs2 = FragCore.splitPacket(buildIpv4Packet(big, 1), p2);
        boolean under576 = true;
        for (byte[] s : segs2) if (s.length > 576) under576 = false;
        check("自定义 MTU=576 生效", under576);
    }

    static void testManyDomains() {
        FragCore.Params p = new FragCore.Params(6, 124, 1500, 443);
        String[] hosts = {"a.mihoyo.com", "zzz.mihoyo.com", "api-takumi-record.mihoyo.com",
                "sg-public-api-static.hoyoverse.com", "x.com"};
        for (String h : hosts) {
            byte[] host = bytes(h);
            byte[] hello = buildHelloWithDomainAt(180, host);
            FragCore.Sni sni = FragCore.parseSni(hello);
            List<byte[]> segs = FragCore.splitPacket(buildIpv4Packet(hello, 31337), p);
            check("多域名分片无损 " + h, segs != null
                    && java.util.Arrays.equals(FragCore.reassemble(segs), hello));
            if (segs != null) {
                check("多域名首段不含域名 " + h, !contains(firstPayload(segs), host));
                check("多域名切点在域名前 " + h, firstPayload(segs).length < sni.hostStart);
            }
        }
    }

    static void testGuards() {
        // guard=0 时 cut 会落到域名内部，真正的保证是「完整域名不出现在首段」
        for (int guard : new int[]{0, 1, 6, 12, 20, 40}) {
            FragCore.Params p = new FragCore.Params(guard, 124, 1500, 443);
            byte[] host = bytes("zzz.mihoyo.com");
            byte[] hello = buildHelloWithDomainAt(200, host);
            List<byte[]> segs = FragCore.splitPacket(buildIpv4Packet(hello, 1), p);
            check("guard=" + guard + " 仍分片", segs != null);
            if (segs == null) continue;
            byte[] first = firstPayload(segs);
            check("guard=" + guard + " 首段 >= 阈值",
                    first.length >= FragCore.MEASURED_DEVICE_THRESHOLD);
            check("guard=" + guard + " 首段无完整域名", !contains(first, host));
            check("guard=" + guard + " 首段无完整关键词", !contains(first, bytes("mihoyo")));
        }
    }

    static void testRandomCutWindow() {
        FragCore.Params p = new FragCore.Params(6, 124, 1500, 443);
        p.randomCut = true;
        byte[] host = bytes("zzz.mihoyo.com");
        byte[] hello = buildHelloWithDomainAt(200, host);
        FragCore.Sni sni = FragCore.parseSni(hello);
        byte[] pkt = buildIpv4Packet(hello, 1);
        int lo = Math.max(p.minCut, FragCore.MEASURED_DEVICE_THRESHOLD);
        int bad = 0;
        java.util.Set<Integer> seen = new java.util.HashSet<Integer>();
        for (int i = 0; i < 500; i++) {
            List<byte[]> segs = FragCore.splitPacket(pkt, p);
            if (segs == null) { bad++; continue; }
            int cut = firstPayload(segs).length;
            if (cut < lo || cut > sni.hostStart - 1) bad++;
            seen.add(cut);
        }
        check("随机切点 500 次全在合法窗口内", bad == 0, "越界 " + bad + " 次");
        check("随机切点确实随机", seen.size() > 1, "取值 " + seen.size() + " 种");
    }

    static void testThresholdBoundary() {
        // 边界：让 min_cut 真正成为约束（guard 大到 hostStart-guard < min_cut），
        // 此时切点应恰好等于 min_cut=114（= 设备阈值），且必须被接受而不是被拒。
        FragCore.Params p = new FragCore.Params(200, FragCore.MEASURED_DEVICE_THRESHOLD, 1500, 443);
        byte[] host = bytes("zzz.mihoyo.com");
        byte[] hello = buildHelloWithDomainAt(300, host);
        FragCore.Sni sni = FragCore.parseSni(hello);
        List<byte[]> segs = FragCore.splitPacket(buildIpv4Packet(hello, 1), p);
        check("min_cut=114（边界值）仍分片", segs != null);
        if (segs == null) return;
        byte[] first = firstPayload(segs);
        check("min_cut 起约束时首段 == 114", first.length == 114, "实际 " + first.length);
        check("边界值下切点仍在域名之前", first.length < sni.hostStart);
        check("边界值下首段不含域名", !contains(first, host));

        // 再退一步：min_cut 比设备阈值还小 → 阈值必须兜底，不能被 106 这种值放行。
        // 这正是移植到 Java 后、用同一批向量对拍时才暴露的 bug：
        // 原来的下限校验写的是 min(min_cut, 阈值)，min_cut=60 时校验放松成 cut<60，
        // 于是 106（低于阈值 114）也被放行 —— 分片照样被设备拦，等于白切。
        FragCore.Params p2 = new FragCore.Params(200, 60, 1500, 443);
        List<byte[]> segs2 = FragCore.splitPacket(buildIpv4Packet(hello, 1), p2);
        check("min_cut 低于阈值时由阈值兜底", segs2 != null);
        if (segs2 != null) {
            int c = firstPayload(segs2).length;
            check("兜底后首段 >= 阈值", c >= FragCore.MEASURED_DEVICE_THRESHOLD, "实际 " + c);
            check("兜底后首段 == 114", c == 114, "实际 " + c);
            check("兜底后首段不含域名", !contains(firstPayload(segs2), host));
        }
    }

    private static byte[] bytes(String s) { return s.getBytes(java.nio.charset.StandardCharsets.US_ASCII); }

    public static void main(String[] args) {
        System.out.println("=== FragCore 纯 JVM 单测 ===");
        long t0 = System.currentTimeMillis();
        testParseSni();
        testSplitIpv4();
        testSeqWrap();
        testIpv6();
        testSkips();
        testMtuResegmentation();
        testManyDomains();
        testGuards();
        testRandomCutWindow();
        testThresholdBoundary();

        System.out.println();
        System.out.println("通过 " + passed + " 项，失败 " + failures.size() + " 项"
                + "  (" + (System.currentTimeMillis() - t0) + " ms)");
        if (!failures.isEmpty()) {
            System.out.println("失败清单：");
            for (String f : failures) System.out.println("  - " + f);
            System.exit(1);
        }
        System.out.println("OK");
    }
}
