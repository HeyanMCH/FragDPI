package com.fragdpi.android;

import java.util.ArrayList;
import java.util.List;

/**
 * FragCore —— 首包分片引擎核心（Android / Java 版，对应桌面版的 core/fragcore.py）
 *
 * <p>职责：
 * <ul>
 *   <li>从 TLS ClientHello 里解析 SNI 域名与其偏移</li>
 *   <li>算出切点并把首个 TCP 报文切成多段（保持 seq 连续、payload 逐字节不变）</li>
 * </ul>
 *
 * <p><b>为什么这段逻辑要单独成类、不碰 Android API</b>：它是整个工具里唯一
 * 「算错了就静默失效」的部分 —— 切点偏一字节，域名就完整落在首段里，设备照样拦。
 * 所以它必须是纯函数、可在普通 JVM 上跑单测（见 FragCoreTest），
 * 不需要模拟器、不需要真机。
 *
 * <p>实测约束（对应桌面版同一台设备）：
 * <ul>
 *   <li>设备把前几个报文攒到 114 字节再查：首段 &lt;= 113 必被拦，&gt;= 114 通过</li>
 *   <li>切割点必须落在 SNI 扩展内部（域名之前），否则关键词完整出现在首段</li>
 * </ul>
 */
public final class FragCore {

    /** 实测设备水位线：首段 &lt;= 113 被拦。 */
    public static final int MEASURED_DEVICE_THRESHOLD = 114;

    /** 解析结果。domain 为 null 表示没解析出来；hostEnd &lt; 0 表示本包内域名不完整。 */
    public static final class Sni {
        public final String domain;
        public final int hostStart;
        public final int hostEnd;
        Sni(String domain, int hostStart, int hostEnd) {
            this.domain = domain;
            this.hostStart = hostStart;
            this.hostEnd = hostEnd;
        }
        public boolean complete() { return hostEnd >= 0; }
    }

    /** 分片参数。 */
    public static final class Params {
        public int guard = 6;        // 切点距域名起始的距离
        public int minCut = 124;     // 首段最小字节数（实测阈值 114 + 10B 余量）
        public int mtu = 1500;
        public int port = 443;
        public boolean randomCut = false;   // 默认关：见桌面版 sweep_cut --window 的说明
        public Params() {}
        public Params(int guard, int minCut, int mtu, int port) {
            this.guard = guard; this.minCut = minCut; this.mtu = mtu; this.port = port;
        }
    }

    /** inspect() 的解析结果。 */
    public static final class Pkt {
        public final int ver;          // 4 或 6
        public final int payloadOff;
        public final int tcpOff;
        public final int total;
        public final long seq;         // 用 long 承载 32 位无符号
        public final byte[] payload;
        Pkt(int ver, int payloadOff, int tcpOff, int total, long seq, byte[] payload) {
            this.ver = ver; this.payloadOff = payloadOff; this.tcpOff = tcpOff;
            this.total = total; this.seq = seq; this.payload = payload;
        }
    }

    private FragCore() {}

    private static int u8(byte[] b, int i) { return b[i] & 0xFF; }
    private static int u16(byte[] b, int i) { return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF); }
    private static long u32(byte[] b, int i) {
        return ((long) (b[i] & 0xFF) << 24) | ((b[i + 1] & 0xFF) << 16)
                | ((b[i + 2] & 0xFF) << 8) | (b[i + 3] & 0xFF);
    }

    // ------------------------------------------------------------------ SNI
    /**
     * 从 TLS ClientHello 里取出 SNI 域名与偏移。
     *
     * @return Sni 或 null（不是 ClientHello / 结构不合法）
     */
    public static Sni parseSni(byte[] payload) {
        if (payload == null || payload.length < 9) return null;
        if (u8(payload, 0) != 0x16 || u8(payload, 1) != 0x03) return null;

        int hsBase = 5;
        if (payload.length < hsBase + 4) return null;
        if (u8(payload, hsBase) != 0x01) return null;              // 必须是 ClientHello

        int bodyLen = ((payload[hsBase + 1] & 0xFF) << 16)
                | ((payload[hsBase + 2] & 0xFF) << 8) | (payload[hsBase + 3] & 0xFF);
        int bodyBase = hsBase + 4;
        int bodyEnd = Math.min(payload.length, bodyBase + bodyLen);

        int pos = 34;                                              // version(2) + random(32)
        if (bodyBase + pos >= bodyEnd) return null;

        int sidLen = u8(payload, bodyBase + pos);
        pos += 1 + sidLen;
        if (bodyBase + pos + 2 > bodyEnd) return null;

        int csLen = u16(payload, bodyBase + pos);
        pos += 2 + csLen;
        if (bodyBase + pos + 1 > bodyEnd) return null;

        int compLen = u8(payload, bodyBase + pos);
        pos += 1 + compLen;
        if (bodyBase + pos + 2 > bodyEnd) return null;

        int extLen = u16(payload, bodyBase + pos);
        pos += 2;
        int extEnd = Math.min(bodyEnd - bodyBase, pos + extLen);

        while (pos + 4 <= extEnd) {
            int etype = u16(payload, bodyBase + pos);
            int elen = u16(payload, bodyBase + pos + 2);
            if (etype == 0x0000) {                                 // server_name
                //  结构：etype(2) elen(2) | list_len(2) name_type(1) name_len(2) name
                //  所以 name_len 在 pos+7，name 在 pos+9
                if (pos + 9 > bodyEnd - bodyBase) return null;
                int nlen = u16(payload, bodyBase + pos + 7);
                int start = bodyBase + pos + 9;
                if (start >= payload.length) return null;
                int avail = Math.min(nlen, payload.length - start);
                StringBuilder sb = new StringBuilder(avail);
                for (int i = 0; i < avail; i++) {
                    int c = payload[start + i] & 0xFF;
                    sb.append(c >= 32 && c < 127 ? (char) c : '?');
                }
                boolean complete = avail >= nlen;
                return new Sni(sb.toString(), start, complete ? start + nlen : -1);
            }
            pos += 4 + elen;
        }
        return null;
    }

    // ------------------------------------------------------------------ 拆包
    /** 解析 IPv4/IPv6 + TCP 头。不是 TCP / 结构不合法时返回 null。 */
    public static Pkt inspect(byte[] data) {
        if (data == null || data.length < 40) return null;
        int ver = (data[0] >> 4) & 0x0F;
        int tcpOff, hdrLen;
        int total;
        if (ver == 4) {
            int ihl = (data[0] & 0x0F) * 4;
            if (data.length < ihl + 20) return null;
            total = Math.min(u16(data, 2), data.length);
            if (u8(data, 9) != 6) return null;                     // 必须是 TCP
            tcpOff = ihl;
            hdrLen = ihl;
        } else if (ver == 6) {
            if (data.length < 60 || u8(data, 6) != 6) return null;
            hdrLen = 40;
            total = Math.min(hdrLen + u16(data, 4), data.length);
            tcpOff = hdrLen;
        } else {
            return null;
        }
        if (total < tcpOff + 20) return null;
        int doff = ((data[tcpOff + 12] >> 4) & 0x0F) * 4;
        if (doff < 20) return null;
        int payloadOff = tcpOff + doff;
        if (payloadOff >= total) return null;

        byte[] payload = new byte[total - payloadOff];
        System.arraycopy(data, payloadOff, payload, 0, payload.length);
        long seq = u32(data, tcpOff + 4);
        return new Pkt(ver, payloadOff, tcpOff, total, seq, payload);
    }

    /** 按当前设备阈值算出切点（与桌面版 _cut_point 逻辑一致）。 */
    public static int cutPoint(int hostStart, Params p, boolean haveHost) {
        // 设备阈值是**实测的物理属性**，不是用户偏好 —— 必须是硬下限。
        // （用 min 的话，min_cut 一旦被调到阈值以下，就会放行低于阈值的切点，白切。）
        int lo = Math.max(p.minCut, MEASURED_DEVICE_THRESHOLD);
        if (!haveHost) return lo;
        if (p.randomCut) {
            int hi = hostStart - 1;
            if (hi >= lo) return lo + (int) (Math.random() * (hi - lo + 1));
        }
        int cut = Math.max(lo, hostStart - p.guard);
        if (cut >= hostStart) cut = hostStart + 1;                 // 落在域名内部
        return cut;
    }

    /**
     * 把承载 ClientHello 的首个 TCP 报文切成多段。
     *
     * @return 分段后的报文列表；不需要分片时返回 null（调用方应原样放行）
     */
    public static List<byte[]> splitPacket(byte[] data, Params p) {
        Pkt pk = inspect(data);
        if (pk == null) return null;
        byte[] payload = pk.payload;
        if (payload.length < 6) return null;
        if (u8(payload, 0) != 0x16 || u8(payload, 1) != 0x03 || u8(payload, 5) != 0x01) {
            return null;                                            // 只处理 ClientHello
        }

        Sni sni = parseSni(payload);
        boolean haveHost = sni != null && sni.hostStart > 0;
        int hostStart = haveHost ? sni.hostStart : -1;

        int cut = cutPoint(hostStart, p, haveHost);
        // 下限用 max：设备阈值是硬下限，不能被 min_cut 放松
        if (cut <= 0 || cut >= payload.length - 1
                || cut < Math.max(p.minCut, MEASURED_DEVICE_THRESHOLD)) {
            return null;                                            // 位置不合适，别乱切
        }
        return splitIntoSegments(data, pk, cut, p);
    }

    private static List<byte[]> splitIntoSegments(byte[] data, Pkt pk, int cut, Params p) {
        int maxSeg = Math.max(200, p.mtu - pk.payloadOff);
        List<Integer> bounds = new ArrayList<Integer>();
        bounds.add(0);
        bounds.add(cut);
        while (bounds.get(bounds.size() - 1) < pk.payload.length) {
            bounds.add(Math.min(pk.payload.length, bounds.get(bounds.size() - 1) + maxSeg));
        }
        List<byte[]> out = new ArrayList<byte[]>(bounds.size() - 1);
        for (int i = 0; i < bounds.size() - 1; i++) {
            int from = bounds.get(i), to = bounds.get(i + 1);
            int segLen = to - from;
            byte[] pkt = new byte[pk.payloadOff + segLen];
            System.arraycopy(data, 0, pkt, 0, pk.payloadOff);        // 头原样拷
            System.arraycopy(pk.payload, from, pkt, pk.payloadOff, segLen);

            long newSeq = (pk.seq + from) & 0xFFFFFFFFL;
            putU32(pkt, pk.tcpOff + 4, newSeq);
            if (pk.ver == 4) {
                putU16(pkt, 2, pkt.length);                          // IPv4 total length
            } else {
                putU16(pkt, 4, pkt.length - 40);                     // IPv6 payload length
            }
            out.add(pkt);
        }
        return out;
    }

    private static void putU16(byte[] b, int i, int v) {
        b[i] = (byte) ((v >> 8) & 0xFF);
        b[i + 1] = (byte) (v & 0xFF);
    }

    private static void putU32(byte[] b, int i, long v) {
        b[i] = (byte) ((v >> 24) & 0xFF);
        b[i + 1] = (byte) ((v >> 16) & 0xFF);
        b[i + 2] = (byte) ((v >> 8) & 0xFF);
        b[i + 3] = (byte) (v & 0xFF);
    }

    /** 标准 16 位反码校验和（仅供测试与自检使用）。 */
    public static int checksum(byte[]... parts) {
        long sum = 0;
        int carryBytes = 0;
        for (byte[] b : parts) {
            int i = 0;
            if (carryBytes == 1) {
                sum += ((0x00 << 8) | (b[0] & 0xFF)) & 0xFFFF;
                i = 1;
                carryBytes = 0;
            }
            for (; i + 1 < b.length; i += 2) {
                sum += (((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF));
            }
            if (i < b.length) { carryBytes = 1; sum += ((b[i] & 0xFF) << 8); }
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        }
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) ((~sum) & 0xFFFF);
    }

    /** 把分段拼回去（测试用）：返回负载字节 + 各段长度。 */
    public static byte[] reassemble(List<byte[]> packets) {
        int total = 0;
        List<byte[]> segs = new ArrayList<byte[]>();
        for (byte[] p : packets) {
            Pkt pk = inspect(p);
            segs.add(pk.payload);
            total += pk.payload.length;
        }
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] s : segs) {
            System.arraycopy(s, 0, out, off, s.length);
            off += s.length;
        }
        return out;
    }
}
