package com.fragdpi.android;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * FragProxy 的端到端验证（纯 JVM，loopback 真 socket，不需要 Android）。
 *
 * <p>这是「分片到底有没有生效」的硬证据：在**服务端侧**记录第一次 read() 拿到多少字节。
 * 如果代理把首段和其余部分分两次 write（且 TCP_NODELAY 生效），
 * 服务端的第一次 read 就应该只拿到切点长度 —— 而不是整段 ClientHello。
 *
 * 运行：
 *   javac -d out android/app/src/com/fragdpi/android/*.java
 *   java  -cp out com.fragdpi.android.FragProxyTest
 */
public final class FragProxyTest {

    private static int passed = 0;
    private static final List<String> failures = new ArrayList<String>();

    private static void check(String name, boolean cond, String extra) {
        if (cond) passed++;
        else {
            failures.add(name + (extra == null || extra.isEmpty() ? "" : "   [" + extra + "]"));
            System.out.println("  FAIL  " + name + (extra == null ? "" : "   " + extra));
        }
    }

    private static void check(String name, boolean cond) { check(name, cond, ""); }

    /** 扮演「真实服务器」：记录第一次 read 的字节数，并收集完整请求。 */
    private static final class FakeServer implements Runnable {
        final ServerSocket ss;
        volatile int firstReadLen = -1;
        volatile byte[] received;
        volatile int connectionCount = 0;

        FakeServer() throws Exception {
            ss = new ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress("127.0.0.1", 0));
        }

        int port() { return ss.getLocalPort(); }

        @Override public void run() {
            try {
                while (!ss.isClosed()) {
                    Socket s = ss.accept();
                    connectionCount++;
                    s.setTcpNoDelay(true);
                    InputStream in = s.getInputStream();
                    byte[] buf = new byte[64 * 1024];
                    int first = -1;
                    int total = 0;
                    int n;
                    // 读到 4 字节「结束标记」为止（标记由客户端在负载之后发出）
                    while (total < buf.length && (n = in.read(buf, total, buf.length - total)) > 0) {
                        if (first < 0) first = n;
                        total += n;
                        if (total >= 5 && buf[total - 4] == 'Z' && buf[total - 3] == 'E'
                                && buf[total - 2] == 'N' && buf[total - 1] == 'D') break;
                    }
                    firstReadLen = first;
                    received = Arrays.copyOf(buf, total);
                    s.close();
                }
            } catch (Exception ignored) {
                // 关闭时正常退出
            }
        }

        void close() { try { ss.close(); } catch (Exception ignored) { } }
    }

    private static final byte[] MARK = new byte[]{'Z', 'E', 'N', 'D'};

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] o = new byte[a.length + b.length];
        System.arraycopy(a, 0, o, 0, a.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }

    /** 走 SOCKS5 连到假服务器，发 payload，返回服务端侧观察结果。 */
    private static FakeServer roundTripSocks(byte[] payload, FragCore.Params params) throws Exception {
        FakeServer srv = new FakeServer();
        Thread st = new Thread(srv, "fake-server");
        st.setDaemon(true);
        st.start();

        FragCore.Params p = params != null ? params : new FragCore.Params();
        FragProxy proxy = new FragProxy(0, p, new FragProxy.Logger() {
            @Override public void log(String msg) { }
        });
        proxy.setSplitDelayMs(5);
        int proxyPort = proxy.start();

        Socket c = new Socket();
        c.setTcpNoDelay(true);
        c.connect(new InetSocketAddress("127.0.0.1", proxyPort), 5000);
        InputStream in = c.getInputStream();
        OutputStream out = c.getOutputStream();

        // SOCKS5 问候
        out.write(new byte[]{0x05, 0x01, 0x00});
        out.flush();
        byte[] rep = new byte[2];
        readFully(in, rep, 2);
        check("SOCKS5 握手成功", rep[0] == 0x05 && rep[1] == 0x00);

        // CONNECT 到**假服务器的实际端口**。注意 ATYP=0x01 时地址是 **4 个原始字节**，
        // 不是「长度 + ASCII」（那是 ATYP=0x03 域名形式）—— 写错会让代理去连一个乱码 IP。
        int targetPort = srv.port();
        byte[] req = new byte[]{
                0x05, 0x01, 0x00, 0x01,
                127, 0, 0, 1,
                (byte) ((targetPort >> 8) & 0xFF), (byte) (targetPort & 0xFF)
        };
        out.write(req);
        out.flush();
        byte[] resp = new byte[10];
        readFully(in, resp, 10);
        check("SOCKS5 CONNECT 被接受", resp[1] == 0x00, "rep=" + resp[1]);

        // 发 ClientHello + 结束标记
        out.write(payload);
        out.flush();
        out.write(MARK);
        out.flush();

        long deadline = System.currentTimeMillis() + 5000;
        while (srv.received == null && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
        }
        proxy.stop();
        srv.close();
        return srv;
    }

    private static void readFully(InputStream in, byte[] b, int n) throws Exception {
        int off = 0;
        while (off < n) {
            int r = in.read(b, off, n - off);
            if (r < 0) throw new IllegalStateException("连接提前关闭");
            off += r;
        }
    }

    static void testSocks5Split() throws Exception {
        FragCore.Params p = new FragCore.Params(6, 124, 1500, 443);
        byte[] hello = FragCoreTest.buildHelloWithDomainAt(200, "zzz.mihoyo.com".getBytes("US-ASCII"));
        FragCore.Sni sni = FragCore.parseSni(hello);
        check("构造前提：解析到域名", sni != null && "zzz.mihoyo.com".equals(sni.domain));

        FakeServer srv = roundTripSocks(hello, p);
        check("服务端收到了数据", srv.received != null);
        if (srv.received == null) return;

        byte[] got = srv.received;
        // 去掉尾部标记
        byte[] body = Arrays.copyOf(got, got.length - MARK.length);
        check("负载逐字节一致（分片无损）", Arrays.equals(body, hello),
                "收到 " + body.length + "B / 期望 " + hello.length + "B");

        int first = srv.firstReadLen;
        check("服务端第一次 read 拿到了数据", first > 0, "firstReadLen=" + first);
        check("★ 第一次 read 只拿到首段（= 切点）", first < hello.length,
                "first=" + first + " total=" + hello.length);
        check("★ 首段 >= 设备阈值", first >= FragCore.MEASURED_DEVICE_THRESHOLD, "first=" + first);
        check("★ 首段落在域名之前", first < sni.hostStart,
                "first=" + first + " hostStart=" + sni.hostStart);
        check("★ 首段不含完整域名" + "",
                !contains(Arrays.copyOf(body, first), "zzz.mihoyo.com".getBytes("US-ASCII")));
    }

    static void testHttpConnectSplit() throws Exception {
        FragCore.Params p = new FragCore.Params(6, 124, 1500, 443);
        byte[] hello = FragCoreTest.buildHelloWithDomainAt(200, "a.mihoyo.com".getBytes("US-ASCII"));
        FragCore.Sni sni = FragCore.parseSni(hello);

        FakeServer srv = new FakeServer();
        Thread st = new Thread(srv, "fake-server-http");
        st.setDaemon(true);
        st.start();

        FragProxy proxy = new FragProxy(0, p, new FragProxy.Logger() {
            @Override public void log(String msg) { }
        });
        proxy.setSplitDelayMs(5);
        int proxyPort = proxy.start();

        Socket c = new Socket();
        c.setTcpNoDelay(true);
        c.connect(new InetSocketAddress("127.0.0.1", proxyPort), 5000);
        InputStream in = c.getInputStream();
        OutputStream out = c.getOutputStream();
        out.write(("CONNECT 127.0.0.1:" + srv.port() + " HTTP/1.1\r\nHost: x\r\n\r\n")
                .getBytes("US-ASCII"));
        out.flush();

        StringBuilder resp = new StringBuilder();
        int state = 0;
        int ch;
        while ((ch = in.read()) >= 0) {
            resp.append((char) ch);
            char[] t = {'\r', '\n', '\r', '\n'};
            if (ch == t[state]) { state++; if (state == 4) break; }
            else state = (ch == '\r') ? 1 : 0;
        }
        check("HTTP CONNECT 返回 200", resp.indexOf("200") > 0, resp.toString().trim());

        out.write(hello);
        out.flush();
        out.write(MARK);
        out.flush();
        long deadline = System.currentTimeMillis() + 5000;
        while (srv.received == null && System.currentTimeMillis() < deadline) Thread.sleep(20);
        proxy.stop();
        srv.close();

        check("HTTP 通道也收到数据", srv.received != null);
        if (srv.received == null) return;
        byte[] body = Arrays.copyOf(srv.received, srv.received.length - MARK.length);
        check("HTTP 通道分片无损", Arrays.equals(body, hello));
        check("★ HTTP 通道首段 < 全长", srv.firstReadLen < hello.length,
                "first=" + srv.firstReadLen + " total=" + hello.length);
        check("★ HTTP 通道首段不含域名",
                !contains(Arrays.copyOf(body, srv.firstReadLen), "a.mihoyo.com".getBytes("US-ASCII")));
    }

    static void testNonTlsPassthrough() throws Exception {
        // 非 ClientHello：应当原样透传，不分片
        FragCore.Params p = new FragCore.Params(6, 124, 1500, 443);
        byte[] payload = new byte[400];
        for (int i = 0; i < payload.length; i++) payload[i] = (byte) ('a' + (i % 26));

        FakeServer srv = roundTripSocks(payload, p);
        check("非 TLS 流量也能通过", srv.received != null);
        if (srv.received == null) return;
        byte[] body = Arrays.copyOf(srv.received, srv.received.length - MARK.length);
        check("非 TLS 流量原样透传", Arrays.equals(body, payload));
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

    public static void main(String[] args) throws Exception {
        System.out.println("=== FragProxy 端到端验证（loopback 真 socket）===");
        testSocks5Split();
        testHttpConnectSplit();
        testNonTlsPassthrough();
        System.out.println();
        System.out.println("通过 " + passed + " 项，失败 " + failures.size() + " 项");
        if (!failures.isEmpty()) {
            System.out.println("失败清单：");
            for (String f : failures) System.out.println("  - " + f);
            System.exit(1);
        }
        System.out.println("OK");
    }
}
