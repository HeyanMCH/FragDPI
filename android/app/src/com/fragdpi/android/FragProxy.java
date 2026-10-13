package com.fragdpi.android;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * FragProxy —— 本地 TCP 分段代理（Android 版，对应桌面版 tools/fragproxy）。
 *
 * <p>同时支持 <b>SOCKS5（无认证）</b> 与 <b>HTTP CONNECT</b> 两种入站协议，
 * 所以 VpnService 只要把应用流量导向它即可，不必关心应用用的是哪种代理。
 *
 * <p>核心动作：客户端发来的**第一段负载**（通常就是 TLS ClientHello），
 * 若含可解析的 SNI，就用 {@link FragCore} 算出切点、**分两次 write 发往真实服务器**，
 * 中间隔一个极短停顿 —— 这样链路上的设备看到的第一个报文里没有完整域名。
 *
 * <p>为什么不直接改包：这里只动**分段方式**，payload 逐字节不变、序号由内核维护，
 * 因此不需要任何证书、也不会破坏 TLS 校验。
 */
public final class FragProxy {

    /** 日志回调（Android 里接到 UI，JVM 测试里接到 stdout）。 */
    public interface Logger { void log(String msg); }

    private static final Logger NOP = new Logger() {
        @Override public void log(String msg) { }
    };

    private final int listenPort;
    private final FragCore.Params params;
    private final Logger logger;
    /** 两段之间的停顿（毫秒）。0 表示不等待（靠 TCP_NODELAY 分隔）。 */
    private volatile int splitDelayMs = 2;

    private ServerSocket server;
    private Thread acceptThread;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger connections = new AtomicInteger();
    private final AtomicInteger splits = new AtomicInteger();
    private final AtomicInteger failures = new AtomicInteger();

    public FragProxy(int listenPort, FragCore.Params params, Logger logger) {
        this.listenPort = listenPort;
        this.params = params == null ? new FragCore.Params() : params;
        this.logger = logger == null ? NOP : logger;
    }

    public boolean isRunning() { return running.get(); }
    public int getConnections() { return connections.get(); }
    public int getSplits() { return splits.get(); }
    public int getFailures() { return failures.get(); }
    public int getPort() { return listenPort; }
    public void setSplitDelayMs(int ms) { this.splitDelayMs = Math.max(0, ms); }

    /** 启动监听。返回实际绑定的端口（传 0 时由系统分配，便于测试）。 */
    public synchronized int start() throws IOException {
        if (running.get()) return server.getLocalPort();
        server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress("127.0.0.1", listenPort));
        running.set(true);
        acceptThread = new Thread(new Runnable() {
            @Override public void run() { acceptLoop(); }
        }, "fragproxy-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        logger.log("FragProxy 已监听 127.0.0.1:" + server.getLocalPort());
        return server.getLocalPort();
    }

    public synchronized void stop() {
        running.set(false);
        if (server != null) {
            try { server.close(); } catch (IOException ignored) { }
            server = null;
        }
        if (acceptThread != null) {
            try { acceptThread.join(1500); } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            acceptThread = null;
        }
        logger.log("FragProxy 已停止（连接 " + connections.get()
                + "，分片 " + splits.get() + "，失败 " + failures.get() + "）");
    }

    private void acceptLoop() {
        while (running.get()) {
            final Socket client;
            try {
                client = server.accept();
            } catch (IOException e) {
                if (running.get()) logger.log("accept 失败：" + e.getMessage());
                break;
            }
            Thread t = new Thread(new Runnable() {
                @Override public void run() { handle(client); }
            }, "fragproxy-conn");
            t.setDaemon(true);
            t.start();
        }
    }

    // ------------------------------------------------------------------ 单连接
    private void handle(Socket client) {
        connections.incrementAndGet();
        Socket remote = null;
        try {
            client.setTcpNoDelay(true);
            InputStream cin = client.getInputStream();
            OutputStream cout = client.getOutputStream();

            String[] target = negotiate(cin, cout);      // {host, port}
            if (target == null) return;
            String host = target[0];
            int port = Integer.parseInt(target[1]);

            remote = new Socket();
            remote.setTcpNoDelay(true);
            remote.connect(new InetSocketAddress(host, port), 10000);
            remote.setTcpNoDelay(true);

            if (!pump(cin, remote.getOutputStream(), true)) return;
            pump(remote.getInputStream(), cout, false);
        } catch (Exception e) {
            failures.incrementAndGet();
            logger.log("连接处理失败：" + e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            closeQuietly(remote);
            closeQuietly(client);
        }
    }

    /**
     * 协商入站协议，返回 {host, port}；失败返回 null。
     * 先读第一个字节：0x05 → SOCKS5；否则按 HTTP 文本处理（CONNECT）。
     */
    private String[] negotiate(InputStream in, OutputStream out) throws IOException {
        int b0 = in.read();
        if (b0 < 0) return null;
        if (b0 == 0x05) return socks5(in, out, b0);
        return httpConnect(in, out, b0);
    }

    private String[] socks5(InputStream in, OutputStream out, int b0) throws IOException {
        int nmethods = readByte(in);
        if (nmethods < 0) return null;
        skip(in, nmethods);
        out.write(new byte[]{0x05, 0x00});            // 无需认证
        out.flush();

        int ver = readByte(in), cmd = readByte(in), rsv = readByte(in), atyp = readByte(in);
        if (ver != 0x05 || cmd != 0x01) return null;  // 只支持 CONNECT
        String host;
        if (atyp == 0x01) {
            byte[] a = readN(in, 4);
            if (a == null) return null;
            host = (a[0] & 0xFF) + "." + (a[1] & 0xFF) + "." + (a[2] & 0xFF) + "." + (a[3] & 0xFF);
        } else if (atyp == 0x03) {
            int len = readByte(in);
            if (len < 0) return null;
            byte[] d = readN(in, len);
            if (d == null) return null;
            host = new String(d, StandardCharsets.US_ASCII);
        } else if (atyp == 0x04) {
            byte[] a = readN(in, 16);
            if (a == null) return null;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 16; i += 2) {
                if (sb.length() > 0) sb.append(':');
                sb.append(Integer.toHexString(((a[i] & 0xFF) << 8) | (a[i + 1] & 0xFF)));
            }
            host = sb.toString();
        } else {
            return null;
        }
        byte[] pb = readN(in, 2);
        if (pb == null) return null;
        int port = ((pb[0] & 0xFF) << 8) | (pb[1] & 0xFF);

        out.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
        out.flush();
        return new String[]{host, String.valueOf(port)};
    }

    private String[] httpConnect(InputStream in, OutputStream out, int b0) throws IOException {
        StringBuilder head = new StringBuilder();
        head.append((char) b0);
        int matched = 0;
        while (head.length() < 8192) {
            int c = in.read();
            if (c < 0) return null;
            head.append((char) c);
            char[] tail = {'\r', '\n', '\r', '\n'};
            if (c == tail[matched]) {
                matched++;
                if (matched == 4) break;
            } else {
                matched = (c == '\r') ? 1 : 0;
            }
        }
        String[] lines = head.toString().split("\r\n");
        if (lines.length == 0) return null;
        String[] parts = lines[0].split(" ");
        if (parts.length < 2 || !"CONNECT".equalsIgnoreCase(parts[0])) {
            out.write("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
                    .getBytes(StandardCharsets.US_ASCII));
            out.flush();
            return null;
        }
        String hp = parts[1];
        int idx = hp.lastIndexOf(':');
        String host = idx > 0 ? hp.substring(0, idx) : hp;
        int port = idx > 0 ? Integer.parseInt(hp.substring(idx + 1)) : 443;
        out.write("HTTP/1.1 200 Connection Established\r\n\r\n"
                .getBytes(StandardCharsets.US_ASCII));
        out.flush();
        return new String[]{host, String.valueOf(port)};
    }

    /**
     * 单向搬运。splitFirst=true 时，把**第一段**负载按切点分两次写出。
     *
     * @return 是否正常结束
     */
    private boolean pump(InputStream in, OutputStream out, boolean splitFirst) throws IOException {
        byte[] buf = new byte[16 * 1024];
        boolean first = splitFirst;
        int n;
        while ((n = in.read(buf)) > 0) {
            if (first) {
                first = false;
                if (writeSplit(out, buf, n)) continue;
            }
            out.write(buf, 0, n);
            out.flush();
        }
        return true;
    }

    /** 把一段负载按切点分两次写。返回 true 表示确实做了分片。 */
    private boolean writeSplit(OutputStream out, byte[] buf, int n) throws IOException {
        byte[] chunk = new byte[n];
        System.arraycopy(buf, 0, chunk, 0, n);
        FragCore.Sni sni = FragCore.parseSni(chunk);
        boolean haveHost = sni != null && sni.hostStart > 0;
        // 非 ClientHello / 拿不到域名时，仍尝试按阈值切（设备只看首包）
        int cut = FragCore.cutPoint(haveHost ? sni.hostStart : -1, params, haveHost);
        if (cut <= 0 || cut >= n) return false;
        if (cut < Math.max(params.minCut, FragCore.MEASURED_DEVICE_THRESHOLD)) return false;
        if (haveHost && cut >= sni.hostStart) cut = sni.hostStart + 1;
        if (cut <= 0 || cut >= n) return false;

        out.write(chunk, 0, cut);
        out.flush();
        if (splitDelayMs > 0) {
            try { Thread.sleep(splitDelayMs); } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
        out.write(chunk, cut, n - cut);
        out.flush();
        splits.incrementAndGet();
        logger.log("分片 " + (haveHost ? "(域名已隐去)" : "(未解析到域名)")
                + " 首段 " + cut + "B / 共 " + n + "B");
        return true;
    }

    // ------------------------------------------------------------------ 小工具
    private static int readByte(InputStream in) throws IOException { return in.read(); }

    private static byte[] readN(InputStream in, int n) throws IOException {
        byte[] b = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(b, off, n - off);
            if (r < 0) return null;
            off += r;
        }
        return b;
    }

    private static void skip(InputStream in, int n) throws IOException {
        long left = n;
        while (left > 0) {
            long s = in.skip(left);
            if (s <= 0) { if (in.read() < 0) return; s = 1; }
            left -= s;
        }
    }

    private static void closeQuietly(Socket s) {
        if (s != null) try { s.close(); } catch (IOException ignored) { }
    }
}
