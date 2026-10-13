package com.fragdpi.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 把本地分段代理放在前台服务里跑 —— 否则息屏/切后台会被系统回收。
 *
 * <p>这一版**刻意不碰 VpnService**：Android 上用 VpnService 无根地接管全量流量，
 * 需要把 TUN 里的 IP 包交给一个用户态 TCP 栈（tun2socks 之类）再转发到本地代理，
 * 那是一块独立且工作量大得多的工程。在没做完之前硬塞一个半成品 VpnService
 * 只会把用户流量黑洞掉，比不做更糟。
 *
 * <p>所以当前的能力边界说清楚：
 * <ul>
 *   <li>✅ 覆盖走系统代理的应用（浏览器、多数 App）—— 在 Wi-Fi 设置里把代理指向本机端口即可</li>
 *   <li>❌ 不走系统代理的应用（很多游戏客户端用裸 socket）—— 需要等 VpnService + tun2socks</li>
 * </ul>
 */
public class ProxyService extends Service {

    public static final String ACTION_START = "com.fragdpi.android.START";
    public static final String ACTION_STOP = "com.fragdpi.android.STOP";
    public static final String EXTRA_PORT = "port";
    private static final String CHANNEL_ID = "fragdpi";
    private static final int NOTIF_ID = 1001;

    /** 给 Activity 拿状态用。 */
    public static final class State {
        public boolean running;
        public int port = 8443;
        public int connections;
        public int splits;
        public int failures;
    }

    private static final State SHARED = new State();
    private static final List<String> LOG = Collections.synchronizedList(new ArrayList<String>());

    public static State sharedState() { return SHARED; }

    public static List<String> logLines() {
        synchronized (LOG) { return new ArrayList<String>(LOG); }
    }

    private static void log(String msg) {
        synchronized (LOG) {
            LOG.add(msg);
            while (LOG.size() > 300) LOG.remove(0);
        }
    }

    public final class LocalBinder extends Binder {
        public ProxyService service() { return ProxyService.this; }
    }

    private final LocalBinder binder = new LocalBinder();
    private FragProxy proxy = null;
    private FragCore.Params params = new FragCore.Params();

    @Override public IBinder onBind(Intent intent) { return binder; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            if (ACTION_STOP.equals(intent.getAction())) {
                stopProxy();
                stopForegroundCompat();
                stopSelf();
                return START_NOT_STICKY;
            }
            int port = intent.getIntExtra(EXTRA_PORT, 8443);
            params.guard = intent.getIntExtra("guard", params.guard);
            params.minCut = intent.getIntExtra("minCut", params.minCut);
            params.port = intent.getIntExtra("tlsPort", params.port);
            startProxy(port);
        }
        return START_STICKY;
    }

    private void startProxy(int port) {
        if (proxy != null && proxy.isRunning()) {
            log("代理已在运行（端口 " + proxy.getPort() + "）");
            return;
        }
        startForegroundCompat(port);
        proxy = new FragProxy(port, params, new FragProxy.Logger() {
            @Override public void log(String msg) { ProxyService.log(msg); }
        });
        try {
            int actual = proxy.start();
            SHARED.running = true;
            SHARED.port = actual;
            log("已启动，监听 127.0.0.1:" + actual);
        } catch (Exception e) {
            log("启动失败：" + e.getClass().getSimpleName() + ": " + e.getMessage());
            proxy = null;
            SHARED.running = false;
            stopForegroundCompat();
            stopSelf();
        }
    }

    private void stopProxy() {
        if (proxy != null) {
            SHARED.connections = proxy.getConnections();
            SHARED.splits = proxy.getSplits();
            SHARED.failures = proxy.getFailures();
            proxy.stop();
            proxy = null;
        }
        SHARED.running = false;
        log("已停止");
    }

    @Override
    public void onDestroy() {
        stopProxy();
        super.onDestroy();
    }

    // ------------------------------------------------------------------ 通知
    private void startForegroundCompat(int port) {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, getString(R.string.notif_channel),
                    NotificationManager.IMPORTANCE_LOW);
            nm.createNotificationChannel(ch);
        }
        Notification.Builder b = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        b.setContentTitle(getString(R.string.notif_title))
                .setContentText("本地分段代理 127.0.0.1:" + port)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setOngoing(true);
        startForeground(NOTIF_ID, b.build());
    }

    private void stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } else {
            //noinspection deprecation
            stopForeground(true);
        }
    }
}
