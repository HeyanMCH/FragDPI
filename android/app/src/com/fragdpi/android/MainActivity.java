package com.fragdpi.android;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * 极简界面：启动/停止本地分段代理，显示端口与实时日志。
 *
 * <p>刻意用纯代码搭 UI（不写 layout XML）：这个版本要能用本机的手工工具链
 * （aapt2 + javac + d8 + apksigner）直接编出 APK，少一层资源依赖少一类坑。
 * 界面朴素是取舍，不是偷懒。
 */
public class MainActivity extends Activity {

    private static final int DEFAULT_PORT = 8443;

    private TextView status, logView;
    private EditText portInput;
    private Button toggle;
    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildUi());
        requestNotifPermission();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    private View buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#0b0b0d"));
        int pad = dp(16);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("FragDPI  ·  安卓版");
        title.setTextColor(Color.parseColor("#eaff2e"));
        title.setTextSize(22);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("首包分片 · 绕过只看首个 TCP 报文的 DPI 设备\nv0.1 —— 覆盖走系统代理的应用");
        sub.setTextColor(Color.parseColor("#82828f"));
        sub.setTextSize(12);
        sub.setPadding(0, dp(4), 0, dp(12));
        root.addView(sub);

        status = new TextView(this);
        status.setTextColor(Color.parseColor("#ececf1"));
        status.setTextSize(15);
        status.setPadding(0, 0, 0, dp(8));
        root.addView(status);

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);

        TextView lbl = new TextView(this);
        lbl.setText("端口 ");
        lbl.setTextColor(Color.parseColor("#82828f"));
        row.addView(lbl);

        portInput = new EditText(this);
        portInput.setInputType(InputType.TYPE_CLASS_NUMBER);
        portInput.setText(String.valueOf(DEFAULT_PORT));
        portInput.setTextColor(Color.parseColor("#ececf1"));
        portInput.setBackgroundColor(Color.parseColor("#14141a"));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        portInput.setLayoutParams(lp);
        row.addView(portInput);

        toggle = new Button(this);
        toggle.setText("启动");
        toggle.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { onToggle(); }
        });
        row.addView(toggle);
        root.addView(row);

        Button wifi = new Button(this);
        wifi.setText("打开 Wi-Fi 设置（把代理指向 127.0.0.1）");
        wifi.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                try {
                    startActivity(new Intent(Settings.ACTION_WIFI_SETTINGS));
                } catch (Exception ignored) {
                    startActivity(new Intent(Settings.ACTION_SETTINGS));
                }
            }
        });
        root.addView(wifi);

        TextView steps = new TextView(this);
        steps.setText("\n使用步骤\n"
                + "1) 点「启动」\n"
                + "2) 打开 Wi-Fi 设置 → 当前网络 → 代理 → 手动\n"
                + "  主机名 127.0.0.1，端口填上面的端口\n"
                + "3) 完成后浏览器等走系统代理的应用即可正常访问\n\n"
                + "⚠ 不走系统代理的应用（多数游戏）本版覆盖不到，需要后续的 VpnService 版本。\n"
                + "⚠ Wi-Fi 代理只对当前网络生效，换网络要重设。\n");
        steps.setTextColor(Color.parseColor("#82828f"));
        steps.setTextSize(12);
        root.addView(steps);

        TextView logTitle = new TextView(this);
        logTitle.setText("日志");
        logTitle.setTextColor(Color.parseColor("#eaff2e"));
        logTitle.setPadding(0, dp(8), 0, dp(4));
        root.addView(logTitle);

        ScrollView sc = new ScrollView(this);
        sc.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        logView = new TextView(this);
        logView.setTextColor(Color.parseColor("#9aa0a6"));
        logView.setTextSize(11);
        logView.setTypeface(Typeface.MONOSPACE);
        sc.addView(logView);
        root.addView(sc);
        return root;
    }

    private void onToggle() {
        ProxyService.State st = ProxyService.sharedState();
        Intent i = new Intent(this, ProxyService.class);
        if (st.running) {
            i.setAction(ProxyService.ACTION_STOP);
        } else {
            int port;
            try {
                port = Integer.parseInt(portInput.getText().toString().trim());
                if (port < 1024 || port > 65535) throw new NumberFormatException();
            } catch (Exception e) {
                port = DEFAULT_PORT;
                portInput.setText(String.valueOf(port));
            }
            i.setAction(ProxyService.ACTION_START);
            i.putExtra(ProxyService.EXTRA_PORT, port);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(i);
        } else {
            startService(i);
        }
        ui.postDelayed(new Runnable() {
            @Override public void run() { refresh(); }
        }, 600);
    }

    private void refresh() {
        ProxyService.State st = ProxyService.sharedState();
        if (st.running) {
            status.setText("● 运行中  127.0.0.1:" + st.port
                    + "   连接 " + st.connections + " · 分片 " + st.splits
                    + (st.failures > 0 ? (" · 失败 " + st.failures) : ""));
            status.setTextColor(Color.parseColor("#35e07a"));
            toggle.setText("停止");
            portInput.setEnabled(false);
        } else {
            status.setText("○ 已停止");
            status.setTextColor(Color.parseColor("#82828f"));
            toggle.setText("启动");
            portInput.setEnabled(true);
        }
        StringBuilder sb = new StringBuilder();
        for (String l : ProxyService.logLines()) sb.append(l).append('\n');
        logView.setText(sb.length() == 0 ? "（暂无日志）" : sb.toString());
    }

    private void requestNotifPermission() {
        if (Build.VERSION.SDK_INT >= 33) {
            try {
                requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 1);
            } catch (Exception ignored) {
                // 拒绝也不影响代理功能，只是通知不显示
            }
        }
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
