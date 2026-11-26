package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.os.Bundle;
import android.provider.Settings;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Typeface;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.wireguard.android.util.RootShell;
import com.wireguard.android.util.ToolsInstaller;

import java.util.ArrayList;
import java.util.List;

/**
 * DEBUG BUILD ONLY: an explicitly launched, read-only readiness view.
 *
 * This screen cannot Start/Stop a tunnel, modify route rules, change DNS, or
 * install iptables chains. ToolsInstaller may extract app-bundled wg tools
 * into THIS debug package's private directory; it never installs system-wide
 * kernel modules and never edits the official Wonhee installation.
 *
 * No secret keys or full VPN config are ever read or displayed.
 */
public final class RootlabReadinessActivity extends Activity {
    private TextView report;
    private Button scanButton;
    private String lastReport = "Run the read-only preflight to collect device capabilities.";

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        column.setPadding(pad, pad, pad, pad);

        TextView header = new TextView(this);
        header.setText("Wonhee 0.15.79 · Multi-Exit Readiness");
        header.setTextSize(20f);
        header.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        column.addView(header);

        TextView description = new TextView(this);
        description.setText("ROOTLAB PREVIEW — NOT A VPN CONNECTION TEST\n"
                + "This screen reads kernel capabilities and checks the app-bundled "
                + "WireGuard CLI. It does not start a tunnel, change routes, "
                + "set packet marks, touch firewall rules or modify DNS.\n"
                + "Keep your official 0.15.61 app installed. Do not start "
                + "two competing VPN sessions.");
        description.setTextSize(14f);
        description.setPadding(0, dp(12), 0, dp(12));
        column.addView(description);

        scanButton = new Button(this);
        scanButton.setText("Run read-only preflight");
        column.addView(scanButton);

        Button copy = new Button(this);
        copy.setText("Copy report");
        column.addView(copy);

        report = new TextView(this);
        report.setTypeface(Typeface.MONOSPACE);
        report.setTextSize(12f);
        report.setTextIsSelectable(true);
        report.setPadding(0, dp(12), 0, dp(12));
        report.setText(lastReport);
        column.addView(report);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(column);
        setContentView(scroll);

        scanButton.setOnClickListener(v -> {
            scanButton.setEnabled(false);
            report.setText("Reading device capabilities; no networking changes...");
            Thread worker = new Thread(() -> {
                final String text = inspectDevice();
                runOnUiThread(() -> {
                    lastReport = text;
                    report.setText(text);
                    scanButton.setEnabled(true);
                });
            }, "wonhee-lab-read-only-preflight");
            worker.setDaemon(true);
            worker.start();
        });
        copy.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager)
                    getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard != null) {
                clipboard.setPrimaryClip(
                        ClipData.newPlainText("Wonhee rootlab readiness", lastReport));
            }
        });
    }

    private String inspectDevice() {
        StringBuilder result = new StringBuilder();
        result.append("Wonhee 0.15.79 RootLab · read-only capability report\n");
        result.append("Build package: ").append(getPackageName()).append('\n');
        result.append("Private DNS (Android): ");
        try {
            result.append(Settings.Global.getString(getContentResolver(),
                    "private_dns_mode"));
        } catch (RuntimeException unreadable) {
            result.append("UNREADABLE");
        }
        result.append(" (must remain OFF)\n");
        result.append("Isolated kernel journal: ")
                .append(RootIsolatedWireGuardPreferencesJournal.pendingOrUnknown(this)
                        ? "PENDING OR UNKNOWN" : "No pending app-private steps observed")
                .append('\n');
        result.append("Isolated UID journal: ")
                .append(RootIsolatedUidPolicyPreferencesJournal.pendingOrUnknown(this)
                        ? "PENDING OR UNKNOWN" : "No pending app-private steps observed")
                .append('\n');

        try {
            RootShell shell = new RootShell(getApplicationContext());
            shell.start();
            read(shell, result, "ROOT USER", "id -u");
            read(shell, result, "ANDROID KERNEL", "uname -r");
            read(shell, result, "WIREGUARD MODULE",
                    "ls -ld /sys/module/wireguard");
            // This may extract the bundled executables into this debug app's
            // own storage. It NEVER turns on WireGuard or touches netd.
            try {
                new ToolsInstaller(getApplicationContext(), shell)
                        .ensureToolsAvailable();
                result.append("\nAPP-BUNDLED CLI: INITIALIZED\n");
            } catch (Exception toolError) {
                result.append("\nAPP-BUNDLED CLI: UNAVAILABLE (")
                        .append(toolError.getClass().getSimpleName())
                        .append(")\n");
            }
            read(shell, result, "WIREGUARD CLI", "wg --version");
            read(shell, result, "WG-QUICK CLI PATH", "command -v wg-quick");
            read(shell, result, "KERNEL WIREGUARD INTERFACES",
                    "wg show interfaces");
            read(shell, result, "IPv4 UID/FWMARK POLICY RULE HELP",
                    "ip -4 rule help 2>&1");
            read(shell, result, "IPv6 UID/FWMARK POLICY RULE HELP",
                    "ip -6 rule help 2>&1");
            read(shell, result, "IPv4 UNREACHABLE ROUTE HELP",
                    "ip -4 route help 2>&1");
            read(shell, result, "IPv6 UNREACHABLE ROUTE HELP",
                    "ip -6 route help 2>&1");
            read(shell, result, "IPv4 RESERVED 12500–12999",
                    "ip -4 rule show | grep -E '^12[5-9][0-9]{2}:' || true");
            read(shell, result, "IPv6 RESERVED 12500–12999",
                    "ip -6 rule show | grep -E '^12[5-9][0-9]{2}:' || true");
            read(shell, result, "IPv4 PRIVATE TABLES 51000–51007",
                    "ip -4 route show table all | grep -E 'table 5100[0-7]([[:space:]]|$)' || true");
            read(shell, result, "IPv6 PRIVATE TABLES 51000–51007",
                    "ip -6 route show table all | grep -E 'table 5100[0-7]([[:space:]]|$)' || true");
            read(shell, result, "IPv4 EXISTING MANGLE OUTPUT",
                    "iptables -t mangle -S OUTPUT");
            read(shell, result, "IPv6 EXISTING MANGLE OUTPUT",
                    "ip6tables -t mangle -S OUTPUT");
        } catch (Exception denied) {
            result.append("\nREAD-ONLY ROOT CHECK INCOMPLETE: ")
                    .append(denied.getClass().getSimpleName())
                    .append("\nCheck root permission for this side-by-side debug app.\n");
        }
        result.append("\nNo route, firewall, DNS or WireGuard connection was changed.\n");
        result.append("CLI help is not a verified leak-proof routing test.\n");
        return result.toString();
    }

    private void read(RootShell shell, StringBuilder out, String label,
            String command) {
        out.append("\n===== ").append(label).append(" =====\n");
        try {
            List<String> lines = new ArrayList<>();
            int status = shell.run(lines, command);
            out.append("Exit code: ").append(status).append('\n');
            if (lines.isEmpty()) {
                out.append("(no output)\n");
            } else {
                int printed = 0;
                for (String line : lines) {
                    if (printed++ >= 32) {
                        out.append("(additional lines omitted)\n");
                        break;
                    }
                    // Avoid unexpectedly dumping large kernel outputs.
                    out.append(line.length() > 280 ? line.substring(0, 280) : line)
                            .append('\n');
                }
            }
        } catch (Exception failed) {
            out.append("CHECK FAILED: ")
                    .append(failed.getClass().getSimpleName()).append('\n');
        }
    }

    private int dp(int count) {
        return Math.round(count * getResources().getDisplayMetrics().density);
    }
}
