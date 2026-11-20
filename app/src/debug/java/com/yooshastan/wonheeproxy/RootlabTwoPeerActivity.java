package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * DEBUG-ONLY supervised independent WireGuard link experiment.
 * No Android per-app routing or DNS changes are allowed by this activity.
 */
public final class RootlabTwoPeerActivity extends Activity {
    private static final int PICK_FIRST = 141;
    private static final int PICK_SECOND = 142;
    private static final int PICK_HOME = 144;
    private static final int SAVE_LOG = 143;
    private static final ExecutorService WORKER = Executors.newSingleThreadExecutor();
    private static final AtomicBoolean WORKING = new AtomicBoolean(false);

    private RootlabTwoPeerSession session;
    private TextView statusText;
    private TextView aStatus;
    private TextView bStatus;
    private TextView homeStatus;
    private EditText homeTarget;
    private Button startButton;
    private Button stopButton;
    private String report = "Import Exit A and Exit B. Optionally import "
            + "a separate Home WireGuard .conf. No Android apps are routed.";

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        session = new RootlabTwoPeerSession(getApplicationContext());

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        layout.setPadding(pad, pad, pad, pad);

        TextView heading = text("Wonhee 0.15.62 · Multi-Link Lab", 21, true);
        layout.addView(heading);
        TextView warning = text(
                "FUNCTIONAL KERNEL-LINK TEST — NOT A VPN KILL SWITCH\n"
                + "This starts two independent Internet WireGuard links "
                + "plus an optional third Home WireGuard link in private "
                + "routing tables. It does NOT route phone apps, DNS or "
                + "system traffic into any tunnel.\n"
                + "Home requires its own WireGuard .conf; a Tailscale "
                + "connection cannot be imported as a WireGuard profile.\n"
                + "Private DNS must stay OFF. Do not run the official Wonhee "
                + "VPN simultaneously. Always use Safe Stop before closing "
                + "the lab or updating the app.\n"
                + "If recovery pauses, do not uninstall or overwrite the "
                + "imported configurations; export diagnostics.", 14, false);
        layout.addView(warning);

        aStatus = text("Exit A: not imported", 14, true);
        bStatus = text("Exit B: not imported", 14, true);
        homeStatus = text("Home (optional): not imported", 14, true);
        layout.addView(aStatus);
        layout.addView(bStatus);
        layout.addView(homeStatus);
        Button a = action(layout, "Import WireGuard configuration · Exit A",
                () -> choose(PICK_FIRST));
        Button b = action(layout, "Import WireGuard configuration · Exit B",
                () -> choose(PICK_SECOND));
        action(layout, "Import optional Home WireGuard .conf",
                () -> choose(PICK_HOME));
        action(layout, "Remove optional Home profile (after Safe Stop)", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Remove Home profile from this RootLab?")
                        .setMessage("Only the Home configuration in this test "
                                + "package will be deleted. If any tunnel "
                                + "ownership journal exists, removal is refused. "
                                + "Official Wonhee is never changed.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Remove Home", (dialog, which) ->
                                execute("Remove optional Home", session::removeHomeProfile))
                        .show());
        action(layout, "Check selected profiles (no root changes)", () ->
                execute("Two-exit/Home profile compatibility", session::profileReadiness));
        startButton = action(layout, "Start 2 exits + optional Home", this::confirmStart);
        action(layout, "Read handshake & counters", () ->
                execute("Handshake status", session::status));
        action(layout, "Probe two peers · bound ICMP (optional)", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Bound, numeric ICMP probes")
                        .setMessage("This sends one ICMP probe toward 1.1.1.1 "
                                + "bound to each independently verified "
                                + "WireGuard interface. It does NOT enable "
                                + "per-app routing. If Android cannot prove "
                                + "the output interface, the probe is skipped.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Probe", (dialog, which) ->
                                execute("Bound test probes", session::probe))
                        .show());
        homeTarget = new EditText(this);
        homeTarget.setSingleLine(true);
        homeTarget.setHint("Numeric Home LAN host · e.g. 10.0.0.169");
        homeTarget.setText("10.0.0.169");
        layout.addView(homeTarget);
        action(layout, "Probe Home host over Home interface (optional)", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Explicit private Home probe")
                        .setMessage("Send one ICMP request only after verifying "
                                + "the imported Home AllowedIPs, Home private "
                                + "route and named WireGuard interface. "
                                + "No Android app routing is enabled.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Probe Home", (dialog, which) -> {
                            final String target =
                                    homeTarget.getText().toString().trim();
                            execute("Bound Home test probe",
                                    () -> session.probeHome(target));
                        }).show());
        stopButton = action(layout, "Safe Stop ALL selected test links", () ->
                execute("Exact-owned Safe Stop", session::stop));
        action(layout, "Export redacted diagnostics (.txt)", this::exportLog);
        action(layout, "Copy redacted diagnostics", () -> {
            ClipboardManager clipboard = (ClipboardManager)
                    getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard != null) {
                clipboard.setPrimaryClip(ClipData.newPlainText(
                        "Wonhee 0.15.62 Multi-Link Lab",
                        report + "\n\n" + session.diagnostics()));
            }
        });

        statusText = text(report, 12, false);
        statusText.setTypeface(Typeface.MONOSPACE);
        statusText.setTextIsSelectable(true);
        statusText.setPadding(0, dp(12), 0, dp(12));
        layout.addView(statusText);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(layout);
        setContentView(scroll);

        execute("Encrypted profile inventory", () ->
                "Exit A: " + (session.hasProfile(RootlabTwoPeerSession.FIRST)
                    ? "imported" : "not imported") + "\n"
                + "Exit B: " + (session.hasProfile(RootlabTwoPeerSession.SECOND)
                    ? "imported" : "not imported") + "\n"
                + "Home: " + (session.hasProfile(RootlabTwoPeerSession.HOME)
                    ? "imported (third WireGuard link)" : "optional / not imported")
                + "\nThis screen does not automatically connect anything.");
    }

    private TextView text(String value, int sp, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sp);
        view.setPadding(0, dp(8), 0, dp(8));
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    private Button action(LinearLayout panel, String label, Runnable runnable) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setOnClickListener(v -> runnable.run());
        panel.addView(button);
        return button;
    }

    private void choose(int requestCode) {
        if (WORKING.get()) return;
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startActivityForResult(intent, requestCode);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode,
            Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) return;
        if (requestCode == SAVE_LOG) {
            Uri output = data.getData();
            try (OutputStream stream = getContentResolver().openOutputStream(output)) {
                if (stream == null) throw new IllegalStateException("Cannot open output.");
                stream.write((report + "\n\n" + session.diagnostics())
                        .getBytes(StandardCharsets.UTF_8));
            } catch (Exception failed) {
                statusText.setText("Could not export redacted report ("
                        + failed.getClass().getSimpleName() + ").");
            }
            return;
        }
        if (requestCode != PICK_FIRST && requestCode != PICK_SECOND
                && requestCode != PICK_HOME) return;
        final String slot = requestCode == PICK_FIRST
                ? RootlabTwoPeerSession.FIRST : requestCode == PICK_SECOND
                ? RootlabTwoPeerSession.SECOND : RootlabTwoPeerSession.HOME;
        Uri input = data.getData();
        execute("Encrypted import " + slot, () -> {
            try (InputStream stream = getContentResolver().openInputStream(input)) {
                return session.importProfile(slot, stream)
                        + "\n" + session.profileReadiness();
            }
        });
    }

    private void confirmStart() {
        if (WORKING.get()) return;
        new AlertDialog.Builder(this)
                .setTitle("Start 2 exits + optional Home?")
                .setMessage("This is a ROOT experimental network operation. "
                        + "Only selected WireGuard links and their private "
                        + "routing tables are changed. No Android apps "
                        + "or DNS are switched.\n\n"
                        + "Do not enable official Wonhee while this test runs. "
                        + "Use Safe Stop before uninstalling this RootLab APK.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Start links", (dialog, which) ->
                        execute("Multi-link kernel Start", session::start))
                .show();
    }

    private void exportLog() {
        Intent document = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        document.addCategory(Intent.CATEGORY_OPENABLE);
        document.setType("text/plain");
        document.putExtra(Intent.EXTRA_TITLE,
                "wonhee-01562-multilink-redacted-report.txt");
        startActivityForResult(document, SAVE_LOG);
    }

    private interface Action { String run() throws Exception; }

    private void execute(String label, Action task) {
        if (!WORKING.compareAndSet(false, true)) {
            if (statusText != null) {
                statusText.setText("Another isolated operation is still running.");
            }
            return;
        }
        if (statusText != null) statusText.setText(label + "...");
        if (startButton != null) startButton.setEnabled(false);
        if (stopButton != null) stopButton.setEnabled(false);
        WORKER.execute(() -> {
            String outcome;
            try {
                outcome = task.run();
            } catch (Exception failed) {
                // Never display a parser/RootShell exception message. It may
                // contain a config line or private WireGuard endpoint.
                outcome = label + ": REFUSED OR FAILED ("
                        + failed.getClass().getSimpleName() + ").\n"
                        + "If a kernel ownership journal is pending, use Safe Stop. "
                        + "Do not delete the app or the imported profiles.";
            } finally {
                WORKING.set(false);
            }
            final String safe = outcome;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                report = label + "\n" + safe;
                statusText.setText(report);
                startButton.setEnabled(true);
                stopButton.setEnabled(true);
                updateLabels();
            });
        });
    }

    private void updateLabels() {
        // UI names only; never show tunnel secrets, peer keys or endpoints.
        WORKER.execute(() -> {
            boolean a = false, b = false, home = false;
            try {
                a = session.hasProfile(RootlabTwoPeerSession.FIRST);
                b = session.hasProfile(RootlabTwoPeerSession.SECOND);
                home = session.hasProfile(RootlabTwoPeerSession.HOME);
            } catch (Exception ignored) { }
            final boolean first = a, second = b, third = home;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                aStatus.setText("Exit A: " + (first ? "encrypted profile ready" : "not imported"));
                bStatus.setText("Exit B: " + (second ? "encrypted profile ready" : "not imported"));
                homeStatus.setText("Home: " + (third
                        ? "encrypted WG profile ready (optional third link)"
                        : "not imported (optional)"));
            });
        });
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
