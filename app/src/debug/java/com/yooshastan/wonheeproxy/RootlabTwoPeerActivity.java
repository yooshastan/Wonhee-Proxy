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
 * Exact Moka per-app routing requires deliberate opt-in and safe rollback.
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
            + "a separate Home WireGuard .conf. App routing needs explicit opt-in.";

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        session = new RootlabTwoPeerSession(getApplicationContext());

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        layout.setPadding(pad, pad, pad, pad);

        TextView heading = text("Wonhee 0.15.76 · Brave Nightly Home Pilot", 21, true);
        layout.addView(heading);
        TextView warning = text(
                "FUNCTIONAL KERNEL-LINK TEST — NOT A VPN KILL SWITCH\n"
                + "This starts two independent Internet WireGuard links "
                + "plus an optional third Home WireGuard link in private "
                + "routing tables. It does NOT route phone apps, DNS or "
                + "system traffic into any tunnel automatically.\n"
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
        action(layout, "Probe Exit A TCP/HTTPS · bound (optional)", () ->
                confirmTcpProbe(RootlabTwoPeerSession.FIRST, "1.1.1.1:443"));
        action(layout, "Probe Exit B TCP/HTTPS · bound (optional)", () ->
                confirmTcpProbe(RootlabTwoPeerSession.SECOND, "1.1.1.1:443"));
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
        action(layout, "Probe Home Navidrome TCP/HTTP · bound (optional)", () ->
                confirmTcpProbe(RootlabTwoPeerSession.HOME,
                        homeTarget.getText().toString().trim() + ":4533"));
        action(layout, "Moka → Home routing readiness (read-only)", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Moka / Home routing preflight")
                        .setMessage("Read-only: identify the installed Moka UID "
                                + "and verify the three owned WireGuard links, "
                                + "Home identity and Navidrome route. "
                                + "This does NOT route any app, open ports or "
                                + "install DNS, UID or firewall rules. "
                                + "Activation remains locked until the "
                                + "fail-closed policy is independently tested.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Check", (dialog, which) ->
                                execute("Moka Home routing readiness",
                                        session::previewMokaHomeRouting))
                        .show());
        action(layout, "Inspect Moka Home firewall (read-only)", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Dual-stack firewall inspection")
                        .setMessage("Read Android's current IPv4/IPv6 OUTPUT rules, "
                                + "check reserved name collisions and CLI syntax, "
                                + "and validate the proposed exact-owned Moka policy. "
                                + "No firewall rules, app routing or DNS changes "
                                + "will be made. Activation remains locked.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Inspect", (dialog, which) ->
                                execute("Moka Home firewall inspection",
                                        session::auditMokaHomeFirewall))
                        .show());
        action(layout, "Stage detached Moka firewall chains · opt-in test", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Stage detached IPv4/IPv6 chains?")
                        .setMessage("This is a root firewall mutation test. "
                                + "It creates and verifies two private filter chains "
                                + "with Moka/Home allow and terminal reject rules, "
                                + "but NEVER connects them to Android OUTPUT or "
                                + "any app UID rule. No app packets are affected. "
                                + "Exact-owned Safe Stop removes the staged chains "
                                + "before removing the WireGuard links. "
                                + "If recovery is uncertain, the journal is retained. "
                                + "Do not uninstall, clear data or update until clean.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Stage detached chains", (dialog, which) ->
                                execute("Detached Moka firewall stage",
                                        session::stageDetachedMokaFirewall))
                        .show());
        action(layout, "Attach Moka IPv6 OUTPUT guard · opt-in test", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Temporarily block Moka IPv6 traffic?")
                        .setMessage("ADVANCED ROOT TEST. Requires successful staging "
                                + "of both detached firewall chains. "
                                + "This WILL insert one real IPv6 OUTPUT rule "
                                + "matching only the detected Moka UID, rejecting "
                                + "Moka's IPv6 connections until Safe Stop. "
                                + "Other apps and Moka IPv4 remain unchanged. "
                                + "It does NOT route Moka through Home or provide "
                                + "dual-stack leak protection. Safe Stop must "
                                + "remove this hook BEFORE deleting firewall "
                                + "chains or WireGuard links. If recovery pauses, "
                                + "DO NOT uninstall or clear app data.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Attach IPv6 guard", (dialog, which) ->
                                execute("Moka IPv6 OUTPUT hook",
                                        session::attachMokaIpv6Hook))
                        .show());
        action(layout, "Read Moka IPv6 REJECT counters · read-only", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Read Moka IPv6 firewall counters")
                        .setMessage("Read exact OUTPUT hook and REJECT packet/byte "
                                + "counters without resetting them. Take one "
                                + "reading, open Moka and try a normal network "
                                + "action, then take a second reading. No test "
                                + "traffic is generated by Wonhee. A zero delta "
                                + "does not prove the firewall is broken and "
                                + "a positive delta does not prove leak safety.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Read counters", (dialog, which) ->
                                execute("Moka IPv6 firewall counters",
                                        session::readMokaIpv6Counters))
                        .show());
        action(layout, "Audit cellular Moka → Home route · read-only", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Inspect Android's Home route selection")
                        .setMessage("READ ONLY: checks private Home table 51002, "
                                + "the proposed UID policy priority, and an "
                                + "Android route-get lookup for Moka UID 10300. "
                                + "This is NOT a live Moka socket or leak test. "
                                + "No UID routes, firewall rules, DNS or packet "
                                + "routing will be activated.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Inspect routing", (dialog, which) ->
                                execute("Moka Home cellular route audit",
                                        session::auditMokaHomeRouteSelection))
                        .show());
        action(layout, "Audit proposed Moka IPv4 rule order · read-only", () ->
                execute("Moka IPv4 enforcement ordering",
                        session::previewMokaIpv4Order));
        action(layout, "Attach Moka IPv4 OUTPUT guard · opt-in test", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Temporarily restrict Moka IPv4 connections?")
                        .setMessage("ADVANCED ROOT EXPERIMENT. Requires all three "
                                + "WireGuard links, both exact-owned staged "
                                + "chains, and the Moka IPv6 OUTPUT guard. "
                                + "This WILL attach one IPv4 OUTPUT rule matching "
                                + "the installed Moka UID. Only TCP "
                                + "10.0.0.169:4533 already leaving through "
                                + "the Home WireGuard interface is permitted "
                                + "to proceed; other Moka IPv4 output is REJECTED. "
                                + "Moka may lose ALL cellular connectivity. "
                                + "No app routing, DNS or VPN activation occurs. "
                                + "The existing IPv6 guard remains active. "
                                + "Safe Stop MUST remove the IPv4 hook FIRST. "
                                + "Do not uninstall/clear data if cleanup pauses.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Attach IPv4 guard", (dialog, which) ->
                                execute("Moka IPv4 OUTPUT hook",
                                        session::attachMokaIpv4Hook))
                        .show());
        action(layout, "Read Moka IPv4 REJECT counters · read-only", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Read Moka IPv4 packet counters")
                        .setMessage("While both guards are active, take a baseline "
                                + "of Moka IPv4 OUTPUT hook, Home RETURN and "
                                + "REJECT counters. Open Moka over cellular, "
                                + "attempt connecting to Navidrome, and take "
                                + "a second reading. No counters reset and no "
                                + "traffic generated by Wonhee. After checking, "
                                + "run Exact-owned Safe Stop.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Read counters", (dialog, which) ->
                                execute("Moka IPv4 firewall counters",
                                        session::readMokaIpv4Counters))
                        .show());
        action(layout, "Stage Home /32 fallback blocker · opt-in test", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Add exact private Home fallback route?")
                        .setMessage("ROOT NETWORK ROUTE TEST. Requires three "
                                + "working links and both owned Moka IPv4/IPv6 "
                                + "OUTPUT guards. Adds a high-metric UNREACHABLE "
                                + "route for ONLY 10.0.0.169/32 in private "
                                + "Home table 51002. No Android UID selector, "
                                + "mark, DNS, or global route is installed. "
                                + "It should not affect normal app networking. "
                                + "This DOES NOT prove fail-closed behavior "
                                + "or make Moka work over cellular. "
                                + "Use Exact-owned Safe Stop after inspecting. "
                                + "Do not clear data if recovery pauses.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Stage fallback route", (dialog, which) ->
                                execute("Moka Home fallback blocker",
                                        session::stageMokaHomeFallback))
                        .show());
        action(layout, "Inspect Home /32 fallback · read-only", () ->
                execute("Moka Home fallback route audit",
                        session::auditMokaHomeFallback));
        action(layout, "Route Moka to Home · opt-in live UID test", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Temporarily route Moka through Home?")
                        .setMessage("ROOTED CELLULAR EXPERIMENT. This WILL "
                                + "install one IPv4 policy rule for Moka UID "
                                + "10300 and ONLY destination 10.0.0.169/32. "
                                + "It requires the staged unreachable route, "
                                + "both exact Moka IPv4/IPv6 firewall hooks, "
                                + "a live Home WireGuard interface, and "
                                + "Android Private DNS OFF. It refuses other "
                                + "Android VPNs and non-cellular networks. "
                                + "The Home route and synthetic UID lookup "
                                + "will be checked immediately. Moka may "
                                + "connect to Navidrome or may fail. "
                                + "This is NOT yet proven safe during "
                                + "Home loss, external Android route changes "
                                + "or DNS/mark variations. Do NOT disconnect "
                                + "Home or reboot for this first test. "
                                + "Save the results and run Exact-owned "
                                + "Safe Stop immediately afterward; it must "
                                + "remove the UID rule FIRST. Never uninstall "
                                + "or clear app data if recovery pauses.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Enable Moka-only test", (dialog, which) ->
                                execute("Moka Home UID selector",
                                        session::activateMokaHomeUidRoute))
                        .show());
        action(layout, "Inspect active Moka Home UID route · read-only", () ->
                execute("Moka Home UID route audit",
                        session::auditMokaHomeUidRoute));
        action(layout, "Route Brave Nightly to Home · opt-in live browser test", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Enable Brave Nightly Home-only test?")
                        .setMessage("ADVANCED ROOT TEST. Requires cellular, "
                                + "Android Private DNS OFF, all three WG links, "
                                + "Moka's active UID selector, both Moka firewall "
                                + "guards and exact-owned Home fallback. "
                                + "This installs a separate Brave UID rule and "
                                + "dual-stack firewall guards. Brave's exact package UID may ONLY "
                                + "contact http://10.0.0.169:4533 through Home; "
                                + "other traffic from that UID is blocked "
                                + "until Safe Stop; sandboxed subprocess UIDs are NOT covered. Use only an unauthenticated test page (no passwords or sign-in). No Chrome or system routing "
                                + "changes. Synthetic routing is NOT proof of "
                                + "real browser packet delivery. Do not disconnect "
                                + "Home, change networks or reboot during this "
                                + "unproven experiment. Run Exact-owned Safe Stop "
                                + "afterward; it removes Brave ownership FIRST. "
                                + "Never uninstall/clear data if recovery pauses.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Enable Brave pilot", (dialog, which) ->
                                execute("Brave Nightly Home routing pilot",
                                        session::activateBraveHomePilot))
                        .show());
        action(layout, "Inspect Brave Home pilot · read-only", () ->
                execute("Brave Home routing audit", session::auditBraveHomePilot));
        action(layout, "Diagnose Moka + browser Home path · read-only", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Inspect Moka, Chrome and Brave routing?")
                        .setMessage("READ-ONLY SNAPSHOT. This compares the saved "
                                + "Moka selector outcome with current Android "
                                + "UID policy rules and private Home routes. "
                                + "It reads per-app synthetic route lookups, "
                                + "Moka firewall counters and TCP socket states "
                                + "for 10.0.0.169:4533 with redacted UID/mark metadata. "
                                + "No networking changes, probe traffic, "
                                + "packet capture or browser routing activation. "
                                + "It does not prove whether a real app packet "
                                + "reached Home. Capture once before an app "
                                + "connection attempt, retry in Moka or a "
                                + "browser, then capture again; use Exact-owned "
                                + "Safe Stop afterward.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Inspect", (dialog, which) ->
                                execute("Moka and browser connection path",
                                        session::diagnoseMokaBrowserPath))
                        .show());
        action(layout, "Home encrypted transport correction · opt-in lab", () ->
                new android.app.AlertDialog.Builder(this)
                        .setTitle("Test exact Home IPv6 transport exception?")
                        .setMessage("Requires existing three links and exact Moka dual-stack guards, "
                                + "fallback and UID selector. Cellular and Private DNS OFF. "
                                + "Uses a device-tested candidate mark, not a production allocation. "
                                + "Only the Moka no-login TCP diagnostic is permitted. "
                                + "Do not authenticate or stream. Use Exact-owned Safe Stop afterward.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Run transport trial", (dialog, which) ->
                                execute("Home encrypted transport trial", session::activateHomeTransportTrial))
                        .show());
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
        scroll.setFitsSystemWindows(true);
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

    private void confirmTcpProbe(String slot, String target) {
        if (WORKING.get()) return;
        new AlertDialog.Builder(this)
                .setTitle("Optional interface-bound TCP test · " + slot)
                .setMessage("Only send a numeric TCP/HTTP diagnostic through "
                        + "the verified WireGuard interface. The test checks "
                        + "owned routes and uses root curl --interface when "
                        + "available; otherwise it refuses. It never adds "
                        + "app UID, DNS or firewall rules, and does not prove "
                        + "kill-switch or no-fallback safety. "
                        + "Target: " + target)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Test TCP", (dialog, which) ->
                        execute("Bound " + slot + " TCP probe",
                                () -> session.probeTcp(slot, target)))
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
        if (RootlabHomeTransportTrial.pendingOrUnknown(getApplicationContext())
                && !"Exact-owned Safe Stop".equals(label)) {
            if (statusText != null) statusText.setText(
                    "Transport ownership pending. Only Exact-owned Safe Stop is available.");
            return;
        }
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
