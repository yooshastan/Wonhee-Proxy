package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.print.PrintManager;
import android.text.InputType;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import com.wireguard.android.backend.WgQuickBackend;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.text.DateFormat;
import java.io.IOException;
import java.io.OutputStream;

/** Manually started isolated test UI; leaves the existing GoBackend path intact. */
public final class RootDualKernelActivity extends Activity {
    private static final int REQUEST_SAVE_SESSION_REPORT = 7911;
    private static final int PINK = 0xfffbadd8;
    private static final int WHITE = 0xfff8f1f9;
    private static final int MUTED = 0xffc4b7c9;
    private static final int PANEL = 0xff242033;
    private static final int NAV_ACTIVE = 0xff6a3b65;
    private static final int NAV_IDLE = 0xff292337;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final List<SecureTunnelProfileStore.Profile> saved = new ArrayList<>();
    private RootDualKernelSession dual;
    private RootLabPreferences uiPreferences;
    private RootSessionJournal sessionJournal;
    private String pendingSessionExport;
    private TextView sessionSummary;
    private Spinner homeChoice;
    private Spinner airChoice;
    private Spinner internetDnsChoice;
    private EditText customDnsInput;
    private TextView dnsPreview;
    private Button saveDnsButton;
    private EditText homeServiceIp;
    private Button homeRouteButton;
    private Button savePairButton;
    private Button checkButton;
    private Button startButton;
    private Button stopButton;
    private Button emergencyButton;
    private Button restartButton;
    private Button resumeButton;
    private Button refreshLiveButton;
    private Button recoverButton;
    private Button firewallPreflightButton;
    private Button guardReadinessButton;
    private Button dnsRouteCheckButton;
    private Button routeAuditButton;
    private Button interfaceInspectButton;
    private TextView status;
    private TextView liveStatus;
    private TextView actionSummary;
    private TextView managementSummary;
    private TextView selectedPairSummary;
    private final LinearLayout[] pages = new LinearLayout[4];
    private final Button[] navButtons = new Button[4];
    private ScrollView scrollView;
    private boolean visible;
    private final Runnable poll = new Runnable() {
        @Override public void run() {
            if (!visible) return;
            if (dual.isManagingPair() && !dual.isBusy()) {
                dual.readStatus(message -> { if (visible) liveStatus.setText(message); });
            }
            updateManagementSummary();
            refreshButtons();
            handler.postDelayed(this, 5000L);
        }
    };

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        dual = RootDualKernelSession.get(this);
        uiPreferences = new RootLabPreferences(this);
        sessionJournal = new RootSessionJournal(this);
        sessionJournal.record("APP", "Control Center opened");
        ScrollView scroll = new ScrollView(this);
        scrollView = scroll;
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(0xff12101d);
        LinearLayout column = new LinearLayout(this);
        column.setPadding(dp(18), dp(22), dp(18), dp(24));
        column.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(column);
        setContentView(scroll);

        label(column, "WONHEE PROXY", 26, PINK);
        label(column, "Home + Internet · Dual-kernel control", 14, MUTED);
        managementSummary = label(column, "Checking local session state...", 14, WHITE);
        actionSummary = label(column, "Latest result: Tap a control to begin.  ·  View Logs", 12, MUTED);
        actionSummary.setOnClickListener(v -> showPage(3));
        actionSummary.setContentDescription("Open last diagnostic result in Logs");

        LinearLayout navigation = new LinearLayout(this);
        navigation.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams navigationLayout = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(48));
        navigationLayout.topMargin = dp(9);
        column.addView(navigation, navigationLayout);
        String[] destinations = {"Connect", "Profiles", "Privacy", "Logs"};
        for (int i = 0; i < destinations.length; i++) {
            final int pageIndex = i;
            Button tab = new Button(this);
            tab.setText(destinations[i]);
            tab.setAllCaps(false);
            tab.setTextSize(12);
            tab.setPadding(0, 0, 0, 0);
            tab.setMinWidth(0);
            tab.setMinimumWidth(0);
            LinearLayout.LayoutParams tabLayout = new LinearLayout.LayoutParams(0, dp(46), 1f);
            if (i > 0) tabLayout.leftMargin = dp(5);
            navigation.addView(tab, tabLayout);
            navButtons[i] = tab;
            tab.setOnClickListener(v -> showPage(pageIndex));
        }
        for (int i = 0; i < pages.length; i++) {
            LinearLayout page = new LinearLayout(this);
            page.setOrientation(LinearLayout.VERTICAL);
            pages[i] = page;
            column.addView(page, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT));
        }
        showPage(0);

        // Keep the primary live status above the long diagnostic tool list.
        LinearLayout livePanel = card(pages[0]);
        label(livePanel, "LIVE HOME + INTERNET STATUS", 17, PINK);
        selectedPairSummary = label(livePanel, "Pair: loading saved profiles...", 12, MUTED);
        label(livePanel, "Privacy guard OFF · DNS isolation unverified", 12, PINK);
        label(livePanel, "Individual speed, traffic total and handshake age. Refreshes "
                + "every 5 seconds while this process manages the pair.", 12, MUTED);
        liveStatus = label(livePanel, "Tap Read live status to inspect the two kernel "
                + "interfaces. If they survived an app restart, verify their identities "
                + "before resuming control.", 14, WHITE);
        refreshLiveButton = button(livePanel, "Read live status");
        refreshLiveButton.setOnClickListener(v -> {
            recordAction("Read live kernel status");
            liveStatus.setText("Reading kernel interface counters...");
            dual.inspectLiveStatus((ok, detail) -> {
                if (isFinishing()) return;
                liveStatus.setText(detail);
                if (!ok) publishResult(detail);
                else { sessionJournal.record("LIVE", detail); updateSessionSummary(); }
                refreshButtons();
            });
            refreshButtons();
        });
        resumeButton = button(livePanel, "Verify + resume existing pair");
        resumeButton.setOnClickListener(v -> confirmResume());

        LinearLayout profiles = card(pages[1]);
        label(profiles, "SELECTED CONFIGURATIONS", 17, PINK);
        label(profiles, "Import several .conf files, then choose one Home split tunnel "
                + "and one internet exit. This preview activates two at a time; "
                + "additional concurrent tunnels need route validation.", 13, MUTED);
        Button importButton = button(profiles, "Import / manage profiles");
        importButton.setOnClickListener(v -> startActivity(new Intent(this, VpnActivity.class)));
        label(profiles, "Home / ASUS profile", 16, WHITE);
        homeChoice = new Spinner(this);
        profiles.addView(homeChoice);
        label(profiles, "Internet / AirVPN profile", 16, WHITE);
        airChoice = new Spinner(this);
        profiles.addView(airChoice);
        savePairButton = button(profiles, "Save selected pair");
        savePairButton.setOnClickListener(v -> {
            int homeIndex = homeChoice.getSelectedItemPosition();
            int internetIndex = airChoice.getSelectedItemPosition();
            if (homeIndex < 0 || internetIndex < 0 || homeIndex == internetIndex
                    || homeIndex >= saved.size() || internetIndex >= saved.size()) {
                publishResult("Choose two different profiles before saving the default pair.");
                return;
            }
            try {
                uiPreferences.savePair(saved.get(homeIndex).name, saved.get(internetIndex).name);
                publishResult("Saved default Home and Internet profile selections for this device. "
                        + "No WireGuard keys or routes were changed.");
            } catch (IllegalArgumentException invalid) {
                publishResult("The two selected entries need different saved profile names.");
            }
        });

        LinearLayout privacyPolicy = card(pages[1]);
        label(privacyPolicy, "INTERNET DNS + TRACKER RESOLVER", 17, PINK);
        label(privacyPolicy, "Choose a DNS provider for the selected Internet profile. "
                + "AdGuard can perform provider-side ad/tracker filtering, but root WireGuard "
                + "does not itself configure Android VpnService DNS or enforce a leak guard.",
                12, MUTED);
        internetDnsChoice = new Spinner(this);
        ArrayAdapter<String> dnsAdapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item, VpnDnsPresets.LABELS);
        dnsAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        internetDnsChoice.setAdapter(dnsAdapter);
        privacyPolicy.addView(internetDnsChoice);
        customDnsInput = new EditText(this);
        customDnsInput.setSingleLine(true);
        customDnsInput.setInputType(InputType.TYPE_CLASS_TEXT);
        customDnsInput.setTextColor(WHITE);
        customDnsInput.setHintTextColor(MUTED);
        customDnsInput.setHint("Numeric DNS: 94.140.14.14, 94.140.15.15");
        privacyPolicy.addView(customDnsInput);
        dnsPreview = label(privacyPolicy, "Select an Internet profile and DNS policy.", 12, MUTED);
        internetDnsChoice.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View v, int pos, long id) {
                updateDnsPolicyPreview();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        airChoice.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View v, int pos, long id) {
                loadInternetDnsPolicy();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        saveDnsButton = button(privacyPolicy, "Save Internet DNS policy");
        saveDnsButton.setOnClickListener(v -> confirmSaveInternetDns());
        label(privacyPolicy, "Saving changes encrypted profile options only. Stop and "
                + "restart the kernel pair to load those options, then audit root DNS routes "
                + "and independently test Android DNS and blocking. DoH/DoQ is not enabled.",
                12, MUTED);

        LinearLayout controls = card(pages[0]);
        label(controls, "CONNECTION CONTROLS", 17, PINK);

        LinearLayout maintenance = card(pages[2]);
        label(maintenance, "RECOVERY & ROOT TOOLS", 17, PINK);
        label(maintenance, "Use these only when reconnecting fails or kernel interfaces "
                + "remain after an app restart. Recovery verifies ownership before cleanup.",
                12, MUTED);

        checkButton = button(maintenance, "Check root tools");
        checkButton.setOnClickListener(v -> {
            recordAction("Check root and kernel tools");
            status.setText("Checking root access and bundled kernel tools...");
            refreshButtons();
            dual.checkRoot((ok, detail) -> {
                if (!isFinishing()) { publishResult(detail); refreshButtons(); }
            });
        });
        startButton = button(controls, "Connect selected pair");
        startButton.setOnClickListener(v -> confirmStart());
        styleButton(startButton, 0xff805177);
        stopButton = button(controls, "Disconnect both tunnels");
        stopButton.setOnClickListener(v -> {
            recordAction("Disconnect both managed kernel tunnels");
            status.setText("Stopping both Wonhee-owned kernel interfaces...");
            dual.stopPair((ok, detail) -> {
                if (!isFinishing()) {
                    publishResult(detail);
                    if (ok) liveStatus.setText("Both managed kernel tunnels stopped.");
                    refreshButtons();
                }
            });
            refreshButtons();
        });
        emergencyButton = button(controls, "EMERGENCY DISCONNECT · verify first");
        styleButton(emergencyButton, 0xff9b4058);
        emergencyButton.setOnClickListener(v -> confirmEmergencyDisconnect());
        label(controls, "Works even after Wonhee loses the managed-session state. "
                + "Stops only interfaces whose WireGuard public identities match your selected "
                + "profiles. If a check fails, nothing unknown is removed. "
                + "This is NOT a kill switch.", 12, MUTED);
        restartButton = button(controls, "Restart managed pair");
        restartButton.setOnClickListener(v -> confirmRestart());
        recoverButton = button(maintenance, "Recover verified interfaces");
        recoverButton.setOnClickListener(v -> confirmRecovery());
        LinearLayout privacy = card(pages[2]);
        label(privacy, "PRIVACY & ROUTE AUDITS", 17, PINK);
        label(privacy, "KILL SWITCH: OFF / NOT VERIFIED. Root kernel tunnels are outside "
                + "Android VpnService and its Always-on/lockdown settings. DNS, IPv4/IPv6 "
                + "leaks, endpoint UDP exceptions and reboot behavior still need tests.",
                13, PINK);
        firewallPreflightButton = button(privacy, "Firewall capabilities · read only");
        firewallPreflightButton.setOnClickListener(v -> {
            recordAction("Read-only firewall capability check");
            status.setText("Checking root firewall tools without installing rules...");
            dual.checkFirewallCapabilities((ok, detail) -> {
                if (!isFinishing()) { publishResult(detail); refreshButtons(); }
            });
            refreshButtons();
        });
        guardReadinessButton = button(privacy, "Kill-switch readiness · read only");
        guardReadinessButton.setOnClickListener(v -> {
            recordAction("Read-only kill-switch readiness check");
            status.setText("Checking transport marks, IPv4/IPv6 rules and safe chain ownership...");
            dual.checkGuardReadiness((ok, detail) -> {
                if (!isFinishing()) { publishResult(detail); refreshButtons(); }
            });
            refreshButtons();
        });
        dnsRouteCheckButton = button(privacy, "Audit Internet DNS routes");
        dnsRouteCheckButton.setOnClickListener(v -> {
            recordAction("Audit selected Internet DNS routes");
            int selected = airChoice.getSelectedItemPosition();
            if (selected < 0 || selected >= saved.size()) {
                publishResult("Select an Internet profile before testing its DNS routes.");
                return;
            }
            status.setText("Checking configured DNS destination routes, not actual DNS traffic...");
            dual.checkInternetDnsRoutes(saved.get(selected), (ok, detail) -> {
                if (!isFinishing()) { publishResult(detail); refreshButtons(); }
            });
            refreshButtons();
        });
        routeAuditButton = button(privacy, "Audit split + public routes");
        routeAuditButton.setOnClickListener(v -> {
            recordAction("Audit split and public IPv4/IPv6 routes");
            int homeIndex = homeChoice.getSelectedItemPosition();
            int internetIndex = airChoice.getSelectedItemPosition();
            if (homeIndex < 0 || internetIndex < 0 || homeIndex == internetIndex
                    || homeIndex >= saved.size() || internetIndex >= saved.size()) {
                publishResult("Select two different saved Home and Internet profiles first.");
                return;
            }
            status.setText("Auditing root route decisions and Android active-network DNS...");
            dual.auditCurrentRoutes(saved.get(homeIndex), saved.get(internetIndex), (ok, detail) -> {
                if (!isFinishing()) { publishResult(detail); refreshButtons(); }
            });
            refreshButtons();
        });
        interfaceInspectButton = button(privacy, "Inspect kernel interfaces");
        interfaceInspectButton.setOnClickListener(v -> {
            recordAction("Inspect kernel interface identities");
            status.setText("Checking for existing kernel interfaces without changing them...");
            dual.inspectKernelInterfaces((ok, detail) -> {
                if (!isFinishing()) { publishResult(detail); refreshButtons(); }
            });
            refreshButtons();
        });
        label(privacy, "HOME SERVICE ROUTE TEST (PRIVATE IPv4)", 14, PINK);
        label(privacy, "Checks whether a private Home destination is routed through "
                + "wnhome0. It does not test whether the service's TCP port responds.",
                12, MUTED);
        homeServiceIp = new EditText(this);
        homeServiceIp.setSingleLine(true);
        homeServiceIp.setInputType(InputType.TYPE_CLASS_TEXT);
        homeServiceIp.setTextColor(WHITE);
        homeServiceIp.setHintTextColor(MUTED);
        homeServiceIp.setHint("Home address, e.g. 10.0.0.169");
        homeServiceIp.setText(uiPreferences.homeServiceIp());
        privacy.addView(homeServiceIp);
        homeRouteButton = button(privacy, "Check Home service route");
        homeRouteButton.setOnClickListener(v -> {
            String target = homeServiceIp.getText().toString();
            recordAction("Check Home service route for " + target);
            try { uiPreferences.saveHomeServiceIp(target); }
            catch (IllegalArgumentException invalid) {
                publishResult("Enter a numeric private Home IPv4 address, such as 10.0.0.169.");
                return;
            }
            status.setText("Checking route to selected Home destination...");
            dual.checkHomeServiceRoute(target, (ok, detail) -> {
                if (!isFinishing()) { publishResult(detail); refreshButtons(); }
            });
            refreshButtons();
        });
        // Put privacy status and audits before rarely used recovery tools.
        pages[2].removeView(maintenance);
        pages[2].addView(maintenance);
        LinearLayout diagnostics = card(pages[3]);
        label(diagnostics, "SESSION HISTORY & SUPPORT", 17, PINK);
        label(diagnostics, "A local, timestamped history of actions and results. It survives "
                + "app restarts, keeping up to 160 entries. Export before starting a new session.",
                12, MUTED);
        sessionSummary = label(diagnostics, sessionJournal.title(), 14, WHITE);
        Button saveSession = button(diagnostics, "Save session report (.txt)");
        saveSession.setOnClickListener(v -> saveSessionReport());
        Button printSession = button(diagnostics, "Print / Save session as PDF");
        printSession.setOnClickListener(v -> printSessionReport());
        Button newSession = button(diagnostics, "Start a new log session");
        newSession.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Start a new diagnostic session?")
                .setMessage("This clears the current session history from the app. "
                        + "Save or print the existing report first if you need it. "
                        + "Tunnel configurations and the last saved diagnostic are unchanged.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Start new session", (dialog, which) -> {
                    sessionJournal.newSession();
                    updateSessionSummary();
                }).show());
        label(diagnostics, "LAST TEST RESULT (SAVED BETWEEN APP RESTARTS)", 12, MUTED);
        String previous = uiPreferences.lastDiagnostic();
        long previousAt = uiPreferences.lastDiagnosticTime();
        String restored = previous.isEmpty() ? "Ready for root preflight. Nothing has been started."
                : "Previous result (" + DateFormat.getDateTimeInstance().format(new Date(previousAt))
                    + "):\n" + previous;
        status = label(diagnostics, restored, 14, WHITE);
        Button copyResult = button(diagnostics, "Copy last result");
        copyResult.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard != null) {
                clipboard.setPrimaryClip(ClipData.newPlainText(
                        "Wonhee root diagnostic", status.getText()));
            }
        });
        Button copySnapshot = button(diagnostics, "Copy support snapshot");
        copySnapshot.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard == null) return;
            int homeIndex = homeChoice.getSelectedItemPosition();
            int internetIndex = airChoice.getSelectedItemPosition();
            String homeName = homeIndex >= 0 && homeIndex < saved.size()
                    ? saved.get(homeIndex).name : "none";
            String internetName = internetIndex >= 0 && internetIndex < saved.size()
                    ? saved.get(internetIndex).name : "none";
            String snapshot = "Wonhee root support snapshot\nHome profile: " + homeName
                    + "\nInternet profile: " + internetName
                    + "\n\nLive kernel status:\n" + liveStatus.getText()
                    + "\n\nLast diagnostic:\n" + status.getText();
            clipboard.setPrimaryClip(ClipData.newPlainText("Wonhee root support snapshot", snapshot));
        });
        Button forgetResult = button(diagnostics, "Clear saved diagnostic");
        forgetResult.setOnClickListener(v -> {
            recordAction("Clear last saved diagnostic (session history remains)");
            uiPreferences.clearDiagnostic();
            status.setText("Saved diagnostic cleared. No tunnel configuration changed.");
        });
        label(diagnostics, "The live pair dashboard is at the top of this screen. "
                + "A long handshake age can mean an idle tunnel; it is not "
                + "proof that the connection has failed. Counters are not whole-device "
                + "traffic or a DNS/leak audit.", 12, MUTED);
        label(diagnostics, "Copying a result places it on Android's clipboard; "
                + "other apps may read it. Review its contents before copying or sharing.",
                12, MUTED);
        label(diagnostics, "Session reports redact known secret fields but can still contain "
                + "profile names, peer endpoints and private IP addresses. Review before sharing.",
                12, MUTED);
        label(pages[3], "Test from cellular: check that 10.0.0.169:4533 opens, "
                + "that public IPv4/IPv6 egress is AirVPN Europe, and that DNS resolves. "
                + "Check both fresh handshakes, then disconnect both. "
                + "If the app crashes, a kernel interface may remain: inspect the phone "
                + "with adb shell su -c 'ip -d link show type wireguard'.", 13, MUTED);

        reload();
        loadInternetDnsPolicy();
        updateSelectedPairSummary();
        updateActionSummary(uiPreferences.lastDiagnostic());
        updateManagementSummary();
        refreshButtons();
    }

    private void showPage(int chosen) {
        for (int i = 0; i < pages.length; i++) {
            if (pages[i] != null) pages[i].setVisibility(i == chosen ? View.VISIBLE : View.GONE);
            if (navButtons[i] != null) {
                GradientDrawable background = new GradientDrawable();
                background.setColor(i == chosen ? NAV_ACTIVE : NAV_IDLE);
                background.setCornerRadius(dp(12));
                navButtons[i].setBackground(background);
                navButtons[i].setTextColor(i == chosen ? PINK : MUTED);
                navButtons[i].setSelected(i == chosen);
            }
        }
        updateSelectedPairSummary();
        if (scrollView != null) scrollView.post(() -> scrollView.smoothScrollTo(0, 0));
    }

    private void updateSelectedPairSummary() {
        if (selectedPairSummary == null || homeChoice == null || airChoice == null) return;
        int homeIndex = homeChoice.getSelectedItemPosition();
        int internetIndex = airChoice.getSelectedItemPosition();
        String homeName = homeIndex >= 0 && homeIndex < saved.size()
                ? saved.get(homeIndex).name : "none";
        String internetName = internetIndex >= 0 && internetIndex < saved.size()
                ? saved.get(internetIndex).name : "none";
        selectedPairSummary.setText("Home: " + homeName + "  ·  Internet: " + internetName);
    }

    private void updateManagementSummary() {
        if (managementSummary == null || dual == null) return;
        managementSummary.setText(dual.isBusy() ? "● Kernel operation in progress"
                : dual.isManagingPair() ? "● Managing Home + Internet · check live health below"
                : "○ App control detached · inspect links or use Emergency Disconnect");
    }

    private void updateActionSummary(String result) {
        if (actionSummary == null) return;
        String line = result == null ? "" : result.trim();
        int newline = line.indexOf('\n');
        if (newline >= 0) line = line.substring(0, newline);
        if (line.length() > 92) line = line.substring(0, 89) + "…";
        actionSummary.setText((line.isEmpty() ? "No completed diagnostics yet" : line)
                + "  ·  View Logs");
    }

    private void reload() {
        saved.clear();
        try { saved.addAll(new SecureTunnelProfileStore(this).load()); }
        catch (Exception ignored) { publishResult("Could not decrypt saved profiles on this device."); }
        List<String> names = new ArrayList<>();
        for (SecureTunnelProfileStore.Profile p : saved) names.add(p.name);
        ArrayAdapter<String> homeAdapter = new ArrayAdapter<>(
                this, android.R.layout.simple_spinner_item, names) {
            @Override public View getView(int position, View convertView, ViewGroup parent) {
                TextView text = (TextView) super.getView(position, convertView, parent);
                text.setTextColor(WHITE);
                return text;
            }
        };
        homeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        ArrayAdapter<String> airAdapter = new ArrayAdapter<>(
                this, android.R.layout.simple_spinner_item, new ArrayList<>(names)) {
            @Override public View getView(int position, View convertView, ViewGroup parent) {
                TextView text = (TextView) super.getView(position, convertView, parent);
                text.setTextColor(WHITE);
                return text;
            }
        };
        airAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        homeChoice.setAdapter(homeAdapter);
        airChoice.setAdapter(airAdapter);
        int chosenHome = -1;
        int chosenInternet = -1;
        String preferredHome = uiPreferences.homeName();
        String preferredInternet = uiPreferences.internetName();
        for (int i = 0; i < saved.size(); ++i) {
            if (saved.get(i).name.equals(preferredHome)) chosenHome = i;
            if (saved.get(i).name.equals(preferredInternet)) chosenInternet = i;
        }
        for (int i = 0; i < saved.size(); ++i) {
            if (chosenHome < 0 && saved.get(i).role == SecureTunnelProfileStore.Profile.ROLE_HOME)
                chosenHome = i;
            if (chosenInternet < 0
                    && saved.get(i).role == SecureTunnelProfileStore.Profile.ROLE_INTERNET)
                chosenInternet = i;
        }
        for (int i = 0; i < saved.size(); ++i) {
            String name = saved.get(i).name.toLowerCase(java.util.Locale.ROOT);
            if (chosenHome < 0 && (name.contains("home") || name.contains("pixel")
                    || name.contains("asus") || name.contains("wgs_client"))) chosenHome = i;
            if (chosenInternet < 0 && (name.contains("air") || name.contains("europe")))
                chosenInternet = i;
        }
        if (chosenHome >= 0) homeChoice.setSelection(chosenHome);
        if (chosenInternet >= 0) airChoice.setSelection(chosenInternet);
        updateSelectedPairSummary();
    }

    private void loadInternetDnsPolicy() {
        if (internetDnsChoice == null) return;
        int index = airChoice.getSelectedItemPosition();
        if (index < 0 || index >= saved.size()) {
            dnsPreview.setText("Choose an Internet profile first.");
            return;
        }
        SecureTunnelProfileStore.Profile profile = saved.get(index);
        int choice = VpnDnsPresets.choiceForSaved(
                profile.homeDnsEnabled, profile.homeDnsServer);
        customDnsInput.setText(choice == VpnDnsPresets.CUSTOM ? profile.homeDnsServer : "");
        internetDnsChoice.setSelection(choice);
        updateDnsPolicyPreview();
    }

    private void updateDnsPolicyPreview() {
        if (dnsPreview == null) return;
        int choice = internetDnsChoice.getSelectedItemPosition();
        customDnsInput.setVisibility(choice == VpnDnsPresets.CUSTOM ? View.VISIBLE : View.GONE);
        if (choice == VpnDnsPresets.ADGUARD) {
            dnsPreview.setText("Provider-side ad/tracker DNS filtering selected (AdGuard). "
                    + "Not yet saved or verified; this does not block hardcoded or encrypted "
                    + "app DNS, nor prove that Android uses this resolver.");
        } else if (choice == VpnDnsPresets.QUAD9) {
            dnsPreview.setText("Quad9 malware-focused DNS selected. It is not an ad/tracker "
                    + "blocklist, and Android DNS routing has not been verified.");
        } else if (choice == VpnDnsPresets.IMPORTED) {
            dnsPreview.setText("Using DNS from the imported profile. Resolver filtering "
                    + "policy and Android DNS routing are not verified.");
        } else {
            dnsPreview.setText("DNS override selected for the next tunnel start only. "
                    + "No in-app encrypted DNS or tracker blocking is installed.");
        }
    }

    private void confirmSaveInternetDns() {
        if (dual.isBusy() || dual.isManagingPair()) {
            publishResult("Stop the managed kernel pair before changing its DNS profile.");
            return;
        }
        int index = airChoice.getSelectedItemPosition();
        if (index < 0 || index >= saved.size()) {
            publishResult("Choose an Internet profile before saving a DNS policy.");
            return;
        }
        SecureTunnelProfileStore.Profile selected = saved.get(index);
        int preset = internetDnsChoice.getSelectedItemPosition();
        String custom = customDnsInput.getText().toString();
        new AlertDialog.Builder(this)
                .setTitle("Save Internet DNS provider for next start?")
                .setMessage("The selected DNS policy will be saved with this encrypted "
                        + "WireGuard profile. Imported keys and .conf text stay unchanged. "
                        + "Provider-side blocking works only when Android actually sends DNS "
                        + "queries to that resolver; kernel WireGuard alone does not enforce "
                        + "it, and no kill switch is installed. Continue?")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Save policy", (dialog, which) -> {
                    recordAction("Save Internet DNS policy for " + selected.name);
                    status.setText("Validating DNS reachability through the Internet AllowedIPs...");
                    dual.saveInternetDnsPolicy(selected, preset, custom, (ok, detail) -> {
                        if (isFinishing()) return;
                        publishResult(detail);
                        if (ok) {
                            String chosenName = selected.name;
                            reload();
                            for (int i = 0; i < saved.size(); i++) {
                                if (saved.get(i).name.equals(chosenName)) {
                                    airChoice.setSelection(i);
                                    break;
                                }
                            }
                            loadInternetDnsPolicy();
                        }
                        refreshButtons();
                    });
                    refreshButtons();
                }).show();
    }

    private void confirmStart() {
        if (dual.isBusy() || dual.isManagingPair() || saved.size() < 2) return;
        if (!WgQuickBackend.hasKernelSupport()) {
            publishResult("No kernel WireGuard module available on this device.");
            return;
        }
        if (WireGuardSession.get(this).isConnected()) {
            publishResult("Disconnect the normal Wonhee VPN before starting rooted tunnels.");
            return;
        }
        int home = homeChoice.getSelectedItemPosition();
        int air = airChoice.getSelectedItemPosition();
        if (home < 0 || air < 0 || home >= saved.size() || air >= saved.size() || home == air) {
            publishResult("Choose two different saved WireGuard profiles.");
            return;
        }
        SecureTunnelProfileStore.Profile homeProfile = saved.get(home);
        SecureTunnelProfileStore.Profile airProfile = saved.get(air);
        new AlertDialog.Builder(this)
                .setTitle("Start two rooted kernel tunnels?")
                .setMessage("This runs two independent WireGuard profiles through kernel "
                        + "interfaces named wnhome0 and wnair0. Stop Android Always-on/lockdown "
                        + "first. Home MUST be split-routed; AirVPN MUST include IPv4 and IPv6 "
                        + "defaults. Your connection may drop. Root permission will be requested. "
                        + "This is an experimental connectivity test, not a verified kill switch.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Start test", (dialog, which) -> {
                    recordAction("Connect Home " + homeProfile.name + " + Internet "
                            + airProfile.name);
                    status.setText("Starting Home, then AirVPN Europe...");
                    dual.startPair(homeProfile, airProfile, (ok, detail) -> {
                        if (!isFinishing()) { publishResult(detail); refreshButtons(); }
                    });
                    refreshButtons();
                }).show();
    }

    /**
     * Emergency UI always remains reachable. Stop in-process owned interfaces,
     * or perform the existing identity-checked orphan cleanup after app restart.
     * Never blindly delete interfaces or Android-owned policy rules.
     */
    private void confirmEmergencyDisconnect() {
        if (dual.isBusy()) {
            publishResult("Emergency stop is waiting for a root operation to finish. "
                    + "Try again in a moment; if unresponsive, use USB ADB to remove "
                    + "wnhome0 and wnair0. No kill switch is active.");
            return;
        }
        int homeIndex = homeChoice.getSelectedItemPosition();
        int internetIndex = airChoice.getSelectedItemPosition();
        if (homeIndex < 0 || internetIndex < 0 || homeIndex == internetIndex
                || homeIndex >= saved.size() || internetIndex >= saved.size()) {
            publishResult("Emergency stop requires the correct saved Home and Internet "
                    + "profiles to verify kernel identities. No interfaces were changed. "
                    + "Use USB ADB if the profiles are unavailable.");
            return;
        }
        SecureTunnelProfileStore.Profile selectedHome = saved.get(homeIndex);
        SecureTunnelProfileStore.Profile selectedInternet = saved.get(internetIndex);
        new AlertDialog.Builder(this)
                .setTitle("Emergency disconnect Wonhee tunnels?")
                .setMessage("Wonhee will verify each present interface's WireGuard public "
                        + "identity against the saved profiles before stopping it. "
                        + "Unknown interfaces will not be deleted. This is NOT a fail-closed "
                        + "kill switch: your real Wi-Fi/cellular IP may be exposed afterward. "
                        + "Enable Airplane mode first if you need to block ordinary traffic.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Disconnect now", (dialog, which) -> {
                    recordAction("Emergency disconnect requested for " + selectedHome.name
                            + " and " + selectedInternet.name);
                    status.setText("Verifying interface identities before emergency disconnect...");
                    RootDualKernelSession.Callback completed = (ok, detail) -> {
                        if (isFinishing()) return;
                        // Independently inspect kernel state even when teardown failed.
                        dual.inspectKernelInterfaces((inspected, inspection) -> {
                            if (isFinishing()) return;
                            publishResult((ok ? "EMERGENCY DISCONNECT FINISHED" :
                                    "EMERGENCY DISCONNECT NOT CONFIRMED")
                                    + "\n" + detail + "\n" + inspection
                                    + "\nNo fail-closed firewall is installed. "
                                    + "Do not assume DNS or IPv6 privacy.");
                            liveStatus.setText(inspection);
                            refreshButtons();
                        });
                        refreshButtons();
                    };
                    if (dual.isManagingPair()) dual.stopPair(completed);
                    else dual.recoverMatchingPair(selectedHome, selectedInternet, completed);
                    refreshButtons();
                }).show();
    }

    private void confirmRecovery() {
        if (dual.isBusy() || dual.isManagingPair()) return;
        int homeIndex = homeChoice.getSelectedItemPosition();
        int internetIndex = airChoice.getSelectedItemPosition();
        if (homeIndex < 0 || internetIndex < 0 || homeIndex == internetIndex
                || homeIndex >= saved.size() || internetIndex >= saved.size()) {
            publishResult("Select two distinct saved profiles before recovery.");
            return;
        }
        SecureTunnelProfileStore.Profile selectedHome = saved.get(homeIndex);
        SecureTunnelProfileStore.Profile selectedAir = saved.get(internetIndex);
        new AlertDialog.Builder(this)
                .setTitle("Stop matching orphaned interfaces?")
                .setMessage("Recovery can disconnect your home and internet tunnels. "
                        + "Wonhee will verify the interface AND peer public keys against "
                        + "your selected saved profiles before stopping either interface. "
                        + "Unknown interfaces will not be changed. There is no verified "
                        + "kill switch, so ordinary traffic may use cellular afterward. "
                        + "Start the tunnels again manually after recovery.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Verify and stop", (dialog, which) -> {
                    recordAction("Recover verified, matching kernel interfaces");
                    status.setText("Checking old kernel identities before any cleanup...");
                    dual.recoverMatchingPair(selectedHome, selectedAir, (ok, detail) -> {
                        if (!isFinishing()) { publishResult(detail); refreshButtons(); }
                    });
                    refreshButtons();
                }).show();
    }

    /** User-initiated recovery only. Never silently bring up old kernel routes. */
    private void confirmRestart() {
        if (dual.isBusy() || !dual.isManagingPair()) return;
        int homeIndex = homeChoice.getSelectedItemPosition();
        int internetIndex = airChoice.getSelectedItemPosition();
        if (homeIndex < 0 || internetIndex < 0 || homeIndex == internetIndex
                || homeIndex >= saved.size() || internetIndex >= saved.size()) {
            publishResult("Select two different stored profiles to restart the active pair.");
            return;
        }
        SecureTunnelProfileStore.Profile selectedHome = saved.get(homeIndex);
        SecureTunnelProfileStore.Profile selectedInternet = saved.get(internetIndex);
        new AlertDialog.Builder(this)
                .setTitle("Manually restart both kernel tunnels?")
                .setMessage("Wonhee will first stop the currently managed pair, then "
                        + "start the selected Home and Internet profiles only if BOTH "
                        + "interfaces stopped. Internet and Navidrome access may be interrupted. "
                        + "If the restart fails, ordinary cellular traffic may resume: "
                        + "NO kernel kill switch is installed. Automatic recovery is OFF.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Restart pair", (dialog, which) -> {
                    recordAction("Restart Home " + selectedHome.name + " + Internet "
                            + selectedInternet.name);
                    status.setText("Stopping both managed tunnels before manual restart...");
                    dual.stopPair((stopped, stopDetail) -> {
                        if (isFinishing()) return;
                        if (!stopped) {
                            publishResult("Restart aborted: " + stopDetail
                                    + " No new tunnel start was attempted.");
                            refreshButtons();
                            return;
                        }
                        status.setText("Old pair stopped; starting selected pair...");
                        dual.startPair(selectedHome, selectedInternet, (started, startDetail) -> {
                            if (isFinishing()) return;
                            publishResult((started ? "Manual restart completed. "
                                    : "Manual restart failed after stopping old pair. ")
                                    + startDetail);
                            liveStatus.setText(started ? "Pair restarted. Measuring fresh "
                                    + "traffic and handshakes..." : "Pair restart failed. "
                                    + "Read live status to inspect remaining interfaces.");
                            refreshButtons();
                        });
                        refreshButtons();
                    });
                    refreshButtons();
                }).show();
    }

    private void confirmResume() {
        if (dual.isBusy() || dual.isManagingPair()) return;
        int homeIndex = homeChoice.getSelectedItemPosition();
        int internetIndex = airChoice.getSelectedItemPosition();
        if (homeIndex < 0 || internetIndex < 0 || homeIndex == internetIndex
                || homeIndex >= saved.size() || internetIndex >= saved.size()) {
            publishResult("Select different Home and Internet profiles first.");
            return;
        }
        SecureTunnelProfileStore.Profile selectedHome = saved.get(homeIndex);
        SecureTunnelProfileStore.Profile selectedInternet = saved.get(internetIndex);
        new AlertDialog.Builder(this)
                .setTitle("Resume control of existing kernel tunnels?")
                .setMessage("If both interfaces survived an app restart, Wonhee will "
                        + "verify their WireGuard public identities, peers, and Home/Internet "
                        + "routes against the profiles you selected. Nothing is modified "
                        + "by this verification. If every check passes, the app can "
                        + "monitor and manually restart that existing pair.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Verify and resume", (dialog, which) -> {
                    recordAction("Verify and resume existing kernel pair");
                    status.setText("Verifying existing kernel identities and routes...");
                    dual.verifyAndResumePair(selectedHome, selectedInternet, (ok, detail) -> {
                        if (isFinishing()) return;
                        publishResult(detail);
                        liveStatus.setText(ok ? "Verified active pair. Measuring live "
                                + "traffic now..." : "Unable to resume; "
                                + "tap Read live status for a read-only snapshot.");
                        refreshButtons();
                    });
                    refreshButtons();
                }).show();
    }

    private void refreshButtons() {
        if (startButton == null) return;
        boolean busy = dual.isBusy();
        boolean managing = dual.isManagingPair();
        updateManagementSummary();
        updateSelectedPairSummary();
        savePairButton.setEnabled(!busy && !managing && saved.size() >= 2);
        checkButton.setEnabled(!busy && !managing);
        startButton.setEnabled(!busy && !managing && saved.size() >= 2);
        stopButton.setEnabled(!busy && managing);
        emergencyButton.setEnabled(true); // Never hide emergency recovery due to lost session ownership.
        restartButton.setEnabled(!busy && managing && saved.size() >= 2);
        resumeButton.setEnabled(!busy && !managing && saved.size() >= 2);
        refreshLiveButton.setEnabled(!busy);
        recoverButton.setEnabled(!busy && !managing && saved.size() >= 2);
        firewallPreflightButton.setEnabled(!busy);
        guardReadinessButton.setEnabled(!busy);
        dnsRouteCheckButton.setEnabled(!busy && !saved.isEmpty());
        routeAuditButton.setEnabled(!busy && saved.size() >= 2);
        interfaceInspectButton.setEnabled(!busy);
        saveDnsButton.setEnabled(!busy && !managing && !saved.isEmpty());
        internetDnsChoice.setEnabled(!busy && !managing);
        customDnsInput.setEnabled(!busy && !managing);
        homeRouteButton.setEnabled(!busy);
        homeServiceIp.setEnabled(!busy);
        homeChoice.setEnabled(!busy && !managing);
        airChoice.setEnabled(!busy && !managing);
    }

    @Override protected void onResume() {
        super.onResume();
        if (status != null && !dual.isManagingPair()) {
            reload();
            loadInternetDnsPolicy();
        }
        visible = true;
        // Refresh real kernel state on reopening, even if this process lost ownership.
        // Read-only: do not automatically adopt, start, or stop any interfaces.
        if (!dual.isManagingPair() && !dual.isBusy()) {
            dual.inspectKernelInterfaces((ok, detail) -> {
                if (!visible || isFinishing()) return;
                liveStatus.setText("Kernel state after reopening (read only):\n" + detail);
                sessionJournal.record("KERNEL", detail);
                updateSessionSummary();
                refreshButtons();
            });
        }
        handler.removeCallbacks(poll);
        handler.post(poll);
    }

    @Override protected void onPause() {
        visible = false;
        handler.removeCallbacks(poll);
        super.onPause();
    }

    private void publishResult(String result) {
        status.setText(result);
        uiPreferences.saveDiagnostic(result);
        updateActionSummary(result);
        if (sessionJournal != null) {
            sessionJournal.record("RESULT", result);
            updateSessionSummary();
        }
    }

    private void recordAction(String action) {
        sessionJournal.record("ACTION", action);
        updateSessionSummary();
    }

    private void updateSessionSummary() {
        if (sessionSummary != null) sessionSummary.setText(sessionJournal.title());
    }

    private String buildSessionReport() {
        int homeIndex = homeChoice.getSelectedItemPosition();
        int internetIndex = airChoice.getSelectedItemPosition();
        String home = homeIndex >= 0 && homeIndex < saved.size()
                ? saved.get(homeIndex).name : "none";
        String internet = internetIndex >= 0 && internetIndex < saved.size()
                ? saved.get(internetIndex).name : "none";
        return sessionJournal.report(home, internet, liveStatus.getText().toString(),
                status.getText().toString());
    }

    private void saveSessionReport() {
        recordAction("Save local session report as text");
        pendingSessionExport = buildSessionReport();
        Intent save = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        save.addCategory(Intent.CATEGORY_OPENABLE);
        save.setType("text/plain");
        save.putExtra(Intent.EXTRA_TITLE, "wonhee-session-" + sessionJournal.id() + ".txt");
        try {
            startActivityForResult(save, REQUEST_SAVE_SESSION_REPORT);
        } catch (RuntimeException error) {
            pendingSessionExport = null;
            publishResult("No system document picker available for session export.");
        }
    }

    private void printSessionReport() {
        recordAction("Open Android Print for session report");
        PrintManager printManager = (PrintManager) getSystemService(Context.PRINT_SERVICE);
        if (printManager == null) {
            publishResult("Android printing is not available on this device.");
            return;
        }
        try {
            printManager.print("Wonhee session " + sessionJournal.id(),
                    new RootSessionPrintAdapter(this, "wonhee-session-" + sessionJournal.id(),
                            buildSessionReport()), null);
        } catch (RuntimeException error) {
            publishResult("Could not open Android Print. Use Save session report instead.");
        }
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_SAVE_SESSION_REPORT) return;
        String report = pendingSessionExport;
        pendingSessionExport = null;
        if (resultCode != RESULT_OK || data == null || data.getData() == null
                || report == null) return;
        Uri destination = data.getData();
        try (OutputStream stream = getContentResolver().openOutputStream(destination, "w")) {
            if (stream == null) throw new IOException("Document provider returned no stream");
            stream.write(report.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            stream.flush();
            sessionJournal.record("EXPORT", "Session text report saved to selected document");
            updateSessionSummary();
        } catch (IOException | SecurityException error) {
            publishResult("Could not save the session report. Try another document location.");
        }
    }

    private TextView label(LinearLayout parent, String value, int sp, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sp);
        view.setTextColor(color);
        view.setPadding(0, dp(7), 0, dp(7));
        parent.addView(view);
        return view;
    }

    private Button button(LinearLayout parent, String text) {
        Button result = new Button(this);
        result.setText(text);
        result.setTextColor(WHITE);
        result.setAllCaps(false);
        result.setTextSize(14);
        styleButton(result, 0xff483250);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(48));
        params.topMargin = dp(6);
        parent.addView(result, params);
        return result;
    }

    private void styleButton(Button button, int color) {
        GradientDrawable background = new GradientDrawable();
        background.setColor(color);
        background.setCornerRadius(dp(14));
        button.setBackground(background);
    }

    private LinearLayout card(LinearLayout parent) {
        LinearLayout result = new LinearLayout(this);
        result.setOrientation(LinearLayout.VERTICAL);
        result.setPadding(dp(16), dp(12), dp(16), dp(16));
        GradientDrawable background = new GradientDrawable();
        background.setColor(PANEL);
        background.setCornerRadius(dp(18));
        result.setBackground(background);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.topMargin = dp(10);
        parent.addView(result, params);
        return result;
    }

    private int dp(float value) { return (int) (getResources().getDisplayMetrics().density * value); }
}
