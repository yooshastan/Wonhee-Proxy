package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.WindowInsets;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Small opt-in UI for generalizing root tunnel controls without regressing the pair. */
public final class RootMultiKernelActivity extends Activity {
    private static final int BACKGROUND = 0xff12101d;
    private static final int PANEL = 0xff242033;
    private static final int PINK = 0xfffbadd8;
    private static final int WHITE = 0xfff8f1f9;
    private static final int MUTED = 0xffc4b7c9;

    private SecureTunnelProfileStore store;
    private RootMultiKernelSession session;
    private RootSessionJournal journal;
    private final List<SecureTunnelProfileStore.Profile> saved = new ArrayList<>();
    private final Map<String, CheckBox> selection = new LinkedHashMap<>();
    private LinearLayout profileRows;
    private TextView output;
    private Button connect;
    private Button disconnect;
    private Button preview;
    private Button inspect;
    private Button audit;
    private Button apply;
    private Button remove;
    private Button recover;
    private Button guardReadiness;
    private Button dnsAudit;
    private Button transportAudit;
    private Button serviceProbe;
    private Button packetObserve;
    private Button guardModel;
    private Button enableRecovery;
    private Button disableRecovery;
    private Button checkRecovery;
    private Button dohProbe;
    private Button rootDohProbe;
    private Button dnsEnable;
    private Button dnsDisable;
    private Button dnsEnforcementAudit;
    private Button failClosedEnable;
    private Button failClosedAudit;
    private Button failClosedDisable;
    private Button failClosedGuidedTest;
    private Button failClosedUnderlayChallenge;
    private TextView failClosedStatus;
    private TextView dnsEnforcementStatus;
    private TextView trackerStatus;
    private CheckBox trackerFilter;
    private EditText trackerCustom;
    private EditText trackerAllow;
    private SharedPreferences trackerPrefs;
    private Button guidedAudit;
    private Button guidedDetails;
    private Button advancedToggle;
    private TextView guidedStatus;
    private LinearLayout advancedGroup;
    private boolean guidedRunning;
    private final List<RootSafetyGuide.Finding> guidedFindings = new ArrayList<>();
    private TextView recoveryStatus;
    private EditText serviceTarget;
    private EditText dohUrl;
    private EditText dohBootstrap;
    private Spinner dohTunnel;
    private Spinner dnsProtocol;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        store = new SecureTunnelProfileStore(this);
        session = RootMultiKernelSession.get(this);
        trackerPrefs = getSharedPreferences("wonhee_local_tracker_options", Context.MODE_PRIVATE);
        journal = new RootSessionJournal(this);
        journal.record("APP", "Experimental multi-tunnel manager opened");

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(BACKGROUND);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(18), dp(20), dp(18), dp(80));
        scroll.addView(page);
        scroll.setOnApplyWindowInsetsListener((v, insets) -> {
            int nav = Build.VERSION.SDK_INT >= 30
                    ? insets.getInsets(WindowInsets.Type.navigationBars()).bottom
                    : insets.getSystemWindowInsetBottom();
            page.setPadding(dp(18), dp(20), dp(18), dp(24) + Math.max(dp(56), nav));
            return insets;
        });
        setContentView(scroll);
        scroll.requestApplyInsets();

        label(page, "MULTI-TUNNEL LAB", 25, PINK);
        label(page, "Product Batch F · opt-in experimental root fail-closed guard", 14, WHITE);
        label(page, "EXPERIMENTAL: this multi-profile lab is separate from the older "
                + "wnhome0/wnair0 pair. Stop that legacy pair first. Root changes "
                + "may interrupt Internet access. Keep Termux root or USB recovery ready. "
                + "DNS interception, tracker filtering and Batch F's root OUTPUT guard "
                + "each require separate explicit opt-in. The kill switch is OFF by default; "
                + "it has no reboot-time guarantee. Routing changes require separate consent.", 13, PINK);

        LinearLayout configs = card(page);
        label(configs, "SELECT ACTIVE PROFILES", 18, PINK);
        label(configs, "Select any combination of saved profiles. A default Internet "
                + "route can coexist with distinct split destinations, but overlapping "
                + "split routes or two defaults are refused. Up to eight profiles "
                + "are supported by the current encrypted store.", 13, MUTED);
        profileRows = new LinearLayout(this);
        profileRows.setOrientation(LinearLayout.VERTICAL);
        configs.addView(profileRows);
        Button manage = button(configs, "Import / edit encrypted profiles");
        manage.setOnClickListener(v -> startActivity(new Intent(this, VpnActivity.class)));
        preview = button(configs, "Preview selected routes · read only");
        preview.setOnClickListener(v -> run("Preview routes", false, session::preview));

        LinearLayout controls = card(page);
        label(controls, "CONNECTION CONTROLS", 18, PINK);
        connect = button(controls, "Connect selected tunnels");
        connect.setOnClickListener(v -> confirm(true));
        disconnect = button(controls, "Disconnect selected tunnels");
        disconnect.setOnClickListener(v -> confirm(false));
        label(controls, "Disconnect checks the WireGuard public identities of all "
                + "selected interfaces before changing any, including after an app "
                + "restart. Unknown interfaces are never removed.", 13, MUTED);
        inspect = button(controls, "Read live kernel status");
        inspect.setOnClickListener(v -> run("Read multi-tunnel state", true, session::inspect));

        LinearLayout guided = card(page);
        label(guided, "SECURITY ASSISTANT · GUIDED CHECK", 18, PINK);
        label(guided, "Choose your tunnel profiles, then run five automatic READ-ONLY "
                + "checks: tunnel identity, split routes, DNS destinations, endpoint/Android "
                + "DNS status and guard readiness. Wonhee explains any issue and suggests "
                + "the next safe action. It never changes a route, DNS setting or firewall "
                + "rule without separate consent.", 13, MUTED);
        guidedStatus = label(guided, RootSafetyGuide.summary(guidedFindings)
                + "\nKILL SWITCH: " + session.guardLedgerStatus()
                + " · DNS POLICY LEDGER: " + session.dnsLedgerStatus(), 14, WHITE);
        guidedAudit = button(guided, "Run guided safety check · read only");
        guidedAudit.setOnClickListener(v -> startGuidedAudit());
        guidedDetails = button(guided, "Review safety check details");
        guidedDetails.setOnClickListener(v -> showGuidedDetails());
        advancedToggle = button(guided, "Show advanced security controls");
        advancedToggle.setOnClickListener(v -> {
            boolean reveal = advancedGroup.getVisibility() != View.VISIBLE;
            advancedGroup.setVisibility(reveal ? View.VISIBLE : View.GONE);
            advancedToggle.setText(reveal ? "Hide advanced security controls"
                    : "Show advanced security controls");
        });
        label(guided, "Advanced controls contain recovery, routing rules, DNS probes and "
                + "network diagnostics. They remain available, but are hidden until needed. "
                + "The guided audit never enables the experimental kill switch or guarantees leak-free traffic.", 13, PINK);

        advancedGroup = new LinearLayout(this);
        advancedGroup.setOrientation(LinearLayout.VERTICAL);
        advancedGroup.setVisibility(View.GONE);
        page.addView(advancedGroup);

        LinearLayout recoveryCard = card(advancedGroup);
        label(recoveryCard, "PRODUCT BATCH C · CONNECTION RECOVERY", 18, PINK);
        label(recoveryCard, "Disabled by default. Enroll ONLY an exact selection of "
                + "already connected, identity-verified kernel tunnels. At network handoff "
                + "or after app/process restart, Wonhee may adopt surviving matching "
                + "links and restore missing ones. Android may delay background jobs. "
                + "Changed profiles, unknown interfaces or changed owned routing rules "
                + "block recovery. This does not guarantee a working handshake, DNS, "
                + "leak prevention or fail-closed behavior.", 13, MUTED);
        recoveryStatus = label(recoveryCard, session.recoveryStatus(), 14, PINK);
        enableRecovery = button(recoveryCard, "Enable recovery for selected UP tunnels · opt in");
        enableRecovery.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Enable unattended multi-tunnel recovery?")
                .setMessage("Only the exact selected, currently UP tunnels will be enrolled. "
                        + "On a later handoff, process restart or deferred background job, "
                        + "Wonhee may restart a missing tunnel using its encrypted saved profile. "
                        + "It verifies both public WireGuard keys and the owned route ledger "
                        + "before acting. A manual disconnect or Disable stops future recovery. "
                        + "NO kill switch is installed: unprotected traffic can occur when "
                        + "tunnels are down. Keep Termux/root or USB recovery access ready.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Enable opt-in recovery", (dialog, which) ->
                        run("Enable Product C recovery", false,
                                session::enableAutomaticRecovery))
                .show());
        checkRecovery = button(recoveryCard, "Check / recover missing selected links now");
        checkRecovery.setOnClickListener(v -> run("Run opted-in recovery", true,
                (profiles, cb) -> session.recoverSavedIfDesired(cb)));
        disableRecovery = button(recoveryCard, "Disable automatic recovery · keep tunnels UP");
        disableRecovery.setOnClickListener(v -> session.disableAutomaticRecovery((ok, result) -> {
            if (isFinishing() || isDestroyed()) return;
            output.setText((ok ? "COMPLETE\n" : "CHECK REQUIRED\n") + result);
            journal.record("RESULT", "Product C recovery disable requested");
            updateButtons();
        }));
        label(recoveryCard, "Manual Disconnect overrides recovery intent even when "
                + "routing ownership prevents safely stopping the interfaces. "
                + "No routes, firewall or DNS settings are installed by recovery.", 13, PINK);

        LinearLayout routing = card(advancedGroup);
        label(routing, "EXPERIMENTAL ROUTING OVERRIDES", 18, PINK);
        label(routing, "Batch B addresses the observed Home split route choosing the "
                + "AirVPN default. Inspect the read-only audit first. The optional fix "
                + "adds narrowly scoped Wonhee-owned rules ahead of Android's default "
                + "selection, records a persistent rollback ledger, and verifies root "
                + "route lookups. It is NOT a leak test or kill switch.", 13, MUTED);
        audit = button(routing, "Audit effective routes · read only");
        audit.setOnClickListener(v -> run("Audit UID-0 routes", false, session::auditRouting));
        apply = button(routing, "Apply split-route correction · experimental");
        apply.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Install owned routing priority rules?")
                .setMessage("Only selected, identity-verified running tunnels can be used. "
                        + "Wonhee will refuse policy-rule collisions and unsafe WireGuard "
                        + "endpoint marks, save a rollback ledger, then check root routes. "
                        + "This changes device routing and may interrupt connectivity. "
                        + "Keep USB ADB recovery ready. No kill switch is installed.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Apply rules", (dialog, which) ->
                        run("Install split route priority", false, session::applyRouting))
                .show());
        recover = button(routing, "Verify + recover matching routing rules");
        recover.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Recover exact matching routing rules?")
                .setMessage("Use only if the audit says rollback ledger EMPTY but "
                        + "priority-12500+ rules exist. Wonhee checks the selected "
                        + "encrypted profiles, live WireGuard identities and every "
                        + "reserved kernel rule before restoring the rollback record. "
                        + "No kernel rule or tunnel changes during recovery. "
                        + "Unknown rules are never adopted.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Verify + recover", (dialog, which) ->
                        run("Recover exact matching owned rules", false, session::recoverRouting))
                .show());
        remove = button(routing, "Remove Wonhee routing overrides");
        remove.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Remove Wonhee's routing rules?")
                .setMessage("The app will remove ONLY exactly matching rules recorded in "
                        + "its rollback ledger, even after an app restart. Kernel tunnels "
                        + "remain up. Rules belonging to anything else are not touched.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Remove owned rules", (dialog, which) ->
                        run("Remove owned routing rules", true, session::removeRouting))
                .show());

        LinearLayout encryptedDns = card(advancedGroup);
        label(encryptedDns, "PRODUCT BATCH D · ENCRYPTED DNS TRANSPORT", 18, PINK);
        label(encryptedDns, "Select one checked, verified tunnel and DNS protocol. "
                + "Built-in provider examples fill in a hostname and NUMERIC bootstrap IP; "
                + "you may enter a custom resolver. The root probe checks the upstream "
                + "route, binds the socket to that exact tunnel, validates TLS/response "
                + "and REFUSES on mismatch. No default/direct or plaintext fallback. "
                + "These are one-shot tests, NOT system-wide DNS enforcement.", 13, MUTED);
        dohTunnel = new Spinner(this);
        encryptedDns.addView(dohTunnel);
        dnsProtocol = new Spinner(this);
        ArrayAdapter<String> dnsProtocolOptions = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item,
                new String[] { "DoH · HTTPS/TCP", "DoQ · QUIC/UDP", "DoH3 · HTTP/3/UDP" });
        dnsProtocolOptions.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        dnsProtocol.setAdapter(dnsProtocolOptions);
        encryptedDns.addView(dnsProtocol);
        dohUrl = new EditText(this);
        dohUrl.setSingleLine(true);
        dohUrl.setTextColor(WHITE);
        dohUrl.setHintTextColor(MUTED);
        dohUrl.setHint("https://your-resolver.example/dns-query");
        dohUrl.setText("https://cloudflare-dns.com/dns-query");
        dohUrl.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_VARIATION_URI);
        encryptedDns.addView(dohUrl);
        dohBootstrap = new EditText(this);
        dohBootstrap.setSingleLine(true);
        dohBootstrap.setTextColor(WHITE);
        dohBootstrap.setHintTextColor(MUTED);
        dohBootstrap.setHint("Numeric bootstrap IP (no DNS lookup)");
        dohBootstrap.setText("1.1.1.1");
        dohBootstrap.setInputType(android.text.InputType.TYPE_CLASS_TEXT);
        encryptedDns.addView(dohBootstrap);
        label(encryptedDns, "AirVPN can route public resolver tests. A Home-only split "
                + "tunnel will correctly refuse a public DNS upstream unless that address "
                + "is explicitly routed through Home. No tunnel routes are added here.", 13, MUTED);
        dohProbe = button(encryptedDns, "Test ANDROID-bound DoH · framework baseline");
        dohProbe.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Send one encrypted DNS test query?")
                .setMessage("Wonhee will send an RFC 8484 query for example.com (A) to your "
                        + "chosen DNS provider ONLY if it can bind to the selected verified "
                        + "tunnel. The provider sees the query and your exit IP. "
                        + "TLS certificate/hostname must validate. No plaintext DNS, "
                        + "default-network retry, redirect, DNS settings or firewall changes. "
                        + "This diagnostic is not a system-wide DNS service.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Test encrypted DNS", (dialog, which) -> {
                    Object selectedTunnel = dohTunnel.getSelectedItem();
                    String profileName = selectedTunnel == null ? "" : selectedTunnel.toString();
                    String url = dohUrl.getText().toString();
                    String ip = dohBootstrap.getText().toString();
                    run("Product D DoH probe", false, (profiles, cb) ->
                            session.probeDoH(profiles, profileName, url, ip, cb));
                }).show());
        rootDohProbe = button(encryptedDns, "Test ROOT-bound DoH · opt in");
        rootDohProbe.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Run one root-bound " + currentDnsProtocol().toUpperCase(java.util.Locale.ROOT) + " probe?")
                .setMessage("Product D will execute a short-lived packaged helper as root. "
                        + "It binds its TCP or UDP socket directly to the selected, identity-verified "
                        + "WireGuard kernel interface and numeric bootstrap IP, then uses "
                        + "TLS certificate/hostname validation for the DNS server. "
                        + "Only example.com A will be queried; the DNS provider can see "
                        + "the query and tunnel exit address. If interface binding, TLS "
                        + "or DNS verification fails, it REFUSES with no other network, "
                        + "proxy or plaintext fallback. No routing, DNS or firewall "
                        + "settings are installed. Not a system resolver or kill switch.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Test encrypted DNS", (dialog, which) -> {
                    Object selectedTunnel = dohTunnel.getSelectedItem();
                    String profileName = selectedTunnel == null ? "" : selectedTunnel.toString();
                    String url = dohUrl.getText().toString();
                    String ip = dohBootstrap.getText().toString();
                    String protocol = currentDnsProtocol();
                    run("Product D " + protocol + " root-bound probe", false, (profiles, cb) ->
                            session.probeRootDns(profiles, profileName, protocol, url, ip, cb));
                }).show());
        dnsProtocol.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view,
                                                 int position, long id) {
                if (position == 1) {
                    dohUrl.setText("quic://dns.adguard-dns.com");
                    dohBootstrap.setText("94.140.14.14");
                } else {
                    dohUrl.setText("https://cloudflare-dns.com/dns-query");
                    dohBootstrap.setText("1.1.1.1");
                }
                dohProbe.setVisibility(position == 0 ? View.VISIBLE : View.GONE);
                rootDohProbe.setText("Test ROOT-bound "
                        + (position == 1 ? "DoQ" : position == 2 ? "DoH3" : "DoH")
                        + " · opt in");
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        label(encryptedDns, "Provider examples: Cloudflare for DoH/DoH3, AdGuard for DoQ. "
                + "Switching protocols resets these two fields. No endpoint preferences "
                + "are saved. Root-only "
                + "WireGuard links may not appear as bindable Android Networks: the "
                + "original app-bound probe will refuse. Use the separate ROOT-bound "
                + "test to check the kernel interface explicitly. Root execution is "
                + "one-shot, with no route, DNS or firewall mutation.", 13, PINK);

        LinearLayout trackers = card(advancedGroup);
        label(trackers, "PRODUCT BATCH E · LOCAL TRACKER BLOCKING", 18, PINK);
        label(trackers, "Optional, offline DNS filtering uses a small, transparent "
                + "starter list (" + RootTrackerPolicy.builtIns().size() + " known tracking/ad domains). "
                + "Subdomains are included. An allowlist always wins. No filter lists "
                + "are downloaded and no DNS history is collected. Some apps or sites "
                + "may break; disable and re-enable the DNS relay to change a live filter. "
                + "This cannot block hardcoded IPs or apps with their own HTTPS DNS.", 13, MUTED);
        trackerFilter = new CheckBox(this);
        trackerFilter.setText("Block known tracker domains when encrypted DNS starts");
        trackerFilter.setTextSize(15);
        trackerFilter.setTextColor(WHITE);
        trackerFilter.setButtonTintList(android.content.res.ColorStateList.valueOf(PINK));
        trackerFilter.setChecked(trackerPrefs.getBoolean("enabled", false));
        trackers.addView(trackerFilter);
        label(trackers, "Additional domains to block · one domain per line", 13, WHITE);
        trackerCustom = trackerTextEditor(trackers, "telemetry.example.net (example only)",
                trackerPrefs.getString("custom", ""));
        label(trackers, "Exceptions to allow · one domain per line", 13, WHITE);
        trackerAllow = trackerTextEditor(trackers, "trusted.example.net (example only)",
                trackerPrefs.getString("allow", ""));
        Button trackerPreview = button(trackers, "Preview tracker filtering · no system changes");
        trackerPreview.setOnClickListener(v -> {
            try {
                RootTrackerPolicy.Config configured = RootTrackerPolicy.compile(
                        trackerFilter.isChecked(), trackerCustom.getText().toString(),
                        trackerAllow.getText().toString());
                String summary = configured.enabled
                        ? "Local DNS filtering planned: " + configured.blocked.size()
                          + " domain suffixes blocked and " + configured.allowed.size()
                          + " allowed exceptions.\n\nBuilt-in suffixes:\n"
                          + String.join("\n", RootTrackerPolicy.builtIns())
                          + "\n\nExisting DNS policy is unchanged until separately enabled."
                        : "Tracker filtering is OFF. No DNS or firewall changes planned.";
                new AlertDialog.Builder(this).setTitle("Batch E policy preview")
                        .setMessage(summary).setPositiveButton("Close", null).show();
            } catch (IllegalArgumentException invalid) {
                new AlertDialog.Builder(this).setTitle("Tracker policy refused")
                        .setMessage(invalid.getMessage()).setPositiveButton("Close", null).show();
            }
        });
        trackerStatus = label(trackers, "TRACKER FILTER: " + session.trackerLedgerStatus(), 14, PINK);
        label(trackers, "Configuration is applied ONLY when you press Enable encrypted "
                + "system DNS below. The original selected encrypted upstream remains unchanged.", 13, MUTED);

        LinearLayout enforcement = card(advancedGroup);
        label(enforcement, "PRODUCT BATCH D · SYSTEM RESOLVER ENFORCEMENT", 18, PINK);
        label(enforcement, "EXPERIMENTAL ROOT FIREWALL CHANGE. After the selected "
                + "root-bound encrypted relay passes a local DNS health check, Wonhee "
                + "redirects IPv4 UDP/TCP 53 to it and blocks other classic DNS/DoT "
                + "ports. A tunnel or relay failure makes affected DNS requests FAIL, "
                + "not fall back to Wi-Fi. The original Android Private DNS setting "
                + "must be manually set to OFF before enabling. Keep USB ADB connected. "
                + "This does not intercept applications with their own HTTPS/QUIC DNS "
                + "on arbitrary ports, and is NOT an all-traffic kill switch.", 13, MUTED);
        dnsEnforcementStatus = label(enforcement,
                "DNS POLICY LEDGER: " + session.dnsLedgerStatus(), 14, WHITE);
        dnsEnable = button(enforcement, "Review + enable encrypted system DNS · opt in");
        dnsEnable.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Enable experimental root DNS interception?")
                .setMessage("This modifies IPv4/IPv6 firewall OUTPUT rules and can block "
                        + "DNS if the selected tunnel or encrypted relay fails. IPv6 port-53 "
                        + "queries and DoT TCP/853 will be rejected. First set Android "
                        + "Private DNS to OFF, keep USB ADB available, and do not disconnect "
                        + "these tunnels until you disable/verify owned DNS rules. "
                        + "Disable Batch C automatic tunnel recovery for this first test. "
                        + "Batch E tracker filter is " + (trackerFilter.isChecked() ? "SELECTED" : "OFF")
                        + "; it may cause app/site breakage. "
                        + "An exact rollback record is saved before any firewall mutation. "
                        + "Application-owned DoH on port 443 is not covered. Continue?")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Enable + verify", (dialog, which) -> {
                    Object chosen = dohTunnel.getSelectedItem();
                    String name = chosen == null ? "" : chosen.toString();
                    String protocol = currentDnsProtocol();
                    String url = dohUrl.getText().toString();
                    String bootstrap = dohBootstrap.getText().toString();
                    boolean filter = trackerFilter.isChecked();
                    String block = trackerCustom.getText().toString();
                    String allow = trackerAllow.getText().toString();
                    saveTrackerOptions();
                    run("Enable Batch D DNS-port protection", false, (profiles, cb) ->
                            session.enableRootDns(profiles, name, protocol, url, bootstrap,
                                    filter, block, allow, cb));
                }).show());
        dnsEnforcementAudit = button(enforcement, "Audit live DNS firewall + relay · read only");
        dnsEnforcementAudit.setOnClickListener(v -> run("Audit DNS enforcement", true,
                session::auditRootDns));
        dnsDisable = button(enforcement, "Disable owned DNS rules + restore resolution");
        dnsDisable.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Disable Wonhee's DNS interception?")
                .setMessage("Wonhee will remove ONLY exact owned DNS rules from its "
                        + "rollback ledger, then stop its verified root relay. Kernel "
                        + "tunnels and Android Private DNS settings are not modified. "
                        + "Unknown firewall rules will never be deleted.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Remove owned DNS rules", (dialog, which) ->
                        run("Disable Batch D DNS protection", true, session::disableRootDns))
                .show());

        LinearLayout failClosed = card(advancedGroup);
        label(failClosed, "PRODUCT BATCH F · FAIL-CLOSED FIREWALL PROTOTYPE", 18, PINK);
        label(failClosed, "HIGH-RISK EXPERIMENTAL ROOT OUTPUT FIREWALL. Default OFF. "
                + "Both IPv4/IPv6 deny traffic outside selected kernel tunnels, except "
                + "loopback and exact marked WireGuard UDP endpoints. This may disable "
                + "Wi-Fi/cellular; a shared Android 0x20000 mark is NOT a socket identity. "
                + "Other similarly marked traffic to either exact UDP endpoint may pass. "
                + "Do NOT treat this as a verified leak-proof kill switch. "
                + "Android services or Internet access may stop. Keep WORKING USB ADB "
                + "connected and a recovery shell open. First disable Batch D/E DNS "
                + "enforcement and Batch C auto recovery; keep selected tunnels UP. "
                + "Do not reboot, change or disconnect tunnels until the first rollback "
                + "passes. This prototype does NOT start at boot, prevent every possible "
                + "DNS leak or guarantee seamless handoffs.", 13, MUTED);
        failClosedStatus = label(failClosed,
                "KILL SWITCH LEDGER: " + session.guardLedgerStatus(), 14, PINK);
        failClosedEnable = button(failClosed, "Review + enable experimental kill switch · opt in");
        failClosedEnable.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Batch F: activate root fail-closed guard?")
                .setMessage("Only for a controlled test with USB ADB already connected. "
                        + "This installs app-owned IPv4/IPv6 firewall chains and can "
                        + "cut off all normal Internet connectivity. Your chosen Home "
                        + "and AirVPN tunnels must be UP, identity-verified and have unique "
                        + "numeric UDP endpoint tuples. Shared Android mark 0x20000 may "
                        + "be used, but it is NOT unique: any similarly marked traffic to "
                        + "those exact IP:port pairs can pass this firewall. Both the DNS guard "
                        + "and automatic recovery must be OFF. A rollback record is saved "
                        + "BEFORE any firewall change. Do not disconnect or reboot until "
                        + "you audit and disable this prototype. "
                        + "There is NO boot-time protection guarantee. Enable now?")
                .setNegativeButton("Cancel · keep OFF", null)
                .setPositiveButton("I have USB ADB · enable F", (dialog, which) ->
                        run("Enable Batch F root guard", false, session::enableGuard))
                .show());
        failClosedAudit = button(failClosed,
                "Verify live IPv4/IPv6 guard + rollback ledger · read only");
        failClosedAudit.setOnClickListener(v ->
                run("Audit Batch F guard", true, session::auditGuard));
        failClosedGuidedTest = button(failClosed,
                "Batch F guided preflight · read only, no test packets");
        failClosedGuidedTest.setOnClickListener(v ->
                run("Review Batch F guided safety checks", false, session::reviewGuardTest));
        failClosedUnderlayChallenge = button(failClosed,
                "Test IPv4 + IPv6 physical-underlay rejection · opt in");
        failClosedUnderlayChallenge.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Send two bounded underlay test packets?")
                .setMessage("HIGH-RISK ROOT EXPERIMENT. Only when Batch F is ACTIVE, "
                        + "both tunnels are UP and working USB ADB recovery is connected. "
                        + "Wonhee will attempt ONE ICMP echo each to fixed numeric IPv4 "
                        + "and IPv6 addresses, bound to the verified physical underlay. "
                        + "If the guard is broken, a packet COULD leave outside the VPN. "
                        + "No DNS lookup or private payload will be sent. The test reads "
                        + "exact guard REJECT counters before and after; other traffic may "
                        + "also change those counters. It does NOT disconnect or switch "
                        + "tunnels, install or remove firewall rules, test Home failure, "
                        + "or claim leak freedom. Keep USB ADB open. Proceed?")
                .setNegativeButton("Cancel · no packets", null)
                .setPositiveButton("USB ADB ready · send 2", (dialog, which) ->
                        run("Batch F bounded underlay challenge", false,
                                session::challengeGuardUnderlay))
                .show());
        failClosedDisable = button(failClosed, "Disable Batch F guard + verify exact rollback");
        failClosedDisable.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Remove Batch F firewall guard?")
                .setMessage("Remove only the app-owned IPv4/IPv6 OUTPUT anchors and "
                        + "chains documented in the saved rollback ledger, then verify "
                        + "removal. Unknown rules are never flushed. "
                        + "Kernel tunnel and Android DNS settings remain unchanged.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Disable + verify", (dialog, which) ->
                        run("Disable Batch F guard", true, session::disableGuard))
                .show());

        LinearLayout privacy = card(advancedGroup);
        label(privacy, "NETWORK PROTECTION · READ ONLY", 18, PINK);
        label(privacy, "Privacy Guard is a readiness report, NOT an active kill switch. "
                + "It inspects all selected kernel tunnel identities, UDP transport "
                + "marks/endpoints, public IPv4/IPv6 and split routes, existing "
                + "firewall capability and rollback ownership. It cannot prove "
                + "app-level DNS or fail-closed behavior.", 13, MUTED);
        guardReadiness = button(privacy, "Check multi-tunnel guard readiness");
        guardReadiness.setOnClickListener(v ->
                run("Audit multi-tunnel guard readiness", false, session::auditProtection));
        dnsAudit = button(privacy, "Audit configured DNS routes");
        dnsAudit.setOnClickListener(v ->
                run("Audit configured DNS routes", false, session::auditResolverRoutes));
        transportAudit = button(privacy, "Inspect UDP endpoint egress + Private DNS");
        transportAudit.setOnClickListener(v ->
                run("Audit marked transport paths", false, session::auditTransportPaths));
        label(privacy, "This new Batch D check evaluates the marked route to "
                + "each selected tunnel's current numeric UDP endpoint without "
                + "showing the endpoint address, then records Android's Private "
                + "DNS setting. It does not capture packets or install exceptions.", 13, MUTED);
        label(privacy, "SERVICE PATH · APP SOCKET TEST", 18, PINK);
        label(privacy, "Enter a numeric service destination, such as "
                + "10.0.0.169:4533 or [2001:db8::1]:443. This checks the "
                + "root route separately from a TCP connection made by Wonhee's "
                + "own Android app UID and records WireGuard byte-counter "
                + "changes around the connection. Background traffic may contribute "
                + "to those counters; this is not packet-path proof.", 13, MUTED);
        serviceTarget = new EditText(this);
        serviceTarget.setSingleLine(true);
        serviceTarget.setTextColor(WHITE);
        serviceTarget.setHintTextColor(MUTED);
        serviceTarget.setHint("IP address:port");
        serviceTarget.setTextSize(16);
        serviceTarget.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_VARIATION_URI);
        privacy.addView(serviceTarget);
        serviceProbe = button(privacy, "Test app TCP reachability · no HTTP data");
        serviceProbe.setOnClickListener(v -> {
            String target = serviceTarget.getText().toString();
            run("Probe numeric TCP service path", false,
                    (profiles, callback) -> session.probeService(profiles, target, callback));
        });
        packetObserve = button(privacy, "Observe filtered TCP packet headers · opt in");
        packetObserve.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Observe narrowly filtered packets?")
                .setMessage("Wonhee will attempt up to 4 seconds of filtered TCP "
                        + "summary observation on EACH selected, identity-verified "
                        + "WireGuard interface, creating one TCP handshake per interface "
                        + "to the numeric target above. Only packet counts are reported; "
                        + "no payload, raw addresses or pcap files are saved. This "
                        + "requires existing root tcpdump and timeout tools; nothing "
                        + "is installed. No firewall or route changes occur.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Observe headers", (dialog, which) -> {
                    String target = serviceTarget.getText().toString();
                    run("Observe scoped TCP packet path", false,
                            (profiles, callback) -> session.observeTcpPacketPaths(
                                    profiles, target, callback));
                }).show());
        guardModel = button(privacy, "Preview fail-closed decision · NO rules");
        guardModel.setOnClickListener(v -> {
            String target = serviceTarget.getText().toString();
            run("Preview hypothetical no-fallback decision", false,
                    (profiles, callback) -> session.previewFailClosedModel(
                            profiles, target, callback));
        });
        label(privacy, "The scoped packet-capture diagnostic is optional and may report UNAVAILABLE "
                + "if root tcpdump is absent. The guard preview is a pure model: "
                + "it never installs a kill switch. Android's active network "
                + "DNS state is also included in the endpoint audit.", 13, MUTED);
        label(privacy, "Kill switch: OFF. No iptables/ip6tables changes, DNS blocking "
                + "or hidden network rules are installed by these checks. "
                + "Keep USB ADB recovery ready for future enforcement testing.", 13, PINK);

        LinearLayout diagnostics = card(page);
        label(diagnostics, "LATEST RESULT", 18, PINK);
        output = label(diagnostics, "Select profiles, preview and connect, then audit "
                + "routing. Any correction is a separate opt-in action. Remove owned "
                + "rules before disconnecting or changing tunnels.", 14, WHITE);
        updateButtons();
    }

    @Override protected void onResume() {
        super.onResume();
        reloadProfiles();
        if (dnsEnforcementStatus != null) {
            dnsEnforcementStatus.setText("DNS POLICY LEDGER: " + session.dnsLedgerStatus());
        }
    }

    @Override protected void onPause() {
        saveTrackerOptions();
        super.onPause();
    }

    private EditText trackerTextEditor(LinearLayout parent, String hint, String value) {
        EditText editor = new EditText(this);
        editor.setTextColor(WHITE);
        editor.setHintTextColor(MUTED);
        editor.setTextSize(14);
        editor.setHint(hint);
        editor.setMinLines(2);
        editor.setMaxLines(4);
        editor.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        editor.setText(value);
        parent.addView(editor);
        return editor;
    }

    private void saveTrackerOptions() {
        if (trackerPrefs == null || trackerFilter == null || trackerCustom == null || trackerAllow == null) return;
        trackerPrefs.edit().putBoolean("enabled", trackerFilter.isChecked())
                .putString("custom", trackerCustom.getText().toString())
                .putString("allow", trackerAllow.getText().toString()).apply();
    }

    private void reloadProfiles() {
        String previousDoHTunnel = dohTunnel == null || dohTunnel.getSelectedItem() == null
                ? "" : dohTunnel.getSelectedItem().toString();
        List<String> checked = new ArrayList<>();
        for (Map.Entry<String, CheckBox> entry : selection.entrySet()) {
            if (entry.getValue().isChecked()) checked.add(entry.getKey());
        }
        try {
            List<SecureTunnelProfileStore.Profile> imported = store.load();
            saved.clear();
            saved.addAll(imported);
            selection.clear();
            profileRows.removeAllViews();
            for (SecureTunnelProfileStore.Profile profile : saved) {
                CheckBox checkbox = new CheckBox(this);
                checkbox.setText(profile.name + "  ·  " + routeLabel(profile.routeMode));
                checkbox.setTextColor(WHITE);
                checkbox.setTextSize(15);
                checkbox.setPadding(dp(4), dp(8), dp(4), dp(8));
                checkbox.setButtonTintList(android.content.res.ColorStateList.valueOf(PINK));
                checkbox.setChecked(checked.contains(profile.name));
                checkbox.setOnCheckedChangeListener((button, isChecked) -> updateButtons());
                profileRows.addView(checkbox);
                selection.put(profile.name, checkbox);
            }
            List<String> names = new ArrayList<>();
            for (SecureTunnelProfileStore.Profile profile : saved) names.add(profile.name);
            ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                    android.R.layout.simple_spinner_item, names);
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            dohTunnel.setAdapter(adapter);
            int prior = names.indexOf(previousDoHTunnel);
            if (prior >= 0) dohTunnel.setSelection(prior);
            if (saved.isEmpty()) label(profileRows, "Import a WireGuard .conf to begin.", 13, MUTED);
        } catch (Exception unavailable) {
            saved.clear();
            selection.clear();
            profileRows.removeAllViews();
            dohTunnel.setAdapter(null);
            label(profileRows, "Could not open encrypted profiles. Check Keystore availability.",
                    13, PINK);
        }
        updateButtons();
    }

    private String routeLabel(int routeMode) {
        if (routeMode == VpnRouteModes.HOME) return "split destinations";
        if (routeMode == VpnRouteModes.ALL) return "IPv4+IPv6 defaults";
        return "profile-defined routes";
    }

    private String currentDnsProtocol() {
        int position = dnsProtocol == null ? 0 : dnsProtocol.getSelectedItemPosition();
        if (position == 1) return "doq";
        if (position == 2) return "doh3";
        return "doh";
    }

    private List<SecureTunnelProfileStore.Profile> selected() {
        List<SecureTunnelProfileStore.Profile> profiles = new ArrayList<>();
        for (SecureTunnelProfileStore.Profile profile : saved) {
            CheckBox checkbox = selection.get(profile.name);
            if (checkbox != null && checkbox.isChecked()) profiles.add(profile);
        }
        return profiles;
    }

    private interface Operation {
        void invoke(List<SecureTunnelProfileStore.Profile> selected, RootMultiKernelSession.Callback cb);
    }

    private void startGuidedAudit() {
        List<SecureTunnelProfileStore.Profile> chosen = selected();
        if (chosen.isEmpty()) {
            guidedStatus.setText("Choose at least one imported profile first. "
                    + "Connect it before requesting an identity audit.");
            return;
        }
        if (guidedRunning || session.isBusy()) return;
        guidedFindings.clear();
        guidedRunning = true;
        guidedStatus.setText("Checking selected profiles · step 1 of "
                + RootSafetyGuide.STEP_COUNT + "...\nNo settings will be changed.");
        updateButtons();
        nextGuidedStep(chosen, 0);
    }

    private void nextGuidedStep(List<SecureTunnelProfileStore.Profile> chosen, int step) {
        if (step == RootSafetyGuide.STEP_COUNT) {
            guidedRunning = false;
            String summary = RootSafetyGuide.summary(guidedFindings);
            guidedStatus.setText(summary + "\nKILL SWITCH: " + session.guardLedgerStatus()
                    + " · DNS POLICY LEDGER: " + session.dnsLedgerStatus());
            output.setText("GUIDED READ-ONLY CHECK COMPLETE\n" + summary
                    + "\nTap Review safety check details for each audit.");
            journal.record("RESULT", "Guided read-only audit completed, "
                    + guidedFindings.size() + " checks; no mutations");
            updateButtons();
            return;
        }
        Operation operation;
        switch (step) {
            case 0: operation = session::inspect; break;
            case 1: operation = session::auditRouting; break;
            case 2: operation = session::auditResolverRoutes; break;
            case 3: operation = session::auditTransportPaths; break;
            case 4: operation = session::auditProtection; break;
            default: throw new IllegalStateException("Unexpected guided audit step.");
        }
        operation.invoke(chosen, (ok, report) -> {
            if (isFinishing() || isDestroyed()) return;
            RootSafetyGuide.Finding finding = RootSafetyGuide.assess(
                    step, chosen.size(), ok, report);
            guidedFindings.add(finding);
            if (!ok) {
                guidedRunning = false;
                guidedStatus.setText(RootSafetyGuide.summary(guidedFindings)
                        + "\nNo configuration changed. Review details before retrying.");
                output.setText("GUIDED CHECK PAUSED\n" + finding.explanation);
                updateButtons();
                return;
            }
            guidedStatus.setText("Completed " + (step + 1) + "/"
                    + RootSafetyGuide.STEP_COUNT + ": " + finding.label
                    + "\n" + finding.explanation + "\nChecking next step...");
            nextGuidedStep(chosen, step + 1);
        });
    }

    private void showGuidedDetails() {
        if (guidedFindings.isEmpty()) {
            guidedStatus.setText("Run the guided check first; no security assessment is saved.");
            return;
        }
        String[] options = new String[guidedFindings.size()];
        for (int i = 0; i < options.length; i++) {
            options[i] = RootSafetyGuide.TITLES[i] + " · " + guidedFindings.get(i).label;
        }
        new AlertDialog.Builder(this)
                .setTitle("Read-only safety check results")
                .setItems(options, (dialog, index) -> {
                    RootSafetyGuide.Finding chosen = guidedFindings.get(index);
                    new AlertDialog.Builder(this)
                            .setTitle(options[index])
                            .setMessage(chosen.explanation + "\n\n" + chosen.detail)
                            .setPositiveButton("Done", null).show();
                })
                .setNegativeButton("Close", null).show();
    }

    private void run(String action, boolean allowEmpty, Operation operation) {
        if (guidedRunning) return;
        List<SecureTunnelProfileStore.Profile> list = selected();
        if (list.isEmpty() && !allowEmpty) {
            output.setText("Choose at least one encrypted profile.");
            return;
        }
        if (session.isBusy()) {
            output.setText("A root operation is still running. Try again after it finishes.");
            return;
        }
        journal.record("ACTION", action + " for " + list.size() + " selected profile(s)");
        output.setText("Working: " + action + "...");
        operation.invoke(list, (ok, result) -> {
            if (isFinishing() || isDestroyed()) return;
            output.setText((ok ? "COMPLETE\n" : "CHECK REQUIRED\n") + result);
            // DNS destinations/probe outcomes must not persist into diagnostics.
            journal.record("RESULT", action.startsWith("Product D DoH")
                    ? "Product D DoH probe " + (ok ? "verified" : "refused") : result);
            updateButtons();
        });
        updateButtons();
    }

    private void confirm(boolean starting) {
        List<SecureTunnelProfileStore.Profile> list = selected();
        if (list.isEmpty()) { output.setText("Select at least one profile first."); return; }
        new AlertDialog.Builder(this)
                .setTitle(starting ? "Connect selected tunnels?" : "Disconnect selected tunnels?")
                .setMessage(starting
                        ? "Wonhee will preflight all selected routes, refuse legacy pair "
                        + "collisions, and start only new uniquely named interfaces. "
                        + "Connection may change Internet routing; this is experimental "
                        + "and has NO kill switch. Keep USB ADB available."
                        : "Wonhee will verify the selected kernel interfaces against "
                        + "their saved public identities before stopping any. Other VPNs "
                        + "will be left alone. Regular Wi-Fi/cellular traffic may resume.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton(starting ? "Connect" : "Disconnect", (dialog, which) ->
                        run(starting ? "Connect multi-tunnel selection" : "Disconnect multi-tunnel selection",
                                false, starting ? session::connect : session::disconnect))
                .show();
    }

    private void updateButtons() {
        boolean idle = !session.isBusy() && !guidedRunning;
        boolean ready = idle && !selected().isEmpty();
        boolean firewallUnlocked = "OFF".equals(session.guardLedgerStatus());
        for (CheckBox checkbox : selection.values()) checkbox.setEnabled(idle);
        if (connect != null) connect.setEnabled(ready && firewallUnlocked);
        if (disconnect != null) disconnect.setEnabled(ready && firewallUnlocked);
        if (preview != null) preview.setEnabled(ready);
        if (inspect != null) inspect.setEnabled(idle);
        if (audit != null) audit.setEnabled(ready);
        if (apply != null) apply.setEnabled(ready && firewallUnlocked);
        if (recover != null) recover.setEnabled(ready && firewallUnlocked);
        if (guardReadiness != null) guardReadiness.setEnabled(ready);
        if (dnsAudit != null) dnsAudit.setEnabled(ready);
        if (transportAudit != null) transportAudit.setEnabled(ready);
        if (serviceProbe != null) serviceProbe.setEnabled(ready);
        if (packetObserve != null) packetObserve.setEnabled(ready);
        if (guardModel != null) guardModel.setEnabled(ready);
        if (remove != null) remove.setEnabled(idle && firewallUnlocked);
        if (enableRecovery != null) enableRecovery.setEnabled(ready && firewallUnlocked);
        if (checkRecovery != null) checkRecovery.setEnabled(idle && firewallUnlocked);
        if (dohProbe != null) dohProbe.setEnabled(ready);
        if (rootDohProbe != null) rootDohProbe.setEnabled(ready);
        if (dohTunnel != null) dohTunnel.setEnabled(idle);
        if (dnsProtocol != null) dnsProtocol.setEnabled(idle);
        if (dohUrl != null) dohUrl.setEnabled(idle);
        if (dohBootstrap != null) dohBootstrap.setEnabled(idle);
        if (dnsEnable != null) dnsEnable.setEnabled(ready && firewallUnlocked
                && "OFF".equals(session.dnsLedgerStatus()));
        if (dnsDisable != null) dnsDisable.setEnabled(idle && !"OFF".equals(session.dnsLedgerStatus()));
        if (dnsEnforcementAudit != null) dnsEnforcementAudit.setEnabled(idle);
        if (dnsEnforcementStatus != null) {
            dnsEnforcementStatus.setText("DNS POLICY LEDGER: " + session.dnsLedgerStatus());
        }
        if (failClosedEnable != null) failClosedEnable.setEnabled(ready
                && "OFF".equals(session.guardLedgerStatus())
                && "OFF".equals(session.dnsLedgerStatus()));
        if (failClosedAudit != null) failClosedAudit.setEnabled(idle);
        if (failClosedGuidedTest != null) failClosedGuidedTest.setEnabled(ready);
        if (failClosedUnderlayChallenge != null) failClosedUnderlayChallenge.setEnabled(ready
                && !"OFF".equals(session.guardLedgerStatus()));
        if (failClosedDisable != null) failClosedDisable.setEnabled(idle
                && !"OFF".equals(session.guardLedgerStatus()));
        if (failClosedStatus != null) {
            failClosedStatus.setText("KILL SWITCH LEDGER: " + session.guardLedgerStatus());
        }
        boolean trackerEditable = idle && "OFF".equals(session.dnsLedgerStatus());
        if (trackerFilter != null) trackerFilter.setEnabled(trackerEditable);
        if (trackerCustom != null) trackerCustom.setEnabled(trackerEditable);
        if (trackerAllow != null) trackerAllow.setEnabled(trackerEditable);
        if (trackerStatus != null) trackerStatus.setText("TRACKER FILTER: " + session.trackerLedgerStatus());
        if (disableRecovery != null) disableRecovery.setEnabled(idle);
        if (guidedAudit != null) guidedAudit.setEnabled(ready);
        if (guidedDetails != null) guidedDetails.setEnabled(idle && !guidedFindings.isEmpty());
        if (advancedToggle != null) advancedToggle.setEnabled(idle);
        if (recoveryStatus != null) recoveryStatus.setText(session.recoveryStatus());
    }

    private LinearLayout card(LinearLayout parent) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(14), dp(14), dp(14), dp(14));
        card.setBackgroundColor(PANEL);
        LinearLayout.LayoutParams layout = new LinearLayout.LayoutParams(-1, -2);
        layout.topMargin = dp(16);
        parent.addView(card, layout);
        return card;
    }

    private TextView label(LinearLayout parent, String content, int size, int color) {
        TextView view = new TextView(this);
        view.setText(content);
        view.setTextColor(color);
        view.setTextSize(size);
        view.setPadding(0, dp(7), 0, dp(7));
        parent.addView(view);
        return view;
    }

    private Button button(LinearLayout parent, String title) {
        Button view = new Button(this);
        view.setText(title);
        view.setAllCaps(false);
        view.setTextSize(15);
        view.setTextColor(WHITE);
        view.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xff553659));
        // Allow long labels to wrap without clipping behind Android UI bars.
        view.setMinHeight(dp(56));
        view.setPadding(dp(12), dp(12), dp(12), dp(12));
        LinearLayout.LayoutParams layout = new LinearLayout.LayoutParams(-1, -2);
        layout.topMargin = dp(8);
        parent.addView(view, layout);
        return view;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
