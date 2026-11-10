package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.SharedPreferences;
import android.net.Uri;
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

import java.io.InputStream;
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
    private static final int REQUEST_HOSTS_IMPORT = 8124;
    private static final int REQUEST_ROOT_NOTIFICATION = 8451;
    private static final String ROOT_NOTIFICATION_PREFS = "wonhee_root_traffic_notification";
    private Button rootTrafficNotificationButton;

    private SecureTunnelProfileStore store;
    private RootMultiKernelSession session;
    private RootSessionJournal journal;
    private final List<SecureTunnelProfileStore.Profile> saved = new ArrayList<>();
    private final Map<String, CheckBox> selection = new LinkedHashMap<>();
    private LinearLayout profileRows;
    private TextView output;
    private TextView routeEvidenceSummary;
    private Button exportRouteEvidence;
    private String lastRouteEvidence;
    private Button connect;
    private Button disconnect;
    private Button managedStart;
    private Button managedStop;
    private Button prepareUpdate;
    private Button lifecycleAudit;
    private Button lifecycleRepair;
    private Button emergencyDnsOff;
    private Button orphanDnsAudit;
    private Button orphanDnsRepair;
    private boolean lifecycleBusy;
    private Button preview;
    private Button inspect;
    private Button internetIncidentAudit;
    private Button perAppAudit;
    private Button liveSocketAudit;
    private Button socketBurstAudit;
    private Button livePeerAudit;
    private Button socketBurstCancel;
    private Button audit;
    private Button apply;
    private Button remove;
    private Button recover;
    private Button guardReadiness;
    private Button dnsAudit;
    private Button transportAudit;
    private Button passiveHealth;
    private Button passiveUnderlay;
    private Button serviceProbe;
    private Button packetObserve;
    private Button guardModel;
    private Button enableRecovery;
    private Button disableRecovery;
    private Button checkRecovery;
    private Button dohProbe;
    private Button rootDohProbe;
    private Button relayLifecycleProbe;
    private Button dnsEnable;
    private Button dnsDisable;
    private Button dnsEnforcementAudit;
    private Button dnsPrivacyAudit;
    private Button failClosedEnable;
    private Button failClosedAudit;
    private Button failClosedDisable;
    private Button failClosedGuidedTest;
    private Button failClosedControlPlaneReview;
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
    private volatile boolean blocklistBusy;
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
        label(controls, "PRIMARY VPN CONTROLS · BATCH H", 17, PINK);
        label(controls, "Start in order: verified tunnels → split routing → encrypted DNS "
                + "and tracker filtering → live DNS audit. Stop in reverse protection "
                + "order: exact DNS rollback → exact split-rule cleanup → identity-"
                + "verified tunnel disconnect. Automatic boot startup is NOT enabled. "
                + "Do not confuse this with an all-traffic kill switch.", 13, MUTED);
        managedStart = button(controls, "Start complete Wonhee stack · one confirmation");
        managedStart.setOnClickListener(v -> startManagedStack());
        managedStop = button(controls, "Safe stop complete Wonhee stack · one confirmation");
        managedStop.setOnClickListener(v -> stopManagedStack());
        prepareUpdate = button(controls,
                "Prepare for app update · Safe Stop + independent verification");
        prepareUpdate.setOnClickListener(v -> prepareForUpdate());
        label(controls, "Updates require all Wonhee tunnels DOWN, DNS relay and "
                + "interception cleared, and split-route ownership reconciled. "
                + "This control does not launch the Android installer or prevent "
                + "an external ADB/Play Store update. Use the Fedora guarded "
                + "installer for the final independent live-state check.", 12, MUTED);
        internetIncidentAudit = button(controls,
                "Connected but no Internet · read-only snapshot");
        internetIncidentAudit.setOnClickListener(v -> run(
                "Connectivity incident snapshot", false, session::auditInternetIncident));
        label(controls, "If both tunnels appear UP but browsing stops, select EVERY "
                + "active profile and capture a passive report before Safe Stop, "
                + "only if practical. It checks identity, handshake age, transfer "
                + "counter movement, routes, DNS and relay without sending packets "
                + "or changing connectivity. If you need service restored, use "
                + "Safe Stop rather than waiting for diagnostics.", 12, MUTED);

        perAppAudit = button(controls,
                "Inspect Messages / Play services / Android routes · read only");
        perAppAudit.setOnClickListener(v -> run("Per-app route predictions",
                false, session::auditKnownAppRouting));
        label(controls, "Compares the actual installed app UIDs with kernel route "
                + "predictions for normal and protected-from-VPN socket marks. "
                + "It DOES NOT observe live sockets or enforce VPN-only traffic. "
                + "Select every active tunnel; do not disable RCS, microG, "
                + "Google services or Wi-Fi Calling for this test.", 12, MUTED);

        liveSocketAudit = button(controls,
                "Inspect live socket marks (Messages / Play / Android) · read only");
        liveSocketAudit.setOnClickListener(v -> run("Live socket marks read-only",
                false, session::auditLiveSocketMarks));
        label(controls, "Three short passive samples using existing root ss/inet_diag. "
                + "Reports only app UIDs, aggregate socket counts and readable fwmarks; "
                + "no peer addresses, messages, or DNS queries are displayed. "
                + "A short-lived QUIC connection may be missed, and a sampled "
                + "mark alone does not prove its actual physical route. "
                + "Requires Android/kernel ss support; refusal changes nothing.",
                12, MUTED);

        socketBurstAudit = button(controls,
                "Watch live socket marks for up to 15 seconds · read only");
        socketBurstAudit.setOnClickListener(v -> run(
                "Targeted socket mark burst", false, session::auditLiveSocketMarksBurst));
        label(controls, "DIRECT-ROUTE ADVISORIES · READ ONLY", 17, PINK);
        livePeerAudit = button(controls,
                "0.15.38 · Check direct-route advisories · read only");
        livePeerAudit.setOnClickListener(v -> run(
                "Live peer route attribution", false, session::auditLivePeerRouting));
        label(controls, "This is the 0.15.38 direct-route advisory audit. "
                + "Checks numeric public destinations of observed Messages, "
                + "Google services and Android sockets against their REAL UID and "
                + "fwmark (up to 18 route lookups, bounded watch). Shows only "
                + "aggregate route categories. Local KDE Connect/Navidrome "
                + "destinations are excluded; no messages or remote IPs are shown. "
                + "Predicted routes do not prove packet egress.", 12, MUTED);
        socketBurstCancel = button(controls, "Stop live socket watch");
        socketBurstCancel.setOnClickListener(v -> {
            if (session.isSocketBurstActive()) {
                session.cancelSocketBurst();
                socketBurstCancel.setEnabled(false);
                output.setText("Stop requested. Returning partial aggregate "
                        + "after current read-only socket query completes.");
            }
        });
        label(controls, "Start this short watch, then open Messages or Play Store "
                + "normally. It ends automatically or when Stop is tapped. "
                + "No packet capture, endpoints, contents, or firewall actions. "
                + "A missing transient socket is not proof of safe routing.",
                12, MUTED);

        label(controls, "EMERGENCY DNS RECOVERY · NO VPN RESTART REQUIRED", 17, PINK);
        label(controls, "If DNS redirects or rejects requests and the normal owner "
                + "record is missing, first run the read-only orphan audit, then "
                + "the explicitly confirmed exact DNS-only recovery. This works "
                + "with tunnels UP or DOWN and never disconnects them, changes "
                + "routing, or terminates an unverified local relay. Removing "
                + "DNS protection may allow regular Android DNS outside the VPN.",
                13, MUTED);
        emergencyDnsOff = button(controls,
                "Disable verified owned DNS · even when tunnels are DOWN");
        emergencyDnsOff.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Disable exact owned DNS firewall now?")
                .setMessage("Wonhee will use the existing saved DNS owner record "
                        + "to remove only its exact firewall rules and stop the "
                        + "verified local DNS relay. The tunnels do NOT need to "
                        + "be connected. If the record is missing, use Orphan DNS "
                        + "Audit instead. This can restore normal, unprotected "
                        + "Android DNS when the VPN is down.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Disable owned DNS", (d, w) ->
                        run("Emergency DNS owned disable", true, session::disableRootDns))
                .show());
        orphanDnsAudit = button(controls, "Audit orphaned DNS firewall · read only");
        orphanDnsAudit.setOnClickListener(v ->
                run("Orphan DNS read-only audit", true, session::auditOrphanDns));
        orphanDnsRepair = button(controls,
                "Recover exact orphaned DNS rules · explicit opt in");
        orphanDnsRepair.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Emergency orphan DNS cleanup?")
                .setMessage("This is ONLY for lost DNS ownership records. "
                        + "With no saved DNS owner record and no Batch F guard, "
                        + "Wonhee checks all EIGHT original WN_ DNS firewall "
                        + "signatures and refuses any extra, modified or duplicated "
                        + "WN_ rule. An exact tag match alone cannot prove "
                        + "cryptographic ownership. Only after a second preflight "
                        + "will it record durable recovery intent and remove "
                        + "those exact rules. A partial cleanup may then be "
                        + "retried after interruption. It leaves existing "
                        + "tunnels, routing, and DNS relay processes untouched, "
                        + "even if they are running. Normal Android DNS may "
                        + "resume outside the VPN. Keep USB ADB available.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Verify and remove orphan DNS", (d, w) ->
                        run("Orphan DNS explicit repair", true, session::recoverOrphanDns))
                .show());

        label(controls, "BATCH H.2a · CRASH / REBOOT RECOVERY", 17, PINK);
        label(controls, "If the app was interrupted, first inspect whether exact "
                + "saved ownership still matches live DNS and route rules. "
                + "Stopped-state repair is only permitted with NO active kernel "
                + "tunnels, NO local DNS listener and NO unknown firewall rules. "
                + "Active sessions must use Safe stop above.", 13, MUTED);
        lifecycleAudit = button(controls,
                "Audit interrupted startup/shutdown · read only");
        lifecycleAudit.setOnClickListener(v -> run(
                "Batch H.2a reconciliation audit", true, session::auditLifecycleRecovery));
        lifecycleRepair = button(controls,
                "Repair VERIFIED stopped ownership · opt in");
        lifecycleRepair.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Repair stale ownership only while stopped?")
                .setMessage("Batch H.2a will independently inspect all selected "
                        + "kernel interfaces, the DNS relay, owned DNS firewall "
                        + "tags, and every IPv4/IPv6 routing priority 12500–12799. "
                        + "It REFUSES repair if ANY WireGuard tunnel or DNS listener "
                        + "is running, if a guard chain exists, or if any rule differs "
                        + "from Wonhee's exact saved ownership. "
                        + "After verifying the STOPPED state twice, it can remove "
                        + "exact owned leftover rules and stale ownership entries. "
                        + "It will NOT start or disconnect tunnels. "
                        + "Keep USB ADB available; back up important configurations.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Repair verified stopped state", (dialog, which) ->
                        run("Batch H.2a stopped ownership repair", true,
                                session::repairStoppedLifecycle))
                .show());


        inspect = button(controls, "Read live kernel status");
        inspect.setOnClickListener(v -> run("Read multi-tunnel state", true, session::inspect));
        rootTrafficNotificationButton = button(controls,
                "Enable root tunnel speed + blocked-request notification");
        rootTrafficNotificationButton.setOnClickListener(v -> toggleRootTrafficNotification());
        label(controls, "Optional silent notification: combined download/upload from "
                + "identity-verified kernel WireGuard tunnels, plus DNS blocked replies "
                + "since the current relay started. Not Android's system VPN badge, "
                + "not a whole-device leak test, and not a kill switch.", 12, MUTED);
        Button dashboardPreview = button(controls,
                "Open Candy Pink status dashboard · preview");
        dashboardPreview.setOnClickListener(v -> startActivity(
                new Intent(this, WonheeDashboardPreviewActivity.class)));

        // Route diagnostics are discoverable without opening advanced controls.
        LinearLayout evidence = card(page);
        label(evidence, "DIAGNOSTICS · ROUTE EVIDENCE", 18, PINK);
        label(evidence, "Protected-from-VPN predictions may reflect intentional Android "
                + "exemptions. No kernel route prediction proves real packet egress.",
                13, MUTED);
        routeEvidenceSummary = label(evidence,
                "No current audit. Select all active profiles and run the read-only check.",
                14, WHITE);
        Button directEvidence = button(evidence, "Check app direct-route evidence · read only");
        directEvidence.setOnClickListener(v -> run(
                "Live peer route attribution", false, session::auditLivePeerRouting));
        exportRouteEvidence = button(evidence, "Share latest route summary · no endpoints");
        exportRouteEvidence.setEnabled(false);
        exportRouteEvidence.setOnClickListener(v -> shareRouteEvidence());
        label(evidence, "HANDOFF & STABILITY · MANUAL CHECK", 16, PINK);
        label(evidence, "Take a passive snapshot before and after a naturally occurring "
                + "Wi-Fi/cellular handoff, then audit live DNS separately. No handoff, "
                + "tunnel restart, firewall or DNS change is initiated. Keep Android "
                + "Private DNS OFF.", 12, MUTED);
        Button handoffSnapshot = button(evidence,
                "Snapshot tunnel health before/after handoff · read only");
        handoffSnapshot.setOnClickListener(v -> run(
                "F.2 manual passive health snapshot", false, session::snapshotPassiveHealth));
        Button handoffDns = button(evidence, "Audit DNS relay after handoff · read only");
        handoffDns.setOnClickListener(v -> run(
                "Audit DNS enforcement", true, session::auditRootDns));

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

        LinearLayout manualControls = card(advancedGroup);
        label(manualControls, "ADVANCED · TUNNEL-ONLY CONTROLS", 18, PINK);
        label(manualControls, "These controls modify ONLY selected WireGuard interfaces, "
                + "not DNS, routing or tracker protection. For regular use, prefer "
                + "Start complete Wonhee stack and Safe stop complete Wonhee stack. "
                + "Direct tunnel disconnect is blocked whenever DNS ownership "
                + "or live Wonhee DNS firewall rules remain.", 13, MUTED);
        connect = button(manualControls, "Advanced · connect tunnels only (no DNS)");
        connect.setOnClickListener(v -> confirm(true));
        disconnect = button(manualControls, "Advanced · disconnect tunnels only (DNS must be OFF)");
        disconnect.setOnClickListener(v -> confirm(false));

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
        label(routing, "Batch B.1 fixes Android network-mark precedence: HOME destination "
                + "rules match locally generated traffic that is not protectedFromVpn, "
                + "regardless of its network ID. Protected sockets are preserved and "
                + "Android/netd rules are not changed. The read-only audit checks root "
                + "routes plus representative Android fwmark simulations; it is NOT "
                + "proof of actual app sockets, a leak test or a kill switch.", 13, MUTED);
        audit = button(routing, "Audit effective routes · read only");
        audit.setOnClickListener(v -> run("Audit root and Android-mark routes", false, session::auditRouting));
        apply = button(routing, "Apply split-route correction · experimental");
        apply.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Install owned routing priority rules?")
                .setMessage("Only selected, identity-verified running tunnels can be used. "
                        + "Wonhee will refuse policy-rule collisions, protected-socket conflicts "
                        + "and unsafe WireGuard endpoint paths. It installs HOME destination "
                        + "rules using Android's protectedFromVpn bit, saves an exact rollback "
                        + "ledger, then checks root and representative app-UID mark routes. "
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
        relayLifecycleProbe = button(encryptedDns,
                "Batch D.19 · Test local DNS relay lifecycle · no firewall");
        relayLifecycleProbe.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Run temporary encrypted DNS relay test?")
                .setMessage("Uses the same packaged persistent DNS helper as system interception "
                        + "on the selected identity-verified root tunnel. Wonhee starts a "
                        + "short-lived localhost-only root relay, verifies its exact PID "
                        + "and loopback listener, sends one encrypted example.com DNS "
                        + "health query, and stops only its verified PID. No firewall, "
                        + "Android DNS, routing, recovery, or kill-switch settings change. "
                        + "USB ADB recommended; a failed cleanup requires inspection.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Test relay without firewall", (dialog, which) -> {
                    Object chosen = dohTunnel.getSelectedItem();
                    String name = chosen == null ? "" : chosen.toString();
                    String protocol = currentDnsProtocol();
                    String url = dohUrl.getText().toString();
                    String bootstrap = dohBootstrap.getText().toString();
                    run("Product D relay lifecycle test", false, (profiles, cb) ->
                            session.testRootDnsRelay(profiles, name, protocol, url, bootstrap, cb));
                }).show());
        label(encryptedDns, "Run the relay lifecycle test BEFORE enabling system DNS. "
                + "It separately reports launch, PID identity, listener readiness, and "
                + "local encrypted DNS response failures without installing firewall rules.",
                13, PINK);
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
                if (blocklistBusy) { output.setText("Another blocklist operation is running."); return; }
                blocklistBusy = true;
                final boolean enabled = trackerFilter.isChecked();
                final String custom = trackerCustom.getText().toString();
                final String allow = trackerAllow.getText().toString();
                new Thread(() -> {
                    String summary;
                    try {
                        RootTrackerPolicy.Config configured = RootTrackerPolicy.compileWithManaged(
                                enabled, custom, allow, getFilesDir());
                        summary = configured.enabled
                                ? "Local filtering planned: " + configured.blocked.size()
                                  + " unique blocked suffixes; " + configured.allowed.size()
                                  + " allowed exceptions.\nBuilt-ins: "
                                  + String.join(", ", RootTrackerPolicy.builtIns())
                                  + "\nChanges apply only on a NEW, separately enabled DNS relay."
                                : "Filtering is OFF. No DNS or firewall change planned.";
                    } catch (Exception failed) {
                        summary = "Blocklist preview refused. Inspect or restore imported snapshot.";
                    }
                    final String display = summary;
                    runOnUiThread(() -> {
                        blocklistBusy = false;
                        if (!isFinishing() && !isDestroyed()) {
                            new AlertDialog.Builder(this).setTitle("Batch E policy preview")
                                    .setMessage(display).setPositiveButton("Close", null).show();
                        }
                    });
                }, "wonhee-blocklist-preview").start();
            } catch (IllegalArgumentException invalid) {
                new AlertDialog.Builder(this).setTitle("Tracker policy refused")
                        .setMessage("Custom domains or exceptions invalid.")
                        .setPositiveButton("Close", null).show();
            }
        });
        trackerStatus = label(trackers, "TRACKER FILTER: " + session.trackerLedgerStatus(), 14, PINK);
        label(trackers, "BATCH E.2 · DOMAIN FILTER TESTER", 15, PINK);
        label(trackers, "Check one domain against your selected offline policy. "
                + "No DNS query, browsing log or firewall change is performed. "
                + "This tests the planned settings, not necessarily the currently "
                + "running root relay: a relay keeps the snapshot loaded when it started.",
                13, MUTED);
        EditText domainToCheck = trackerTextEditor(trackers,
                "example-ad-domain.com (single domain)", "");
        domainToCheck.setSingleLine(true);
        Button testDomain = button(trackers, "Check domain rule · offline preview");
        testDomain.setOnClickListener(v -> {
            if (blocklistBusy || session.isBusy()) {
                output.setText("Another DNS/blocklist operation is running.");
                return;
            }
            final String domain = domainToCheck.getText().toString().trim();
            final boolean filter = trackerFilter.isChecked();
            final String custom = trackerCustom.getText().toString();
            final String allow = trackerAllow.getText().toString();
            if (domain.isEmpty() || domain.contains("\n") || domain.contains("\r")) {
                output.setText("Enter one plain domain without spaces or scheme.");
                return;
            }
            blocklistBusy = true;
            output.setText("Checking one domain against saved offline policy...");
            new Thread(() -> {
                String result;
                try {
                    RootTrackerPolicy.Config compiled =
                            RootTrackerPolicy.compileWithManaged(
                                    filter, custom, allow, getFilesDir());
                    result = "OFFLINE DOMAIN RULE CHECK\n" + domain + "\n"
                            + compiled.explain(domain)
                            + "\nPolicy preview only; active relay uses the policy loaded "
                            + "at its last explicit DNS activation.\nNo DNS traffic generated.";
                } catch (Exception invalid) {
                    result = "DOMAIN POLICY TEST REFUSED\n"
                            + "Saved/custom blocklist could not be compiled.";
                }
                final String report = result;
                runOnUiThread(() -> {
                    blocklistBusy = false;
                    if (!isFinishing() && !isDestroyed()) output.setText(report);
                });
            }, "wonhee-domain-rule-check").start();
        });

        label(trackers, "BATCH E.1 · MANAGED OFFLINE HOSTS LIST", 15, PINK);
        label(trackers, "Import a standard hosts.txt or one-domain-per-line file "
                + "(up to 250,000 unique domains / 20 MiB). Duplicates and local-network "
                + "names are excluded. No list is downloaded automatically. "
                + "The previous snapshot is retained for recovery. An imported "
                + "snapshot is used only when tracker blocking is selected at the "
                + "NEXT explicit encrypted system DNS activation.", 13, MUTED);
        Button importManaged = button(trackers, "Import local hosts/domain blocklist · offline");
        importManaged.setOnClickListener(v -> {
            if (!canEditBlocklist()) return;
            Intent pick = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            pick.setType("*/*");
            pick.addCategory(Intent.CATEGORY_OPENABLE);
            pick.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivityForResult(pick, REQUEST_HOSTS_IMPORT);
        });
        Button inspectManaged = button(trackers, "Inspect saved blocklist · read only");
        inspectManaged.setOnClickListener(v -> runBlocklistTask("inspect"));
        Button restoreManaged = button(trackers, "Restore previous imported blocklist");
        restoreManaged.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Restore previous offline blocklist?")
                .setMessage("Replaces the saved import with the previous validated snapshot. "
                        + "An active DNS enforcement policy must first be disabled; "
                        + "no tunnel or firewall rules are modified.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Restore", (d, w) -> runBlocklistTask("restore")).show());
        Button clearManaged = button(trackers, "Clear imported blocklist · keep backup");
        clearManaged.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Clear the imported DNS blocklist?")
                .setMessage("Removes the active imported list but preserves its previous "
                        + "snapshot. The built-in nine domains and any custom rules "
                        + "remain available. No running DNS policy is changed.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Clear import", (d, w) -> runBlocklistTask("clear")).show());
        Button sourcesManaged = button(trackers, "Browse compatible list sources");
        sourcesManaged.setOnClickListener(v -> startActivity(new Intent(Intent.ACTION_VIEW,
                Uri.parse("https://github.com/bindhosts/bindhosts/blob/master/Documentation/sources.md"))));

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
        dnsPrivacyAudit = button(enforcement,
                "Batch E.2 · Privacy Monitor and DNS coverage · read only");
        dnsPrivacyAudit.setOnClickListener(v -> run("Privacy Monitor", true,
                session::auditDnsPrivacy));
        label(enforcement, "Only DNS requests that reach Wonhee's local relay are "
                + "counted. This audit does not claim to detect independent app "
                + "DoH/DoH3 on HTTPS port 443. No DNS request names are logged.", 13, MUTED);
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
        label(failClosed, "BATCH F ACTIVATION PAUSED for safety after a connectivity "
                + "interruption. This build cannot activate its all-traffic OUTPUT "
                + "guard or send the underlay challenge. DNS-port enforcement is a "
                + "different feature. Read-only audits and exact-owned guard removal "
                + "remain available. See issue #41.", 13, PINK);
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
        failClosedEnable = button(failClosed, RootGuardSafetyGate.activationPaused()
                ? "All-traffic kill switch unavailable — safety pause"
                : "Review + enable experimental kill switch · opt in");
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
        failClosedControlPlaneReview = button(failClosed,
                "Preview firewall impact on Android network control · read only");
        failClosedControlPlaneReview.setOnClickListener(v ->
                run("Preview Batch F control-plane flow outcomes", false,
                        session::reviewGuardControlPlaneImpact));
        failClosedUnderlayChallenge = button(failClosed,
                RootGuardSafetyGate.activationPaused()
                ? "Underlay challenge unavailable — safety pause"
                : "Test IPv4 + IPv6 physical-underlay rejection · opt in");
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
        passiveHealth = button(privacy,
                "Batch F.2 · Snapshot live tunnel health · read only");
        passiveHealth.setOnClickListener(v -> run("F.2 manual passive health snapshot",
                false, session::snapshotPassiveHealth));
        passiveUnderlay = button(privacy,
                "Batch F.3d · Observe headers + OUTPUT counters · DNS must be OFF");
        passiveUnderlay.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Compare existing OUTPUT counters read only?")
                .setMessage("This is NOT the 0.15.38 direct-route advisory audit. "
                        + "It requires separate Batch D/E DNS enforcement and "
                        + "unattended recovery to be OFF; never disable working "
                        + "protection just to run this optional test. "
                        + "Batch F must remain OFF. Only after exact tunnel/route "
                        + "ownership checks, Wonhee observes up to 32 outgoing "
                        + "packet HEADERS on the current physical Wi-Fi/cellular "
                        + "interface for at most five seconds. The capture is NOT "
                        + "an Android OUTPUT-chain or UID attribution test. "
                        + "Wonhee reports only aggregate candidate counts, "
                        + "tcpdump capture status, interface TX counters, ICMPv6 "
                        + "subtypes, and before/after counters from existing "
                        + "IPv4/IPv6 OUTPUT rules. Counters may include unrelated "
                        + "traffic and cannot prove that the observed packet "
                        + "crossed OUTPUT. No counter is installed or reset. "
                        + "A quiet window is not proof of no network traffic. "
                        + "Raw addresses and packet data are not displayed or saved. "
                        + "No packets are generated, and no policies change. "
                        + "Root tcpdump + timeout must already be available.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Observe headers", (dialog, which) ->
                        run("F.3d passive underlay and OUTPUT counter observation", false,
                                session::observePhysicalControlHeaders))
                .show());
        label(privacy, "Manual on-device snapshot of verified WireGuard handshake age, "
                + "cumulative RX/TX, changed endpoint/underlay route predictions, "
                + "and exact routing ledger ownership. Repeat the button to compare "
                + "to an in-memory snapshot; no background polling, packets, DNS, "
                + "firewall or tunnel changes. Idle traffic is not a failure.", 13, MUTED);
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
        if (guidedRunning || lifecycleBusy || session.isBusy()) return;
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
        if (guidedRunning || lifecycleBusy) return;
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
            if (action.startsWith("Live peer route attribution")) {
                // Share only the compact, bounded aggregate. Never raw socket metadata.
                int detail = result.indexOf("LIVE PUBLIC PEER ROUTES");
                String compact = detail >= 0 ? result.substring(0, detail).trim()
                        : "Audit incomplete; no exportable route classification.";
                if (compact.length() > 2400) compact = compact.substring(0, 2400);
                lastRouteEvidence = compact;
                if (routeEvidenceSummary != null) {
                    routeEvidenceSummary.setText((ok ? "" : "CHECK REQUIRED\\n") + compact);
                }
                if (exportRouteEvidence != null) {
                    exportRouteEvidence.setEnabled(ok && detail >= 0);
                }
            }
            // DNS destinations/probe outcomes must not persist into diagnostics.
            journal.record("RESULT", action.startsWith("Orphan DNS")
                    || action.startsWith("Emergency DNS")
                    ? "Emergency DNS recovery "
                            + (ok ? "completed" : "check required")
                    : action.startsWith("Batch H.2a")
                    ? "Batch H.2a recovery audit/repair "
                            + (ok ? "completed" : "check required")
                    : action.startsWith("Privacy Monitor")
                    ? "Privacy Monitor read-only check " + (ok ? "verified" : "check required")
                    : action.startsWith("Product D relay lifecycle")
                    ? "Product D relay lifecycle " + (ok ? "verified" : "refused")
                    : action.startsWith("Product D DoH")
                    ? "Product D DoH probe " + (ok ? "verified" : "refused")
                    : action.startsWith("Live socket marks read-only")
                    ? "Passive socket UID/fwmark inspection "
                            + (ok ? "completed" : "incomplete")
                    : action.startsWith("Live peer route attribution")
                    ? "Bounded public peer/UID/fwmark route inspection "
                            + (ok ? "completed" : "incomplete/unverified")
                    : action.startsWith("Targeted socket mark burst")
                    ? "Manual bounded socket mark watch "
                            + (ok ? "completed" : "incomplete/cancelled")
                    : action.startsWith("Live socket marks read-only")
                    ? "Manual three-sample socket mark audit "
                            + (ok ? "completed" : "incomplete")
                    : action.startsWith("Per-app route predictions")
                    ? "Read-only per-app routing predictions "
                            + (ok ? "completed" : "check required")
                    : action.startsWith("Connectivity incident snapshot")
                    ? "Read-only Internet outage snapshot "
                            + (ok ? "verified" : "check required")
                    : action.startsWith("F.2 manual passive health")
                            ? "F.2 manual snapshot " + (ok ? "completed" : "check required")
                    : (action.startsWith("F.3b passive underlay")
                            || action.startsWith("F.3c passive underlay")
                            || action.startsWith("F.3d passive underlay"))
                            ? "F.3d anonymous header and OUTPUT counter comparison "
                                    + (ok ? "completed" : "check required")
                            : result);
            if (ok && action.startsWith("Connect multi-tunnel")
                    && wantsRootTrafficNotification() && mayDisplayRootNotifications()) {
                RootMultiTrafficNotificationService.startIfPossible(this);
            }
            // A manual disconnect may stop only ONE of several selected
            // tunnels. Keep the notification alive for remaining verified
            // links; its read-only sampler self-stops after all are gone.
            updateButtons();
        });
        updateButtons();
    }

    private void shareRouteEvidence() {
        if (lastRouteEvidence == null || lastRouteEvidence.isEmpty()
                || exportRouteEvidence == null || !exportRouteEvidence.isEnabled()) {
            return;
        }
        // User-initiated sharing only; does not create any persistent report.
        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType("text/plain");
        send.putExtra(Intent.EXTRA_SUBJECT, "Wonhee read-only route summary");
        send.putExtra(Intent.EXTRA_TEXT, lastRouteEvidence
                + "\\nPredictions only; not evidence of packet egress.");
        startActivity(Intent.createChooser(send, "Share route summary"));
    }

    private boolean canEditBlocklist() {
        if (blocklistBusy || session.isBusy()) {
            output.setText("A DNS or blocklist operation is still running.");
            return false;
        }
        if (!"OFF".equals(session.dnsLedgerStatus())) {
            output.setText("Disable + audit owned DNS enforcement before changing imported lists.");
            return false;
        }
        return true;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_HOSTS_IMPORT
                || resultCode != RESULT_OK || data == null || data.getData() == null) return;
        if (!canEditBlocklist()) return;
        final Uri selected = data.getData();
        blocklistBusy = true;
        output.setText("Validating local HOSTS/domain file. No DNS or routing changes...");
        new Thread(() -> {
            String report;
            try {
                if (!"OFF".equals(session.dnsLedgerStatus()) || session.isBusy()) {
                    throw new IllegalStateException("DNS policy changed; refusing import.");
                }
                try (InputStream in = getContentResolver().openInputStream(selected)) {
                    RootBlocklistStore.Snapshot saved = RootBlocklistStore.importFrom(
                            getFilesDir(), in);
                    report = "BATCH E.1 IMPORT SUCCESS\n" + saved.summary()
                            + "\nPrevious snapshot retained where available."
                            + "\nEnable tracker filtering only on the next explicit DNS activation.";
                }
            } catch (Exception failed) {
                report = "BATCH E.1 IMPORT REFUSED\nNo active DNS policy modified."
                        + "\nCheck that the file uses HOSTS or plain-domain syntax, "
                        + "is <=20 MiB and has <=250,000 unique domains.";
            }
            final String display = report;
            runOnUiThread(() -> {
                blocklistBusy = false;
                if (!isFinishing() && !isDestroyed()) output.setText(display);
            });
        }, "wonhee-blocklist-import").start();
    }

    private void runBlocklistTask(String operation) {
        if (!canEditBlocklist()) return;
        blocklistBusy = true;
        output.setText("Local blocklist " + operation + "...");
        new Thread(() -> {
            String report;
            try {
                if (!"OFF".equals(session.dnsLedgerStatus()) || session.isBusy()) {
                    throw new IllegalStateException("DNS policy changed; no list mutation allowed.");
                }
                switch (operation) {
                    case "inspect": {
                        RootBlocklistStore.Snapshot current =
                                RootBlocklistStore.current(getFilesDir());
                        RootBlocklistStore.Snapshot old =
                                RootBlocklistStore.previous(getFilesDir());
                        report = "MANAGED DNS LIST\nActive: "
                                + (current == null ? "NONE" : current.summary())
                                + "\nPrevious: " + (old == null ? "NONE" : old.summary())
                                + "\nNo DNS changes made.";
                        break;
                    }
                    case "restore": {
                        RootBlocklistStore.Snapshot restored =
                                RootBlocklistStore.restorePrevious(getFilesDir());
                        report = "PREVIOUS HOSTS LIST RESTORED\n" + restored.summary()
                                + "\nChanges apply only on next DNS activation.";
                        break;
                    }
                    case "clear":
                        RootBlocklistStore.clear(getFilesDir());
                        report = "IMPORTED HOSTS LIST CLEARED\nBuilt-ins remain available; "
                                + "previous snapshot preserved for restore.";
                        break;
                    default: throw new IllegalArgumentException("Unknown list operation.");
                }
            } catch (Exception failed) {
                report = "Blocklist operation REFUSED. "
                        + "Check saved snapshot and ensure DNS enforcement is OFF.";
            }
            final String display = report;
            runOnUiThread(() -> {
                blocklistBusy = false;
                if (!isFinishing() && !isDestroyed()) output.setText(display);
            });
        }, "wonhee-blocklist-" + operation).start();
    }

    private boolean wantsRootTrafficNotification() {
        return getSharedPreferences(ROOT_NOTIFICATION_PREFS, Context.MODE_PRIVATE)
                .getBoolean("enabled", false);
    }

    private boolean mayDisplayRootNotifications() {
        return Build.VERSION.SDK_INT < 33
                || checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)
                    == PackageManager.PERMISSION_GRANTED;
    }

    private void toggleRootTrafficNotification() {
        if (wantsRootTrafficNotification()) {
            getSharedPreferences(ROOT_NOTIFICATION_PREFS, Context.MODE_PRIVATE)
                    .edit().putBoolean("enabled", false).apply();
            RootMultiTrafficNotificationService.stop(this);
            output.setText("Optional root traffic notification disabled. "
                    + "VPN, DNS and routing are unchanged.");
            updateRootTrafficNotificationUi();
            return;
        }
        if (!mayDisplayRootNotifications()) {
            requestPermissions(new String[]{
                android.Manifest.permission.POST_NOTIFICATIONS
            }, REQUEST_ROOT_NOTIFICATION);
            return;
        }
        enableRootTrafficNotification();
    }

    private void enableRootTrafficNotification() {
        getSharedPreferences(ROOT_NOTIFICATION_PREFS, Context.MODE_PRIVATE)
                .edit().putBoolean("enabled", true).apply();
        RootMultiTrafficNotificationService.startIfPossible(this);
        output.setText("Root notification requested. Shows verified tunnel speeds "
                + "and live DNS blocked replies only while kernel tunnels are active. "
                + "Android may restrict foreground notifications; check app permissions "
                + "if it does not appear. No network changes.");
        updateRootTrafficNotificationUi();
    }

    private void updateRootTrafficNotificationUi() {
        if (rootTrafficNotificationButton == null) return;
        rootTrafficNotificationButton.setText(wantsRootTrafficNotification()
                ? "Disable root tunnel speed notification"
                : "Enable root tunnel speed + blocked-request notification");
    }

    @Override public void onRequestPermissionsResult(int requestCode,
            String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != REQUEST_ROOT_NOTIFICATION) return;
        if (grantResults.length > 0
                && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            enableRootTrafficNotification();
        } else {
            output.setText("Notification permission denied. Your root VPN "
                    + "and DNS configuration remain unchanged.");
            updateRootTrafficNotificationUi();
        }
    }

    private void finishManagedLifecycle(boolean ok, String message) {
        lifecycleBusy = false;
        output.setText((ok ? "COMPLETE\n" : "CHECK REQUIRED\n") + message);
        // Avoid persisting upstream addresses, domains, public keys, or raw
        // diagnostics in the session journal.
        journal.record("RESULT", "Batch H.1 managed lifecycle "
                + (ok ? "verified complete" : "requires user audit"));
        updateButtons();
    }

    private void rollbackFailedStart(List<SecureTunnelProfileStore.Profile> chosen,
            String stage, String reason) {
        output.setText("Batch H.1 start failed at " + stage
                + ". Attempting exact owned-rule cleanup and verified tunnel stop...");
        // The DNS worker returns a verified, non-secret failure phase. The
        // original full-stack rollback threw that evidence away, leaving only
        // "START FAILED AT DNS" and making safe diagnosis impossible.
        final String safeDetail = "DNS".equals(stage)
                ? RootDnsStartFailure.summary(reason)
                : "Review the stage-specific read-only audit before another start.";
        session.stopManagedStack(chosen, (ok, result) ->
                finishManagedLifecycle(false,
                        "START FAILED AT " + stage + "\n"
                        + safeDetail + "\n"
                        + (ok ? "Automatic safety rollback succeeded.\n"
                              : "Automatic rollback PAUSED; owned rules may remain.\n")
                        + result + "\n"
                        + "No all-traffic kill switch is installed; device connectivity "
                        + "may resume outside the VPN after disconnect."));
    }

    private void startManagedStack() {
        if (lifecycleBusy || guidedRunning || blocklistBusy || session.isBusy()) {
            output.setText("Another Wonhee operation is active."); return;
        }
        List<SecureTunnelProfileStore.Profile> chosen = selected();
        if (chosen.isEmpty()) {
            output.setText("Select the HOME and Internet profiles first."); return;
        }
        Object dnsChoice = dohTunnel == null ? null : dohTunnel.getSelectedItem();
        String dnsName = dnsChoice == null ? "" : dnsChoice.toString();
        boolean foundDns = false;
        for (SecureTunnelProfileStore.Profile profile : chosen) {
            if (profile.name.equals(dnsName)) foundDns = true;
        }
        if (!foundDns) {
            output.setText("Select a checked Internet tunnel as the DNS upstream."); return;
        }
        if (!"OFF".equals(session.guardLedgerStatus())
                || !"OFF".equals(session.dnsLedgerStatus())) {
            output.setText("Existing guard/DNS ownership: audit and disable before start."); return;
        }
        final String protocol = currentDnsProtocol();
        final String endpoint = dohUrl.getText().toString();
        final String bootstrap = dohBootstrap.getText().toString();
        final boolean filter = trackerFilter.isChecked();
        final String custom = trackerCustom.getText().toString();
        final String allow = trackerAllow.getText().toString();
        try {
            RootDnsProbePolicy.parse(protocol, endpoint, bootstrap);
        } catch (Exception refused) {
            output.setText("DNS upstream configuration is invalid. No changes made.");
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Start tunnels, routing and encrypted DNS?")
                .setMessage("Batch H.1 will first require a clean ownership state, "
                        + "then connect the selected kernel WireGuard tunnels, install "
                        + "the exact HOME split routes, and activate the selected "
                        + protocol.toUpperCase(java.util.Locale.ROOT)
                        + " encrypted DNS relay with tracker filtering "
                        + (filter ? "ON" : "OFF") + ". It will verify owned DNS rules. "
                        + "If a stage fails after connecting, Wonhee attempts an "
                        + "automatic exact-owned rollback and disconnect. "
                        + "Normal Wi-Fi/cellular traffic may then resume: this is NOT "
                        + "a zero-leak kill switch. Set Android Private DNS OFF, "
                        + "disable Batch C auto-recovery, and keep USB ADB available.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Start full stack", (dialog, which) -> {
                    saveTrackerOptions();
                    lifecycleBusy = true;
                    output.setText("BATCH H.1 — START PREFLIGHT (read only)...");
                    updateButtons();
                    session.preflightManagedStart(chosen, (preflightOk, preflight) -> {
                        if (!preflightOk) {
                            finishManagedLifecycle(false, preflight); return;
                        }
                        output.setText("START 1/4 — connecting verified kernel tunnels...");
                        session.connect(chosen, (connected, connectReport) -> {
                            if (!connected) {
                                // The existing tunnel connect method already attempts
                                // exact identity-verified rollback on failure.
                                finishManagedLifecycle(false,
                                        "Connection stage refused.\n" + connectReport);
                                return;
                            }
                            output.setText("START 2/4 — installing owned HOME split routes...");
                            session.applyRouting(chosen, (routed, routeReport) -> {
                                if (!routed) {
                                    rollbackFailedStart(chosen, "ROUTING", routeReport);
                                    return;
                                }
                                output.setText("START 3/4 — activating encrypted DNS...");
                                session.enableRootDns(chosen, dnsName, protocol, endpoint,
                                        bootstrap, filter, custom, allow, (dnsOk, dnsReport) -> {
                                    if (!dnsOk) {
                                        rollbackFailedStart(chosen, "DNS", dnsReport);
                                        return;
                                    }
                                    output.setText("START 4/4 — auditing owned DNS rules...");
                                    session.auditRootDns(chosen, (auditOk, auditReport) -> {
                                        if (!auditOk) {
                                            rollbackFailedStart(chosen,
                                                    "FINAL_DNS_AUDIT", auditReport);
                                        } else {
                                            if (wantsRootTrafficNotification()
                                                    && mayDisplayRootNotifications()) {
                                                RootMultiTrafficNotificationService.startIfPossible(this);
                                            }
                                            finishManagedLifecycle(true,
                                                    "BATCH H.1 FULL STACK STARTED\n"
                                                    + "WireGuard tunnels: verified UP\n"
                                                    + "HOME split-route correction: installed\n"
                                                    + "DNS: encrypted relay and owned rules VERIFIED\n"
                                                    + "Tracker filtering: "
                                                    + (filter ? "ON" : "OFF") + "\n"
                                                    + "One-tap Safe stop is available. "
                                                    + "No boot autostart or all-traffic kill switch.");
                                        }
                                    });
                                });
                            });
                        });
                    });
                }).show();
    }

    private void prepareForUpdate() {
        if (lifecycleBusy || guidedRunning || blocklistBusy || session.isBusy()) {
            output.setText("A Wonhee operation is in progress. Update not ready.");
            return;
        }
        List<SecureTunnelProfileStore.Profile> chosen = selected();
        if (chosen.isEmpty()) {
            output.setText("Select ALL active Wonhee tunnel profiles, then prepare for update.");
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Safe Stop before updating Wonhee?")
                .setMessage("This will manually stop unattended recovery, verify selected "
                        + "WireGuard identities, remove only exactly owned DNS interception "
                        + "and split routes, and disconnect the selected kernel tunnels. "
                        + "A second independent read-only lifecycle audit MUST report "
                        + "CLEAN_STOPPED to mark the update as ready. If any stage fails, "
                        + "the update remains BLOCKED; no unknown rules will be flushed. "
                        + "Mobile data or Wi-Fi may work without VPN protection after "
                        + "shutdown. Keep USB ADB available.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Safe Stop + verify", (dialog, which) -> {
                    lifecycleBusy = true;
                    updateButtons();
                    output.setText("UPDATE PREPARATION — identity-verified safe stop...");
                    session.stopManagedStack(chosen, (stopped, result) -> {
                        if (!stopped) {
                            finishManagedLifecycle(false,
                                    "UPDATE BLOCKED — Safe Stop did not finish.\n" + result);
                            return;
                        }
                        output.setText("UPDATE PREPARATION — independent stopped-state audit...");
                        session.verifyUpdateReadiness(chosen, (ready, audit) -> {
                            if (ready) RootMultiTrafficNotificationService.stop(this);
                            finishManagedLifecycle(ready,
                                    (ready ? "UPDATE PREPARED — use guarded Fedora installer.\n"
                                            : "UPDATE BLOCKED — do NOT install.\n")
                                    + result + "\n" + audit);
                        });
                    });
                }).show();
    }

    private void stopManagedStack() {
        if (lifecycleBusy || guidedRunning || blocklistBusy || session.isBusy()) {
            output.setText("Another Wonhee operation is active."); return;
        }
        List<SecureTunnelProfileStore.Profile> chosen = selected();
        if (chosen.isEmpty()) {
            output.setText("Select every active Wonhee profile before safe stop."); return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Safely stop the complete Wonhee stack?")
                .setMessage("Wonhee will persist manual stop of unattended recovery, "
                        + "verify selected WireGuard identities, remove ONLY the "
                        + "exact recorded DNS rules and split-routing overrides, "
                        + "then disconnect selected tunnels after verifying cleanup. "
                        + "Incomplete or foreign ownership makes it stop safely "
                        + "without flushing unrelated firewall rules. "
                        + "Normal Wi-Fi/cellular traffic may resume; keep USB ADB available.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Safe stop", (dialog, which) -> {
                    lifecycleBusy = true;
                    updateButtons();
                    output.setText("BATCH H.1 — safe stop in progress...");
                    session.stopManagedStack(chosen,
                            (ok, result) -> {
                                if (ok) RootMultiTrafficNotificationService.stop(this);
                                finishManagedLifecycle(ok, result);
                            });
                }).show();
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
        updateRootTrafficNotificationUi();
        boolean idle = !session.isBusy() && !guidedRunning && !lifecycleBusy;
        boolean ready = idle && !selected().isEmpty();
        boolean firewallUnlocked = "OFF".equals(session.guardLedgerStatus());
        for (CheckBox checkbox : selection.values()) checkbox.setEnabled(idle);
        if (connect != null) connect.setEnabled(ready && firewallUnlocked);
        if (disconnect != null) disconnect.setEnabled(ready && firewallUnlocked
                && "OFF".equals(session.dnsLedgerStatus()));
        if (managedStart != null) managedStart.setEnabled(ready && firewallUnlocked
                && "OFF".equals(session.dnsLedgerStatus()));
        if (managedStop != null) managedStop.setEnabled(ready && firewallUnlocked);
        if (prepareUpdate != null) prepareUpdate.setEnabled(ready && firewallUnlocked);
        if (emergencyDnsOff != null) emergencyDnsOff.setEnabled(idle
                && !"OFF".equals(session.dnsLedgerStatus()));
        if (orphanDnsAudit != null) orphanDnsAudit.setEnabled(idle);
        if (orphanDnsRepair != null) orphanDnsRepair.setEnabled(idle);
        if (lifecycleAudit != null) lifecycleAudit.setEnabled(idle);
        if (lifecycleRepair != null) lifecycleRepair.setEnabled(idle);
        if (preview != null) preview.setEnabled(ready);
        if (inspect != null) inspect.setEnabled(idle);
        if (internetIncidentAudit != null) internetIncidentAudit.setEnabled(ready);
        if (perAppAudit != null) perAppAudit.setEnabled(ready);
        if (liveSocketAudit != null) liveSocketAudit.setEnabled(ready);
        if (socketBurstAudit != null) socketBurstAudit.setEnabled(ready);
        if (livePeerAudit != null) livePeerAudit.setEnabled(ready);
        if (socketBurstCancel != null) socketBurstCancel.setEnabled(
                session.isSocketBurstActive());
        if (audit != null) audit.setEnabled(ready);
        if (apply != null) apply.setEnabled(ready && firewallUnlocked);
        if (recover != null) recover.setEnabled(ready && firewallUnlocked);
        if (guardReadiness != null) guardReadiness.setEnabled(ready);
        if (dnsAudit != null) dnsAudit.setEnabled(ready);
        if (transportAudit != null) transportAudit.setEnabled(ready);
        if (passiveHealth != null) passiveHealth.setEnabled(ready);
        if (passiveUnderlay != null) passiveUnderlay.setEnabled(ready);
        if (serviceProbe != null) serviceProbe.setEnabled(ready);
        if (packetObserve != null) packetObserve.setEnabled(ready);
        if (guardModel != null) guardModel.setEnabled(ready);
        if (remove != null) remove.setEnabled(idle && firewallUnlocked);
        if (enableRecovery != null) enableRecovery.setEnabled(ready && firewallUnlocked);
        if (checkRecovery != null) checkRecovery.setEnabled(idle && firewallUnlocked);
        if (dohProbe != null) dohProbe.setEnabled(ready);
        if (rootDohProbe != null) rootDohProbe.setEnabled(ready);
        if (relayLifecycleProbe != null) relayLifecycleProbe.setEnabled(ready);
        if (dohTunnel != null) dohTunnel.setEnabled(idle);
        if (dnsProtocol != null) dnsProtocol.setEnabled(idle);
        if (dohUrl != null) dohUrl.setEnabled(idle);
        if (dohBootstrap != null) dohBootstrap.setEnabled(idle);
        if (dnsEnable != null) dnsEnable.setEnabled(ready && firewallUnlocked
                && "OFF".equals(session.dnsLedgerStatus()));
        if (dnsDisable != null) dnsDisable.setEnabled(idle && !"OFF".equals(session.dnsLedgerStatus()));
        if (dnsEnforcementAudit != null) dnsEnforcementAudit.setEnabled(idle);
        if (dnsPrivacyAudit != null) dnsPrivacyAudit.setEnabled(idle);
        if (dnsEnforcementStatus != null) {
            dnsEnforcementStatus.setText("DNS POLICY LEDGER: " + session.dnsLedgerStatus());
        }
        if (failClosedEnable != null) failClosedEnable.setEnabled(ready
                && !RootGuardSafetyGate.activationPaused()
                && "OFF".equals(session.guardLedgerStatus())
                && "OFF".equals(session.dnsLedgerStatus()));
        if (failClosedAudit != null) failClosedAudit.setEnabled(idle);
        if (failClosedGuidedTest != null) failClosedGuidedTest.setEnabled(ready);
        if (failClosedControlPlaneReview != null) failClosedControlPlaneReview.setEnabled(ready);
        if (failClosedUnderlayChallenge != null) failClosedUnderlayChallenge.setEnabled(ready
                && !RootGuardSafetyGate.activationPaused()
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
