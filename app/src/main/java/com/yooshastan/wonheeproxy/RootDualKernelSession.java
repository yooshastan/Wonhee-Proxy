package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

import com.wireguard.android.backend.Statistics;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.android.backend.WgQuickBackend;
import com.wireguard.android.util.RootShell;
import com.wireguard.android.util.ToolsInstaller;
import com.wireguard.config.Config;
import com.wireguard.config.InetNetwork;
import com.wireguard.config.Peer;
import com.wireguard.crypto.Key;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Explicit, rooted-only experiment. Does not create a VpnService and does not
 * change the original GoBackend/Always-on connection. Every root call is off
 * the UI thread. The two kernel interfaces have distinct WireGuard identities.
 *
 * No fail-closed or reboot persistence claim: a kernel interface may outlive
 * the app process, and a partially configured route is a test failure.
 */
final class RootDualKernelSession {
    interface Callback { void completed(boolean success, String message); }
    interface StatusCallback { void completed(String message); }

    private static RootDualKernelSession instance;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Context application;
    private final File appCacheDir;
    private final RootShell rootShell;
    private final ToolsInstaller tools;
    private final WgQuickBackend backend;
    private final Tunnel home = new NamedTunnel("wnhome0");
    private final Tunnel europe = new NamedTunnel("wnair0");
    private volatile boolean busy;
    private volatile boolean managing;
    private volatile boolean missingKernelVersionNode;
    private volatile String lastPreflightStep = "kernel support";
    private Config startedHome;
    private Config startedEurope;
    private final TunnelTrafficHistory homeTraffic = new TunnelTrafficHistory();
    private final TunnelTrafficHistory airTraffic = new TunnelTrafficHistory();

    private static final class KernelCommandException extends Exception {
        final int exitCode;
        KernelCommandException(int exitCode) { this.exitCode = exitCode; }
    }

    private static final class NamedTunnel implements Tunnel {
        private final String name;
        NamedTunnel(String name) { this.name = name; }
        @Override public String getName() { return name; }
        @Override public void onStateChange(State state) { }
    }

    private RootDualKernelSession(Context context) {
        Context app = context.getApplicationContext();
        application = app;
        appCacheDir = app.getCacheDir();
        rootShell = new RootShell(app);
        tools = new ToolsInstaller(app, rootShell);
        backend = new WgQuickBackend(app, rootShell, tools);
        backend.setMultipleTunnels(true);
    }

    static synchronized RootDualKernelSession get(Context context) {
        if (instance == null) instance = new RootDualKernelSession(context);
        return instance;
    }

    boolean isBusy() { return busy; }
    boolean isManagingPair() { return managing; }

    private boolean begin(Callback callback) {
        synchronized (this) {
            if (busy) {
                main.post(() -> callback.completed(false, "Root experiment is already busy."));
                return false;
            }
            busy = true;
            return true;
        }
    }

    private void finish(Callback callback, boolean success, String message) {
        busy = false;
        main.post(() -> callback.completed(success, message));
    }

    private void prepareRoot() throws Exception {
        lastPreflightStep = "kernel support";
        if (!WgQuickBackend.hasKernelSupport()) {
            throw new IllegalStateException("Kernel WireGuard support was not detected.");
        }
        lastPreflightStep = "Magisk root grant";
        rootShell.start(); // Magisk must explicitly grant Wonhee root access.
        lastPreflightStep = "bundled WireGuard tools";
        tools.ensureToolsAvailable();
        // Some Android builds provide WireGuard built into the kernel without
        // /sys/module/wireguard/version. The upstream WgQuickBackend insists on
        // `cat .../version && wg-quick up`; if the version file is absent,
        // invoke the same bundled wg-quick directly instead of failing early.
        missingKernelVersionNode = rootShell.run(null,
                "test -r /sys/module/wireguard/version") != 0;
        lastPreflightStep = "wg executable";
        if (rootShell.run(null, "wg --version >/dev/null 2>&1") != 0) {
            throw new IllegalStateException("Bundled wg executable could not run.");
        }
        lastPreflightStep = "ready";
    }

    /** Use upstream kernel backend when possible; bypass only its version-file gate. */
    private void setKernelState(Tunnel tunnel, Tunnel.State state, Config config) throws Exception {
        if (!missingKernelVersionNode) {
            backend.setState(tunnel, state, config);
            return;
        }
        if (config == null) throw new IllegalStateException("Missing test configuration.");
        File configFile = new File(new File(appCacheDir, "tmp"),
                tunnel.getName() + ".conf");
        // The app-private cache parent is mode 0700; the temporary file is
        // removed after the root command, whether that command succeeds or not.
        try {
            try (FileOutputStream stream = new FileOutputStream(configFile, false)) {
                stream.write(config.toWgQuickString().getBytes(StandardCharsets.UTF_8));
            }
            final String operation = state == Tunnel.State.UP ? "up" : "down";
            final String path = configFile.getAbsolutePath();
            if (path.contains("'")) throw new IllegalStateException("Unsafe file path.");
            int result = rootShell.run(null, "wg-quick " + operation + " '" + path + "'");
            if (result != 0) throw new KernelCommandException(result);
        } finally {
            //noinspection ResultOfMethodCallIgnored
            configFile.delete();
        }
    }


    void checkRoot(Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            try {
                prepareRoot();
                ok = true;
            } catch (Exception | LinkageError ignored) {
                // Never return exception text: root commands can contain config data.
            }
            finish(callback, ok, ok
                    ? "Root and tools ready; kernel mode: "
                        + (missingKernelVersionNode ? "built-in compatibility" : "upstream wg-quick")
                        + ". Routing not yet tested."
                    : "Root preflight failed at: " + lastPreflightStep
                        + ". Check the Magisk grant and bundled tools.");
        });
    }

    /** Read-only checks for possible firewall backends; never installs a kill-switch rule. */
    void checkFirewallCapabilities(Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            String result;
            boolean ready = false;
            try {
                prepareRoot();
                boolean ipv4 = rootShell.run(null,
                        "iptables -w -L OUTPUT -n >/dev/null 2>&1") == 0;
                boolean ipv6 = rootShell.run(null,
                        "ip6tables -w -L OUTPUT -n >/dev/null 2>&1") == 0;
                boolean nft = rootShell.run(null,
                        "nft list ruleset >/dev/null 2>&1") == 0;
                boolean rules = rootShell.run(null,
                        "ip -4 rule show >/dev/null 2>&1") == 0
                        && rootShell.run(null,
                        "ip -6 rule show >/dev/null 2>&1") == 0;
                ready = ipv4 && ipv6 && rules;
                result = "Read-only firewall capability check: IPv4 iptables "
                        + (ipv4 ? "available" : "unavailable") + ", IPv6 ip6tables "
                        + (ipv6 ? "available" : "unavailable") + ", nft "
                        + (nft ? "available" : "unavailable") + ", policy routing "
                        + (rules ? "available" : "unavailable") + ". "
                        + "NO kill-switch rules installed. Capabilities alone do not prove "
                        + "fail-closed behavior; app crash, endpoint UDP, DNS, and reboot "
                        + "still need device-specific validation.";
            } catch (Exception | LinkageError ignored) {
                result = "Firewall capability check failed at root preflight or tool inspection. "
                        + "No firewall rules were changed.";
            }
            finish(callback, ready, result);
        });
    }

    /**
     * No-write readiness gate for an eventual iptables/ip6tables fail-closed
     * guard. We must know how both WireGuard UDP transports are exempted before
     * adding any OUTPUT hooks; otherwise we could break tunnel recovery.
     */
    void checkGuardReadiness(Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ready = false;
            String result;
            try {
                prepareRoot();
                boolean interfaces = backend.getState(home) == Tunnel.State.UP
                        && backend.getState(europe) == Tunnel.State.UP;
                boolean v4 = rootShell.run(null, "iptables -w -L OUTPUT -n >/dev/null 2>&1") == 0;
                boolean v6 = rootShell.run(null, "ip6tables -w -L OUTPUT -n >/dev/null 2>&1") == 0;
                boolean mark4 = rootShell.run(null, "iptables -m mark -h >/dev/null 2>&1") == 0;
                boolean mark6 = rootShell.run(null, "ip6tables -m mark -h >/dev/null 2>&1") == 0;
                // Refuse to reuse possibly foreign or orphaned rule chains.
                boolean reserved4 = rootShell.run(null,
                        "iptables -w -S WN_GUARD4 >/dev/null 2>&1") == 0;
                boolean reserved6 = rootShell.run(null,
                        "ip6tables -w -S WN_GUARD6 >/dev/null 2>&1") == 0;
                List<String> homeMarkOutput = new ArrayList<>();
                List<String> airMarkOutput = new ArrayList<>();
                boolean homeMarkRead = rootShell.run(homeMarkOutput,
                        "wg show wnhome0 fwmark") == 0;
                boolean airMarkRead = rootShell.run(airMarkOutput,
                        "wg show wnair0 fwmark") == 0;
                long homeMark = homeMarkRead
                        ? RootFirewallMark.parse(homeMarkOutput) : 0;
                long airMark = airMarkRead
                        ? RootFirewallMark.parse(airMarkOutput) : 0;
                boolean marks = RootFirewallMark.distinctNonzero(homeMark, airMark);
                boolean androidProtectMark = RootFirewallMark.sharedAndroidProtectBit(
                        homeMark, airMark);
                // Split-only wg-quick interfaces often have no fwmark. A
                // resolved Home endpoint is a possible future *explicit* UDP
                // exemption, not evidence that an exemption exists today.
                List<String> homeEndpointOutput = new ArrayList<>();
                boolean homeEndpoint = rootShell.run(homeEndpointOutput,
                        "wg show wnhome0 endpoints") == 0
                        && RootWireGuardEndpoint.hasSingleNumericEndpoint(homeEndpointOutput);
                List<String> internetEndpointOutput = new ArrayList<>();
                boolean internetEndpoint = rootShell.run(internetEndpointOutput,
                        "wg show wnair0 endpoints") == 0
                        && RootWireGuardEndpoint.hasSingleNumericEndpoint(internetEndpointOutput);
                boolean publicRoutes = routeUses("1.1.1.1", false, europe.getName())
                        && routeUses("2606:4700:4700::1111", true, europe.getName());
                ready = interfaces && v4 && v6 && mark4 && mark6 && marks
                        && homeEndpoint && internetEndpoint && publicRoutes
                        && !reserved4 && !reserved6;
                boolean homeExemptionCandidate = homeMark == 0 && homeEndpoint && airMark > 0;
                String verdict = androidProtectMark ? "ANDROID SHARED MARK — DO NOT ARM"
                        : ready ? "PRECHECK PASS"
                        : homeExemptionCandidate ? "HOME ENDPOINT EXEMPTION NEEDED" : "NOT READY";
                result = "KERNEL GUARD READINESS: " + verdict
                        + "\nBoth kernel interfaces UP: " + (interfaces ? "YES" : "NO")
                        + "\nIPv4/IPv6 OUTPUT readable: " + (v4 && v6 ? "YES" : "NO")
                        + "\nIPv4/IPv6 mark-match userspace support: " + (mark4 && mark6 ? "YES" : "NO")
                        + "\nHome transport mark: " + (homeMark > 0 ? "SET" :
                                homeMarkRead ? "OFF OR INVALID" : "QUERY FAILED")
                        + (homeMark > 0 ? " (0x" + Long.toHexString(homeMark) + ")" : "")
                        + "\nAirVPN transport mark: " + (airMark > 0 ? "SET" :
                                airMarkRead ? "OFF OR INVALID" : "QUERY FAILED")
                        + (airMark > 0 ? " (0x" + Long.toHexString(airMark) + ")" : "")
                        + "\nDistinct nonzero WireGuard transport marks: " + (marks ? "YES" : "NO")
                        + "\nAndroid shared protectedFromVpn mark (0x20000): "
                        + (androidProtectMark ? "YES — not a safe sole exemption" : "NO")
                        + "\nHome peer has a resolved numeric UDP endpoint: "
                        + (homeEndpoint ? "YES" : "NO")
                        + "\nInternet peer has a resolved numeric UDP endpoint: "
                        + (internetEndpoint ? "YES" : "NO")
                        + "\nPublic IPv4/IPv6 root routes select wnair0: "
                        + (publicRoutes ? "YES" : "NO")
                        + "\nReserved rule-chain collision: " + (reserved4 || reserved6 ? "YES" : "NO")
                        + "\nA Home split tunnel may correctly have no fwmark. "
                        + "It would need an independently tested endpoint transport exemption."
                        + "\nBoth numeric UDP endpoints are only candidates for future "
                        + "narrow firewall exemptions. Endpoint rotation, Wi-Fi/cellular "
                        + "handoff and app socket marks still need testing."
                        + (androidProtectMark ? "\nThe shared 0x20000 bit also marks other "
                            + "Android VPN-protected traffic. Do NOT allow all packets with this "
                            + "mark through a kill switch." : "")
                        + "\nNO firewall rules installed or modified. A precheck pass does "
                        + "NOT prove the mark exemptions work, DNS isolation, crash cleanup, "
                        + "or fail-closed behavior. Actual enforcement remains disabled.";
            } catch (Exception | LinkageError ignored) {
                result = "Kernel guard readiness could not be checked. "
                        + "No firewall rules were changed.";
            }
            finish(callback, ready, result);
        });
    }

    /** Profile DNS route audit only; Android/DoH/DoQ resolver behavior is NOT covered. */
    void checkInternetDnsRoutes(SecureTunnelProfileStore.Profile internetProfile,
                                Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean passed = false;
            String result;
            try {
                Config config = parseRuntime(internetProfile);
                Set<InetAddress> servers = config.getInterface().getDnsServers();
                if (servers.isEmpty()) {
                    result = "Internet profile has no DNS servers. Choose imported or "
                            + "custom DNS in profile settings. Android DNS is not verified.";
                } else {
                    prepareRoot();
                    int matched = 0;
                    for (InetAddress server : servers) {
                        String host = server.getHostAddress(); // Numeric from parsed config.
                        String cmd = (server instanceof Inet4Address ? "ip -4" : "ip -6")
                                + " route get '" + host + "'";
                        List<String> output = new ArrayList<>();
                        if (rootShell.run(output, cmd) != 0) continue;
                        for (String line : output) {
                            if (line.contains(" dev " + europe.getName() + " ")
                                    || line.endsWith(" dev " + europe.getName())) {
                                matched++;
                                break;
                            }
                        }
                    }
                    passed = matched == servers.size();
                    result = matched + "/" + servers.size()
                            + " configured Internet DNS routes select wnair0 for root "
                            + "lookups. This does NOT prove Android app DNS, encrypted DNS, "
                            + "or leak prevention; independent traffic testing is required.";
                }
            } catch (Exception | LinkageError ignored) {
                result = "Could not audit configured DNS routes. No settings were changed.";
            }
            finish(callback, passed, result);
        });
    }

    /**
     * Save a per-profile resolver choice in the encrypted profile store.
     * The imported .conf remains untouched and the active kernel pair is never
     * changed. Android resolver behavior in root mode is NOT controlled here.
     */
    void saveInternetDnsPolicy(SecureTunnelProfileStore.Profile profile,
                               int preset, String custom, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean savedPolicy = false;
            String result;
            try {
                if (managing) {
                    result = "Stop the active kernel pair before changing DNS policy. "
                            + "No settings were saved.";
                } else {
                    boolean override = VpnDnsPresets.isOverride(preset);
                    String dns = VpnDnsPresets.addresses(preset, custom);
                    SecureTunnelProfileStore.Profile updated = new SecureTunnelProfileStore.Profile(
                            profile.name, profile.configuration, profile.routeMode,
                            profile.homeRoutes, override, dns, profile.role);
                    // Test that numeric DNS addresses are valid and reachable through
                    // this profile's AllowedIPs before writing any encrypted data.
                    parseRuntime(updated);
                    new SecureTunnelProfileStore(application).save(updated);
                    savedPolicy = true;
                    result = (override ? "Saved Internet DNS policy for next tunnel start: "
                            + VpnDnsPresets.LABELS[preset] + ". "
                            : "Restored imported DNS for the next tunnel start. ")
                            + "Imported .conf and running interfaces were not modified. "
                            + "Provider-side filtering, Android app DNS and leak prevention "
                            + "must be tested independently.";
                }
            } catch (Exception | LinkageError ignored) {
                result = "DNS policy not saved. Check that selected numeric resolver IPs "
                        + "are valid and included in the Internet profile AllowedIPs. "
                        + "No running interfaces were changed.";
            }
            finish(callback, savedPolicy, result);
        });
    }

    /** Read-only route selection for one explicitly validated private home IP. */
    void checkHomeServiceRoute(String homeIp, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            String result;
            try {
                // Reuse the strict private-IPv4 parser, ignoring the dummy TCP port.
                PrivateIpv4Target.parse(homeIp, "1");
                String numericIp = homeIp.trim();
                prepareRoot();
                boolean viaHome = routeUses(numericIp, false, home.getName());
                ok = viaHome;
                result = "HOME ROUTE CHECK: " + (viaHome ? "EXPECTED ROUTE" : "ROUTE MISMATCH")
                        + "\nDestination: " + numericIp
                        + "\nRoot route selects wnhome0: " + (viaHome ? "YES" : "NO")
                        + "\nThis does NOT test TCP connectivity or whether a specific "
                        + "Android app uses this route. No routes were changed.";
            } catch (IllegalArgumentException invalid) {
                result = "Enter a numeric private IPv4 home service address, "
                        + "such as 10.0.0.169. No route was changed.";
            } catch (Exception | LinkageError ignored) {
                result = "Could not query the selected Home service route. "
                        + "Check root grant and network state; nothing was modified.";
            }
            finish(callback, ok, result);
        });
    }

    /**
     * Read-only regression audit for the two expected kernel routing domains.
     * Android may attach per-socket fwmarks, so these root route observations
     * must never be presented as proof of app isolation or fail-closed policy.
     */
    void auditCurrentRoutes(SecureTunnelProfileStore.Profile homeProfile,
                            SecureTunnelProfileStore.Profile internetProfile,
                            Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean passed = false;
            String result;
            try {
                Config homeConfig = parseRuntime(homeProfile);
                Config internetConfig = parseRuntime(internetProfile);
                validatePair(homeConfig, internetConfig);
                prepareRoot();

                boolean ipv4 = routeUses("1.1.1.1", false, europe.getName());
                boolean ipv6 = routeUses("2606:4700:4700::1111", true, europe.getName());
                int homeMatched = 0;
                int homeTotal = 0;
                for (InetNetwork route : homeConfig.getPeers().get(0).getAllowedIps()) {
                    homeTotal++;
                    InetAddress address = route.getAddress();
                    if (routeUses(address.getHostAddress(),
                            !(address instanceof Inet4Address), home.getName())) {
                        homeMatched++;
                    }
                }

                String dnsSummary;
                ConnectivityManager cm = (ConnectivityManager) application.getSystemService(
                        Context.CONNECTIVITY_SERVICE);
                Network active = cm == null ? null : cm.getActiveNetwork();
                LinkProperties props = active == null || cm == null ? null : cm.getLinkProperties(active);
                if (props == null) {
                    dnsSummary = "Android active-network DNS: unavailable.";
                } else {
                    int dnsMatched = 0;
                    List<InetAddress> dns = props.getDnsServers();
                    for (InetAddress server : dns) {
                        if (routeUses(server.getHostAddress(),
                                !(server instanceof Inet4Address), europe.getName())) {
                            dnsMatched++;
                        }
                    }
                    dnsSummary = "Android active-network DNS: " + dnsMatched + "/" + dns.size()
                            + " server destinations select wnair0 for root route queries.";
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        dnsSummary += " Private DNS: "
                                + (props.isPrivateDnsActive() ? "reported active" : "not reported active")
                                + ".";
                    }
                }
                passed = ipv4 && ipv6 && homeMatched == homeTotal && homeTotal > 0;
                result = "READ-ONLY ROOT ROUTE AUDIT " + (passed ? "PASS" : "NEEDS ATTENTION")
                        + "\nPublic IPv4 via wnair0: " + (ipv4 ? "YES" : "NO")
                        + "\nPublic IPv6 via wnair0: " + (ipv6 ? "YES" : "NO")
                        + "\nHome split routes via wnhome0: " + homeMatched + "/" + homeTotal
                        + "\n" + dnsSummary
                        + "\nThis is NOT a packet capture, app-DNS leak test, or kill switch. "
                        + "Android app fwmarks, encrypted DNS and fallback still require "
                        + "independent testing. No firewall rules changed.";
            } catch (Exception | LinkageError ignored) {
                result = "Root route audit could not complete. Check selected profile "
                        + "routes and root access; no firewall settings were modified.";
            }
            finish(callback, passed, result);
        });
    }

    /** Inspect leftovers after an app crash or reboot, without adopting them. */
    void inspectKernelInterfaces(Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            String result;
            try {
                prepareRoot();
                Set<String> existing = backend.getRunningTunnelNames();
                boolean hasHome = existing.contains(home.getName());
                boolean hasAir = existing.contains(europe.getName());
                ok = true;
                result = "Kernel interface inspection (read only):\nwnhome0: "
                        + (hasHome ? "PRESENT" : "ABSENT") + "\nwnair0: "
                        + (hasAir ? "PRESENT" : "ABSENT")
                        + "\nCurrent process manages pair: " + (managing ? "YES" : "NO")
                        + "\nA present interface after restart is NOT automatically trusted or "
                        + "managed. Recover only matching selected profiles, or inspect with adb. "
                        + "No interfaces were changed.";
            } catch (Exception | LinkageError ignored) {
                result = "Could not inspect kernel interfaces. Check root access. "
                        + "No interfaces were changed.";
            }
            finish(callback, ok, result);
        });
    }

    /** Explicit non-mutating live read; kernel names alone do not establish ownership. */
    void inspectLiveStatus(Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            String result;
            try {
                prepareRoot();
                result = summarize("Home", home) + "\n" + summarize("AirVPN Europe", europe)
                        + "\nREAD-ONLY snapshot. Unmanaged interface identities are NOT "
                        + "verified here. Use VERIFY + RESUME before restarting them. "
                        + "Counters are not a leak or connectivity audit.";
                ok = true;
            } catch (Exception | LinkageError ignored) {
                result = "Could not read live kernel status. Check root grant and tools.";
            }
            finish(callback, ok, result);
        });
    }

    /**
     * Process restart loses in-memory ownership even when kernel links remain.
     * Explicitly restore management ONLY after both public identities and
     * split/default routes match the selected encrypted configurations.
     */
    void verifyAndResumePair(SecureTunnelProfileStore.Profile homeProfile,
                             SecureTunnelProfileStore.Profile internetProfile,
                             Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            String result;
            try {
                if (managing) throw new IllegalStateException("Already managing a pair");
                Config verifiedHome = parseRuntime(homeProfile);
                Config verifiedInternet = parseRuntime(internetProfile);
                validatePair(verifiedHome, verifiedInternet);
                prepareRoot();
                if (backend.getState(home) != Tunnel.State.UP
                        || backend.getState(europe) != Tunnel.State.UP) {
                    result = "Cannot resume: both wnhome0 and wnair0 must already be UP. "
                            + "If only one remains, inspect and recover matching interfaces first.";
                } else if (!matchesKernelIdentity(home, verifiedHome)
                        || !matchesKernelIdentity(europe, verifiedInternet)) {
                    result = "Resume refused: running kernel interface or peer identity "
                            + "does not match the selected encrypted profiles. No change made.";
                } else {
                    boolean homeRoutes = true;
                    for (InetNetwork route : verifiedHome.getPeers().get(0).getAllowedIps()) {
                        InetAddress target = route.getAddress();
                        homeRoutes &= routeUses(target.getHostAddress(),
                                !(target instanceof Inet4Address), home.getName());
                    }
                    boolean internetRoutes = routeUses("1.1.1.1", false, europe.getName())
                            && routeUses("2606:4700:4700::1111", true, europe.getName());
                    if (!homeRoutes || !internetRoutes) {
                        result = "Resume refused: active Home split routes or public "
                                + "IPv4/IPv6 default routes did not match. No change made.";
                    } else {
                        startedHome = verifiedHome;
                        startedEurope = verifiedInternet;
                        homeTraffic.clear();
                        airTraffic.clear();
                        managing = true;
                        ok = true;
                        result = "Both active kernel identities and route decisions match. "
                                + "Wonhee resumed managing this pair in the current process; "
                                + "live monitoring and manual restart are now available. "
                                + "No routes or firewall rules were modified.";
                    }
                }
            } catch (Exception | LinkageError ignored) {
                result = "Could not securely resume this pair. Verify imported profiles, "
                        + "root grant, running identities, and routes. No changes made.";
            }
            finish(callback, ok, result);
        });
    }

    private boolean routeUses(String numericHost, boolean ipv6, String device) throws Exception {
        List<String> lines = new ArrayList<>();
        String family = ipv6 ? "ip -6" : "ip -4";
        // Host is a numeric address produced by InetAddress or a fixed probe,
        // not shell syntax from a user-supplied configuration string.
        if (rootShell.run(lines, family + " route get '" + numericHost + "'") != 0) return false;
        return RootKernelRouteAudit.routesThrough(lines, device);
    }

    void startPair(SecureTunnelProfileStore.Profile homeProfile,
                   SecureTunnelProfileStore.Profile airProfile, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean started = false;
            String result = "Could not start both kernel interfaces. Check Magisk and the profiles.";
            boolean homeRaised = false;
            boolean airRaised = false;
            boolean ownsAttempt = false;
            Config localHome = null;
            Config localAir = null;
            String stage = "profile parsing";
            try {
                if (managing) throw new IllegalStateException("pair already managed");
                localHome = parseRuntime(homeProfile);
                localAir = parseRuntime(airProfile);
                stage = "route validation";
                validatePair(localHome, localAir);
                stage = "root preflight";
                prepareRoot();

                // Refuse to take over kernel interfaces left by another process.
                stage = "interface collision check";
                Set<String> existing = backend.getRunningTunnelNames();
                if (existing.contains(home.getName()) || existing.contains(europe.getName())) {
                    result = "Wonhee test interface already exists. Stop it before another test.";
                    throw new IllegalStateException("existing tunnel");
                }
                for (String name : existing) {
                    if (name.startsWith("wnm")) {
                        result = "An experimental multi-tunnel interface is active. "
                                + "Disconnect it in Multi-Tunnel Lab before starting the legacy pair.";
                        throw new IllegalStateException("multi-kernel interface active");
                    }
                }
                ownsAttempt = true;

                stage = "HOME wg-quick up";
                setKernelState(home, Tunnel.State.UP, localHome);
                homeRaised = true;
                stage = "HOME interface verification";
                if (backend.getState(home) != Tunnel.State.UP) throw new IllegalStateException("home did not start");
                startedHome = localHome;
                managing = true;

                stage = "AIRVPN wg-quick up";
                startedEurope = localAir;
                setKernelState(europe, Tunnel.State.UP, localAir);
                airRaised = true;
                stage = "both interfaces verification";
                if (backend.getState(europe) != Tunnel.State.UP || backend.getState(home) != Tunnel.State.UP) {
                    throw new IllegalStateException("both were not active");
                }
                started = true;
                homeTraffic.clear();
                airTraffic.clear();
                result = "Both kernel interfaces are UP. Verify fresh handshakes, routing, DNS and IPv6.";
            } catch (IllegalArgumentException invalid) {
                // Route-policy failures are our own fixed, non-secret strings.
                // Preserve their actionable reason instead of hiding it behind
                // a generic message. Parsing errors can contain configuration
                // details and must remain redacted.
                if ("route validation".equals(stage)) {
                    result = "Route validation failed: " + invalid.getMessage();
                } else {
                    result = "Failed at " + stage + ". Check the selected profile "
                            + "and its routing/DNS options; private configuration is hidden.";
                }
            } catch (KernelCommandException command) {
                result = "Failed at " + stage + ": wg-quick exit code " + command.exitCode
                        + ". No private configuration was included in this message.";
            } catch (Exception | LinkageError ignored) {
                // No logging of private keys, tunnel configs, DNS or peer endpoints.
                if ("interface collision check".equals(stage)
                        && !result.startsWith("An experimental multi-tunnel interface")) {
                    result = "Existing kernel interface detected. Use Recover matching "
                            + "interfaces after confirming the selected profiles. "
                            + "Unknown interfaces will not be changed.";
                } else {
                    result = "Failed at " + stage + ("root preflight".equals(stage)
                            ? " (step: " + lastPreflightStep + ")" : "")
                            + ". Report this stage; no keys are needed.";
                }
            } finally {
                if (!started) {
                    // Best-effort transactional rollback: never intentionally leave only HOME up.
                    try {
                        if (ownsAttempt && localAir != null &&
                                (airRaised || backend.getState(europe) == Tunnel.State.UP)) {
                            setKernelState(europe, Tunnel.State.DOWN, localAir);
                        }
                    } catch (Exception | LinkageError ignored) { }
                    try {
                        if (ownsAttempt && localHome != null &&
                                (homeRaised || backend.getState(home) == Tunnel.State.UP)) {
                            setKernelState(home, Tunnel.State.DOWN, localHome);
                        }
                    } catch (Exception | LinkageError ignored) { }
                    try {
                        boolean leftover = ownsAttempt &&
                                (backend.getState(home) == Tunnel.State.UP ||
                                 backend.getState(europe) == Tunnel.State.UP);
                        managing = leftover;
                        if (!leftover) { startedHome = null; startedEurope = null; }
                        else result = "Start failed; a test interface may remain UP. Use Stop both.";
                    } catch (Exception | LinkageError ignored) { }
                }
                finish(callback, started, result);
            }
        });
    }

    void stopPair(Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            if (!managing) {
                finish(callback, false, "No pair owned by this Wonhee process. No interfaces changed.");
                return;
            }
            // Names can be reused after a crash or another root action.
            // Verify BOTH identities before changing EITHER interface.
            try {
                prepareRoot();
                if (startedHome == null || startedEurope == null
                        || (backend.getState(home) == Tunnel.State.UP
                            && !matchesKernelIdentity(home, startedHome))
                        || (backend.getState(europe) == Tunnel.State.UP
                            && !matchesKernelIdentity(europe, startedEurope))) {
                    finish(callback, false, "Stop refused: current interface identity "
                            + "does not match the pair this process manages. "
                            + "Inspect running interfaces; no changes made.");
                    return;
                }
            } catch (Exception | LinkageError ignored) {
                finish(callback, false, "Stop refused: could not verify both "
                        + "managed interface identities. No changes made.");
                return;
            }
            boolean airDown = false;
            boolean homeDown = false;
            try {
                prepareRoot();
                if (backend.getState(europe) == Tunnel.State.UP) {
                    setKernelState(europe, Tunnel.State.DOWN, startedEurope);
                }
                airDown = backend.getState(europe) == Tunnel.State.DOWN;
                if (backend.getState(home) == Tunnel.State.UP) {
                    setKernelState(home, Tunnel.State.DOWN, startedHome);
                }
                homeDown = backend.getState(home) == Tunnel.State.DOWN;
            } catch (Exception | LinkageError ignored) {
                // Try the other interface even if stopping Air failed.
                try {
                    if (backend.getState(home) == Tunnel.State.UP) {
                        setKernelState(home, Tunnel.State.DOWN, startedHome);
                    }
                    homeDown = backend.getState(home) == Tunnel.State.DOWN;
                } catch (Exception | LinkageError alsoIgnored) { }
            }
            boolean stopped = airDown && homeDown;
            if (stopped) {
                managing = false;
                startedHome = null;
                startedEurope = null;
                homeTraffic.clear();
                airTraffic.clear();
            }
            finish(callback, stopped, stopped ? "Both Wonhee kernel interfaces stopped."
                    : "Stop incomplete. Check each kernel interface and retry Stop both.");
        });
    }

    /**
     * Explicit recovery only: never adopt an orphan or silently restart it.
     * Check BOTH the interface and peer public keys against the selected
     * encrypted profiles before changing either existing interface.
     */
    void recoverMatchingPair(SecureTunnelProfileStore.Profile homeProfile,
                             SecureTunnelProfileStore.Profile airProfile, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean success = false;
            String result = "Recovery refused; no unknown tunnel should be changed.";
            try {
                if (managing) throw new IllegalStateException("Use Stop both for active session");
                Config expectedHome = parseRuntime(homeProfile);
                Config expectedAir = parseRuntime(airProfile);
                validatePair(expectedHome, expectedAir);
                prepareRoot();
                Set<String> existing = backend.getRunningTunnelNames();
                boolean hasHome = existing.contains(home.getName());
                boolean hasAir = existing.contains(europe.getName());
                if (!hasHome && !hasAir) {
                    success = true;
                    result = "No existing Wonhee test interfaces remain. Start selected tunnels.";
                } else {
                    // Check all present interfaces BEFORE stopping any one of them.
                    if (hasHome && !matchesKernelIdentity(home, expectedHome)) {
                        throw new IllegalStateException("Home interface identity mismatch");
                    }
                    if (hasAir && !matchesKernelIdentity(europe, expectedAir)) {
                        throw new IllegalStateException("Internet interface identity mismatch");
                    }
                    if (hasAir) setKernelState(europe, Tunnel.State.DOWN, expectedAir);
                    if (hasHome) setKernelState(home, Tunnel.State.DOWN, expectedHome);
                    success = backend.getState(home) == Tunnel.State.DOWN
                            && backend.getState(europe) == Tunnel.State.DOWN;
                    result = success ? "Matching old interfaces stopped. Start selected tunnels "
                            + "when ready; test connectivity again afterward."
                            : "Recovery incomplete. Recheck kernel interfaces before restarting.";
                }
            } catch (Exception | LinkageError ignored) {
                result = "Recovery refused or incomplete: selected profiles did not match "
                        + "existing kernel identities, or root cleanup failed. "
                        + "Check interfaces before retrying; no keys are needed.";
            } finally {
                finish(callback, success, result);
            }
        });
    }

    private boolean matchesKernelIdentity(Tunnel tunnel, Config expected) throws Exception {
        String actualInterface = readKernelPublicValue(tunnel, "public-key");
        String actualPeer = readKernelPublicValue(tunnel, "peers");
        return expected.getInterface().getKeyPair().getPublicKey().toBase64()
                    .equals(actualInterface)
                && expected.getPeers().size() == 1
                && expected.getPeers().get(0).getPublicKey().toBase64()
                    .equals(actualPeer);
    }

    private String readKernelPublicValue(Tunnel tunnel, String field) throws Exception {
        // Both tunnel names and fields come exclusively from constants above.
        List<String> output = new ArrayList<>();
        if (rootShell.run(output, "wg show " + tunnel.getName() + " " + field) != 0
                || output.size() != 1) {
            throw new IllegalStateException("Unable to verify kernel interface identity");
        }
        return output.get(0).trim();
    }

    void readStatus(StatusCallback callback) {
        if (!managing || busy) {
            main.post(() -> callback.completed(managing ? "Kernel pair operation in progress."
                    : "Root dual-tunnel experiment is idle."));
            return;
        }
        worker.execute(() -> {
            String status;
            try {
                status = summarize("Home", home) + "\n" + summarize("AirVPN Europe", europe);
                status += "\nPassive tunnel counters only. A handshake does not prove "
                        + "internet reachability, DNS isolation, or leak prevention.";
            } catch (Exception | LinkageError ignored) {
                status = "Could not read kernel tunnel status; check Magisk root access.";
            }
            String safe = status;
            main.post(() -> callback.completed(safe));
        });
    }

    private String summarize(String label, Tunnel tunnel) throws Exception {
        TunnelTrafficHistory traffic = tunnel == home ? homeTraffic : airTraffic;
        if (backend.getState(tunnel) != Tunnel.State.UP) {
            traffic.clear();
            return RootTunnelHealth.render(label, false, 0, 0, -1, null);
        }
        Statistics stats = backend.getStatistics(tunnel);
        long recent = 0;
        for (Key peer : stats.peers()) {
            Statistics.PeerStats peerStats = stats.peer(peer);
            if (peerStats != null) recent = Math.max(recent, peerStats.latestHandshakeEpochMillis());
        }
        long ageSeconds = recent > 0 ? Math.max(0L,
                (System.currentTimeMillis() - recent) / 1000L) : -1L;
        TunnelTrafficRates.Result rates = traffic.add(SystemClock.elapsedRealtime(),
                stats.totalRx(), stats.totalTx());
        return RootTunnelHealth.render(label, true, stats.totalRx(), stats.totalTx(),
                ageSeconds, rates);
    }

    private static Config parseRuntime(SecureTunnelProfileStore.Profile profile) throws Exception {
        byte[] bytes = profile.configuration.getBytes(StandardCharsets.UTF_8);
        Config raw;
        try { raw = Config.parse(new ByteArrayInputStream(bytes)); }
        finally { Arrays.fill(bytes, (byte) 0); }
        if (raw.getPeers().size() != 1 || raw.getInterface().getAddresses().isEmpty()) {
            throw new IllegalArgumentException("Each kernel test profile needs one peer and an interface address.");
        }
        Config routed = VpnRouteModes.prepare(raw, profile.routeMode, profile.homeRoutes);
        return VpnDnsOverride.prepare(routed, profile.homeDnsEnabled, profile.homeDnsServer);
    }

    private static void validatePair(Config home, Config air) {
        List<String> homeRoutes = routes(home.getPeers().get(0));
        List<String> airRoutes = routes(air.getPeers().get(0));
        RootDualRoutePolicy.validate(homeRoutes, airRoutes);
        for (InetNetwork h : home.getInterface().getAddresses()) {
            for (InetNetwork a : air.getInterface().getAddresses()) {
                if (h.equals(a)) {
                    throw new IllegalArgumentException("The two tunnel interface addresses must differ.");
                }
            }
        }
    }

    private static List<String> routes(Peer peer) {
        List<String> result = new ArrayList<>();
        for (InetNetwork route : peer.getAllowedIps()) result.add(route.toString());
        return result;
    }
}
