package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Handler;
import android.os.Looper;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * User-triggered DNS/HTTPS reachability check. It never chooses a non-VPN
 * fallback network. These checks cannot establish leak freedom or a kill switch.
 */
final class VpnConnectionDiagnostics {
    interface Callback {
        void finished(String report);
    }

    private static final String TEST_HOST = "example.com";
    private static final ExecutorService WORKER = Executors.newSingleThreadExecutor();
    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    private VpnConnectionDiagnostics() { }

    static void run(Context context, Callback callback) {
        Context application = context.getApplicationContext();
        WORKER.execute(() -> {
            String result;
            try {
                result = perform(application);
            } catch (Exception | LinkageError failure) {
                result = "INCONCLUSIVE: Android VPN network test unavailable. "
                        + "No unprotected fallback test was attempted.";
            }
            final String report = result;
            MAIN.post(() -> callback.finished(report));
        });
    }

    private static String perform(Context context) {
        ConnectivityManager manager = (ConnectivityManager) context.getSystemService(
                Context.CONNECTIVITY_SERVICE);
        if (manager == null) return "INCONCLUSIVE: ConnectivityManager unavailable.";

        Network vpnNetwork = null;
        int matches = 0;
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
            if (capabilities != null
                    && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                vpnNetwork = network;
                matches++;
            }
        }
        if (matches == 0) {
            return "UNAVAILABLE: No Android VPN network is visible to this app. "
                    + "No DNS or HTTPS requests were made.";
        }
        if (matches != 1) {
            return "INCONCLUSIVE: Multiple Android VPN networks were visible. "
                    + "No DNS or HTTPS requests were made.";
        }

        LinkProperties links = manager.getLinkProperties(vpnNetwork);
        int configuredDns = links == null ? 0 : links.getDnsServers().size();
        if (configuredDns == 0) {
            return "VPN transport observed, but Android reports no DNS servers on that VPN network. "
                    + "DNS and HTTPS tests were not started. Check the selected DNS preset.";
        }

        final InetAddress[] resolved;
        try {
            // Resolves on the selected VPN Network, never the default network.
            resolved = vpnNetwork.getAllByName(TEST_HOST);
        } catch (UnknownHostException lookupFailure) {
            return "VPN transport observed; DNS resolution FAILED on the VPN network. "
                    + "Check the resolver, WireGuard routes and Fedora forwarding.";
        } catch (RuntimeException dnsFailure) {
            return "INCONCLUSIVE: Android could not complete VPN-bound DNS resolution.";
        }
        if (resolved == null || resolved.length == 0) {
            return "VPN transport observed; DNS returned no usable addresses.";
        }

        HttpURLConnection connection = null;
        try {
            // Opening explicitly on the VPN Network forbids testing the normal
            // cellular/Wi-Fi network as a silent substitute.
            connection = (HttpURLConnection) vpnNetwork.openConnection(
                    new URL("https://" + TEST_HOST + "/"));
            connection.setConnectTimeout(6000);
            connection.setReadTimeout(6000);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setRequestMethod("HEAD");
            int response = connection.getResponseCode();
            if (response >= 200 && response < 500) {
                return "VPN transport observed. DNS resolution succeeded on the VPN network. "
                        + "HTTPS reached example.com (HTTP " + response + "). "
                        + "PASS: VPN-bound reachability only; not a DNS or traffic-leak audit.";
            }
            return "VPN-bound DNS succeeded; HTTPS returned HTTP " + response
                    + ". Endpoint/network response needs review.";
        } catch (IOException networkFailure) {
            return "VPN-bound DNS succeeded, but HTTPS connectivity FAILED. "
                    + "Check tunnel routing, the gateway's NAT/firewall and internet access.";
        } catch (RuntimeException unsupported) {
            return "INCONCLUSIVE: Android could not complete a VPN-bound HTTPS request.";
        } finally {
            if (connection != null) connection.disconnect();
        }
    }
}
