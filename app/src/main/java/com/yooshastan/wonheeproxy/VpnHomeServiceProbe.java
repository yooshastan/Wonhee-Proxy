package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Handler;
import android.os.Looper;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Exactly one opt-in TCP connect to a strictly validated private IPv4
 * destination through an unambiguous Android-reported VPN Network.
 * No DNS lookup, automatic retry, credentials, traffic capture or fallback.
 */
final class VpnHomeServiceProbe {
    interface Callback {
        void finished(String message);
    }

    private static final ExecutorService WORKER = Executors.newSingleThreadExecutor();
    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    private VpnHomeServiceProbe() { }

    static void run(Context context, PrivateIpv4Target target, Callback callback) {
        Context app = context.getApplicationContext();
        WORKER.execute(() -> {
            String result;
            try {
                result = perform(app, target);
            } catch (Exception | LinkageError unexpected) {
                result = "INCONCLUSIVE: Android VPN-bound TCP test unavailable. "
                        + "No ordinary-network fallback was attempted.";
            }
            String finalResult = result;
            MAIN.post(() -> callback.finished(finalResult));
        });
    }

    private static String perform(Context context, PrivateIpv4Target target) throws Exception {
        ConnectivityManager manager = (ConnectivityManager) context.getSystemService(
                Context.CONNECTIVITY_SERVICE);
        if (manager == null) return "INCONCLUSIVE: Android network service unavailable.";
        Network soleVpn = null;
        int count = 0;
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
            if (capabilities != null
                    && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                soleVpn = network;
                count++;
            }
        }
        if (count == 0) return "UNAVAILABLE: No Android VPN network visible. No connection attempted.";
        if (count != 1) return "INCONCLUSIVE: Multiple VPN networks visible. No connection attempted.";

        // Construct from numeric bytes: InetAddress.getByName/Android DNS is never called.
        InetAddress destination = InetAddress.getByAddress(target.addressBytes());
        try (Socket socket = soleVpn.getSocketFactory().createSocket()) {
            socket.connect(new InetSocketAddress(destination, target.port), 4000);
            return "PASS: TCP port accepted a connection through the Android-reported VPN "
                    + "network. This does not verify service authentication, DNS privacy, "
                    + "IPv6 routing, or leak freedom.";
        } catch (IOException failed) {
            return "FAILED: TCP connection through the VPN did not succeed. "
                    + "Check service listening address, Fedora firewall, WireGuard "
                    + "AllowedIPs and LAN forwarding. No other network was used.";
        }
    }
}
