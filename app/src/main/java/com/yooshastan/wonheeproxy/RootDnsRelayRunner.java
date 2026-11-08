package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.os.Build;

import com.wireguard.android.util.RootShell;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** The DNS relay is started only after an explicit user opt-in. */
final class RootDnsRelayRunner {
    private RootDnsRelayRunner() { }

    static File binary(Context context) {
        return new File(context.getFilesDir(), "wonhee-root-dns-0154-arm64");
    }

    static File trackerFile(Context context) {
        return new File(context.getFilesDir(), "wonhee-tracker-policy-0155.txt");
    }

    static void prepareTrackerPolicy(Context context, RootTrackerPolicy.Config tracker) throws Exception {
        if (!tracker.enabled) return;
        File target = trackerFile(context);
        File staging = File.createTempFile("wonhee-tracker-", ".tmp", context.getFilesDir());
        try {
            try (FileOutputStream out = new FileOutputStream(staging, false)) {
                tracker.writeTo(out);
                out.getFD().sync();
            }
            if (!staging.setReadable(true, true) || !staging.renameTo(target)) {
                throw new IllegalStateException("Cannot commit local tracker policy.");
            }
        } finally {
            //noinspection ResultOfMethodCallIgnored
            staging.delete();
        }
    }

    static void removeTrackerPolicy(Context context) {
        // No firewall state is owned by this file; the relay holds an immutable
        // in-memory copy while running, and validates it before accepting DNS.
        //noinspection ResultOfMethodCallIgnored
        trackerFile(context).delete();
    }

    static void prepare(Context context) throws Exception {
        boolean arm64 = false;
        for (String abi : Build.SUPPORTED_ABIS) if ("arm64-v8a".equals(abi)) arm64 = true;
        if (!arm64) throw new IllegalStateException("Root DNS relay requires ARM64.");
        File target = binary(context);
        // Never overwrite a running helper: the controller refuses a nonempty
        // DNS ledger and separately checks for already occupied listener ports.
        try (InputStream in = context.getAssets().open("wonhee-doh-arm64");
             FileOutputStream out = new FileOutputStream(target, false)) {
            byte[] buffer = new byte[16 * 1024];
            int read;
            while ((read = in.read(buffer)) != -1) out.write(buffer, 0, read);
            out.getFD().sync();
        }
        if (!target.setReadable(true, true) || !target.setExecutable(true, true)) {
            throw new IllegalStateException("Cannot prepare restricted DNS relay executable.");
        }
    }

    static int start(Context context, RootShell shell, String device,
                     RootDnsProbePolicy policy, RootTrackerPolicy.Config tracker) throws Exception {
        File target = binary(context);
        String inner = quote(target.getAbsolutePath()) + " --serve --protocol "
                + quote(policy.protocol) + " --interface " + quote(device)
                + " --url " + quote(policy.url)
                + " --bootstrap " + quote(policy.bootstrapAddress)
                + (tracker.enabled ? " --tracker-file " + quote(trackerFile(context).getAbsolutePath()) : "")
                + " </dev/null >/dev/null 2>&1 & echo $!";
        List<String> result = new ArrayList<>();
        int status = shell.run(result, "sh -c " + quote(inner));
        if (status != 0 || result.size() != 1 || !result.get(0).trim().matches("[0-9]{1,7}")) {
            throw new IllegalStateException("DNS relay could not start; no firewall rules installed.");
        }
        return Integer.parseInt(result.get(0).trim());
    }

    /**
     * Observe only the exact IPv4 loopback listener that the Go relay creates.
     * A bounded read-only root /proc check avoids racing DNS health against
     * asynchronous process startup. This is readiness, not a DNS/leak audit.
     */
    static boolean waitForLoopbackListener(RootShell shell) throws Exception {
        for (int attempt = 0; attempt < 12; attempt++) {
            if (shell.run(null, "grep -qi '0100007F:D11F' /proc/net/udp") == 0) {
                return true;
            }
            Thread.sleep(150);
        }
        return false;
    }

    static boolean sameProcess(Context context, RootShell shell, int pid) throws Exception {
        if (pid < 2 || pid > 9_999_999) return false;
        String path = binary(context).getAbsolutePath();
        String canonical = binary(context).getCanonicalPath();
        List<String> result = new ArrayList<>();
        return shell.run(result, "readlink /proc/" + pid + "/exe") == 0
                && result.size() == 1 && (path.equals(result.get(0).trim())
                || canonical.equals(result.get(0).trim()));
    }

    static void stop(Context context, RootShell shell, int pid) throws Exception {
        if (!sameProcess(context, shell, pid)) {
            throw new IllegalStateException("Refusing to terminate a non-Wonhee process.");
        }
        if (shell.run(null, "kill -TERM " + pid) != 0) {
            throw new IllegalStateException("Cannot stop owned DNS relay process.");
        }
    }

    static int healthQuery() throws Exception {
        byte[] query = DoHWireMessage.question("example.com", 0x5734);
        byte[] exact = localQuery(query);
        return DoHWireMessage.verifiedAnswers(exact, query);
    }

    static boolean blockedHealthQuery() throws Exception {
        byte[] query = DoHWireMessage.question("app-measurement.com", 0x5735);
        byte[] reply = localQuery(query);
        return reply.length == query.length && reply.length >= 17
                && Arrays.equals(Arrays.copyOfRange(reply, 0, 2), Arrays.copyOfRange(query, 0, 2))
                && Arrays.equals(Arrays.copyOfRange(reply, 12, reply.length),
                        Arrays.copyOfRange(query, 12, query.length))
                && (reply[2] & 0x80) != 0 && (reply[3] & 15) == 3
                && reply[6] == 0 && reply[7] == 0;
    }

    /**
     * Optional local test against an ALREADY running relay. Caller must verify
     * owned DNS + tracker ledgers, and that the domain is in its planned filter.
     * Never starts, stops, or changes a relay or firewall.
     */
    static boolean isLocallyBlocked(String domain, boolean ipv6) throws Exception {
        byte[] question = RootFilterDnsProbe.query(domain, ipv6, ipv6 ? 0x5716 : 0x5714);
        return RootFilterDnsProbe.isExactLocalNxDomain(question, localQuery(question));
    }

    private static byte[] localQuery(byte[] query) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(9000);
            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            socket.send(new DatagramPacket(query, query.length, loopback, RootDnsFirewallPlan.PORT));
            byte[] answer = new byte[4096];
            DatagramPacket reply = new DatagramPacket(answer, answer.length);
            socket.receive(reply);
            return Arrays.copyOf(answer, reply.getLength());
        }
    }

    private static String quote(String raw) {
        return "'" + raw.replace("'", "'\\''") + "'";
    }
}
