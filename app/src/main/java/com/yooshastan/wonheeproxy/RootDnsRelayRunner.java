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
import java.util.ArrayList;
import java.util.List;

/** The DNS relay is started only after an explicit user opt-in. */
final class RootDnsRelayRunner {
    private RootDnsRelayRunner() { }

    static File binary(Context context) {
        return new File(context.getFilesDir(), "wonhee-root-dns-0154-arm64");
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
                     RootDnsProbePolicy policy) throws Exception {
        File target = binary(context);
        String inner = quote(target.getAbsolutePath()) + " --serve --protocol "
                + quote(policy.protocol) + " --interface " + quote(device)
                + " --url " + quote(policy.url)
                + " --bootstrap " + quote(policy.bootstrapAddress)
                + " </dev/null >/dev/null 2>&1 & echo $!";
        List<String> result = new ArrayList<>();
        int status = shell.run(result, "sh -c " + quote(inner));
        if (status != 0 || result.size() != 1 || !result.get(0).trim().matches("[0-9]{1,7}")) {
            throw new IllegalStateException("DNS relay could not start; no firewall rules installed.");
        }
        return Integer.parseInt(result.get(0).trim());
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
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(9000);
            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            socket.send(new DatagramPacket(query, query.length, loopback, RootDnsFirewallPlan.PORT));
            byte[] answer = new byte[4096];
            DatagramPacket reply = new DatagramPacket(answer, answer.length);
            socket.receive(reply);
            byte[] exact = java.util.Arrays.copyOf(answer, reply.getLength());
            return DoHWireMessage.verifiedAnswers(exact, query);
        }
    }

    private static String quote(String raw) {
        return "'" + raw.replace("'", "'\\''") + "'";
    }
}
