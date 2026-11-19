package com.yooshastan.wonheeproxy;

import android.content.Context;

import com.wireguard.android.util.RootShell;
import com.wireguard.config.Config;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;

/**
 * Isolated WireGuard peer configuration only, without wg-quick UP/DOWN.
 *
 * NOT wired into production Start: no application caller may use this until
 * the isolated transaction's complete dual-stack no-fallback + DNS gate and
 * exact ownership verification are implemented.
 *
 * The config is held briefly in an app-private, owner-readable file.
 * No private keys or endpoints appear in a shell argument, journal, log,
 * callback, or diagnostics. Only 'wg-quick strip' runs, piped directly
 * into 'wg setconf'; neither command adds routes or changes Android DNS.
 */
final class RootIsolatedWireGuardConfigHandoff {
    private RootIsolatedWireGuardConfigHandoff() { }

    static void apply(Context context, RootShell shell, String device,
            Config configuration) throws Exception {
        if (context == null || shell == null || configuration == null
                || device == null || !device.matches("wnm[0-9a-f]{12}")
                || configuration.getPeers().size() != 1) {
            throw new IllegalArgumentException("Unsafe WireGuard peer handoff.");
        }
        File directory = new File(context.getCacheDir(), "isolated-peer-handoff");
        if (!directory.isDirectory() && !directory.mkdir()) {
            throw new IllegalStateException("Cannot create isolated peer directory.");
        }
        // Android normally aliases /data/user/0 through /data/data; do not
        // reject that trusted parent alias. Refuse a symlink at our OWN
        // staging directory, and require restrictive owner-only permissions.
        if (java.nio.file.Files.isSymbolicLink(directory.toPath())
                || !directory.setReadable(false, false)
                || !directory.setWritable(false, false)
                || !directory.setExecutable(false, false)
                || !directory.setReadable(true, true)
                || !directory.setWritable(true, true)
                || !directory.setExecutable(true, true)) {
            throw new IllegalStateException("Isolated peer directory permissions unsafe.");
        }
        File config = new File(directory, device + ".conf");
        if (!config.createNewFile()) {
            // A crashed helper may have left secrets. Never overwrite it,
            // follow a symlink, or silently adopt its contents.
            throw new IllegalStateException("Stale isolated peer file requires manual audit.");
        }
        try {
            if (!config.setReadable(false, false)
                    || !config.setWritable(false, false)
                    || !config.setReadable(true, true)
                    || !config.setWritable(true, true)
                    || java.nio.file.Files.isSymbolicLink(config.toPath())) {
                throw new IllegalStateException("Peer file permissions unavailable.");
            }
            // Config is parsed and canonicalized by the WireGuard library.
            // Never interpolate this string directly in the root shell.
            byte[] clear = configuration.toWgQuickString()
                    .getBytes(StandardCharsets.UTF_8);
            try (FileOutputStream stream = new FileOutputStream(config, false)) {
                try {
                    stream.write(clear);
                    stream.getFD().sync();
                } finally {
                    Arrays.fill(clear, (byte) 0);
                }
            }
            String path = config.getCanonicalPath();
            if (!path.matches("[A-Za-z0-9_./-]+")) {
                throw new IllegalStateException("Unsafe app-private peer path.");
            }
            // wg-quick STRIP strips Address/DNS/Table without doing UP.
            // Only wg setconf configures the previously owned kernel link.
            String command = "wg-quick strip '" + path
                    + "' | wg setconf " + device + " /dev/stdin";
            if (shell.run(null, command) != 0) {
                throw new IllegalStateException("Kernel WireGuard peer setup failed.");
            }
            List<String> publicKey = new ArrayList<>();
            List<String> peers = new ArrayList<>();
            if (shell.run(publicKey, "wg show " + device + " public-key") != 0
                    || shell.run(peers, "wg show " + device + " peers") != 0
                    || publicKey.size() != 1 || peers.size() != 1
                    || !configuration.getInterface().getKeyPair()
                            .getPublicKey().toBase64().equals(publicKey.get(0).trim())
                    || !configuration.getPeers().get(0)
                            .getPublicKey().toBase64().equals(peers.get(0).trim())) {
                throw new IllegalStateException("Kernel WireGuard identity differs.");
            }
        } finally {
            // If unlink fails, do not return success. Never leave a reusable
            // plaintext peer file in application cache.
            if (config.exists() && !config.delete()) {
                throw new IllegalStateException("Private peer staging file could not be removed.");
            }
        }
    }
}
