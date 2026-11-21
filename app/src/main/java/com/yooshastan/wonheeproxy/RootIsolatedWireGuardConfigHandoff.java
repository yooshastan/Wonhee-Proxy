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
 * No private keys or endpoints appear in shell arguments, journals, logs,
 * callbacks or diagnostics. The WireGuard-library-parsed configuration
 * is converted to strict wg setconf syntax in Java. We do NOT invoke
 * wg-quick, shell pipes, routes, DNS commands or Android VPN services.
 */
final class RootIsolatedWireGuardConfigHandoff {
    private RootIsolatedWireGuardConfigHandoff() { }

    /**
     * Crash-recovery hygiene: remove only a known app-private staging file
     * whose device is listed in a previously authenticated ownership journal.
     * This never touches live WireGuard peers, public kernel routes or an
     * unrelated process's files. Call from Safe Stop, not arbitrary Start.
     */
    static void cleanupStaleOwnedFile(Context context, String device)
            throws Exception {
        if (context == null || device == null
                || !device.matches("wnm[0-9a-f]{12}")) {
            throw new IllegalArgumentException("Invalid staged peer identity.");
        }
        File directory = new File(context.getCacheDir(), "isolated-peer-handoff");
        if (!directory.exists()) return;
        if (!directory.isDirectory()
                || java.nio.file.Files.isSymbolicLink(directory.toPath())) {
            throw new IllegalStateException("Peer staging directory identity changed.");
        }
        File stale = new File(directory, device + ".conf");
        if (!stale.exists()) return;
        if (!stale.isFile()
                || java.nio.file.Files.isSymbolicLink(stale.toPath())
                || !stale.delete()) {
            throw new IllegalStateException("Cannot remove owned stale peer config.");
        }
    }

    static void apply(Context context, RootShell shell, String device,
            Config configuration) throws Exception {
        if (context == null || shell == null || configuration == null
                || device == null || !device.matches("wnm[0-9a-f]{12}")
                || configuration.getPeers().size() != 1) {
            throw new IllegalArgumentException("Unsafe WireGuard peer handoff.");
        }
        File directory = new File(context.getCacheDir(), "isolated-peer-handoff");
        if (!directory.isDirectory() && !directory.mkdir()) {
            throw new RootIsolatedWireGuardTransaction.SafeFailure(
                    "STAGING_DIR_CREATE_FAILED");
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
            throw new RootIsolatedWireGuardTransaction.SafeFailure(
                    "STAGING_DIR_PERMISSIONS_FAILED");
        }
        File config = new File(directory, device + ".conf");
        if (!config.createNewFile()) {
            // A crashed helper may have left secrets. Never overwrite it,
            // follow a symlink, or silently adopt its contents.
            throw new RootIsolatedWireGuardTransaction.SafeFailure(
                    "STAGING_FILE_ALREADY_EXISTS");
        }
        try {
            if (!config.setReadable(false, false)
                    || !config.setWritable(false, false)
                    || !config.setReadable(true, true)
                    || !config.setWritable(true, true)
                    || java.nio.file.Files.isSymbolicLink(config.toPath())) {
                throw new RootIsolatedWireGuardTransaction.SafeFailure(
                        "STAGING_FILE_PERMISSIONS_FAILED");
            }
            // Config is parsed and canonicalized by the WireGuard library.
            // Never interpolate this string directly in the root shell.
            // wg setconf DOES NOT accept wg-quick Address/DNS/MTU.
            // Generate a strict peer-only wg configuration in Java rather
            // than relying on wg-quick strip and a shell pipe on Android.
            String canonical;
            try {
                canonical = RootIsolatedWireGuardSetconfCodec.stripCanonicalQuick(
                        configuration.toWgQuickString());
            } catch (IllegalArgumentException unsafe) {
                throw new RootIsolatedWireGuardTransaction.SafeFailure(
                        "PEER_CONFIG_FORMAT_REJECTED");
            }
            byte[] clear = canonical.getBytes(StandardCharsets.UTF_8);
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
                throw new RootIsolatedWireGuardTransaction.SafeFailure(
                        "STAGING_PATH_REJECTED");
            }
            // Direct wg setconf reads a standard wg-only private file.
            // No wg-quick script, shell pipe, argv key, DNS or route changes.
            String command = "wg setconf " + device + " '" + path + "'";
            if (shell.run(null, command) != 0) {
                throw new RootIsolatedWireGuardTransaction.SafeFailure(
                        "WG_SETCONF_COMMAND_FAILED");
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
                throw new RootIsolatedWireGuardTransaction.SafeFailure(
                        "WG_SETCONF_READBACK_MISMATCH");
            }
        } finally {
            // If unlink fails, do not return success. Never leave a reusable
            // plaintext peer file in application cache.
            if (config.exists() && !config.delete()) {
                throw new RootIsolatedWireGuardTransaction.SafeFailure(
                        "STAGING_FILE_CLEANUP_FAILED");
            }
        }
    }
}
