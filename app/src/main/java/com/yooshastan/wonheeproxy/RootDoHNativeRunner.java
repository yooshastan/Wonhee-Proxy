package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.os.Build;

import com.wireguard.android.util.RootShell;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Runs a packaged, one-shot, restricted Go DNS probe using the EXISTING root
 * shell. Never grants root to an arbitrary URL or shell command, and never
 * installs persistent services or global policy rules.
 */
final class RootDoHNativeRunner {
    private RootDoHNativeRunner() { }

    static int probe(Context context, RootShell shell, String verifiedInterface,
                     DoHProbePolicy endpoint) throws Exception {
        String asset = assetForDevice();
        if (asset == null) {
            throw new IllegalStateException("No root DoH helper for this device architecture.");
        }
        File binary = File.createTempFile("wonhee-doh-", ".bin", context.getCodeCacheDir());
        try {
            try (InputStream in = context.getAssets().open(asset);
                 FileOutputStream out = new FileOutputStream(binary, false)) {
                byte[] buffer = new byte[16 * 1024];
                int read;
                while ((read = in.read(buffer)) != -1) out.write(buffer, 0, read);
                out.getFD().sync();
            }
            if (!binary.setWritable(false, false)
                    || !binary.setReadable(true, true)
                    || !binary.setExecutable(true, true)) {
                throw new IllegalStateException("Cannot prepare private root DNS helper.");
            }
            List<String> output = new ArrayList<>();
            String command = "timeout 17 " + quote(binary.getAbsolutePath())
                    + " --interface " + quote(verifiedInterface)
                    + " --url " + quote(endpoint.url)
                    + " --bootstrap " + quote(endpoint.bootstrapAddress);
            int exit = shell.run(output, command);
            if (exit == 0 && output.size() == 1) {
                String result = output.get(0).trim();
                if (result.matches("VERIFIED A_COUNT=[1-9][0-9]{0,2}")) {
                    return Integer.parseInt(result.substring("VERIFIED A_COUNT=".length()));
                }
            }
            if (output.size() == 1) {
                String result = output.get(0).trim();
                if (result.matches("REFUSED [A-Z_]+")) {
                    throw new IllegalStateException("Root-bound DNS transport: " + result);
                }
            }
            throw new IllegalStateException("Root-bound DNS helper unavailable or incomplete. "
                    + "No fallback was attempted.");
        } finally {
            // Root helper is one shot; never leave an executable behind.
            //noinspection ResultOfMethodCallIgnored
            binary.delete();
        }
    }

    private static String quote(String raw) {
        return "'" + raw.replace("'", "'\\''") + "'";
    }

    private static String assetForDevice() {
        for (String abi : Build.SUPPORTED_ABIS) {
            if ("arm64-v8a".equals(abi)) return "wonhee-doh-arm64";
            if ("armeabi-v7a".equals(abi)) return "wonhee-doh-arm";
            if ("x86_64".equals(abi)) return "wonhee-doh-amd64";
            if ("x86".equals(abi)) return "wonhee-doh-386";
        }
        return null;
    }
}
