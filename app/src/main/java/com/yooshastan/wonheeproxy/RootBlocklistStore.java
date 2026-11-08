package com.yooshastan.wonheeproxy;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * Batch E.1 local, offline, explicitly imported HOSTS/domain-list snapshots.
 * No URL fetching, silent updates, telemetry, or device networking.
 * An import never changes a running DNS relay or the kernel firewall.
 */
final class RootBlocklistStore {
    static final int MAX_DOMAINS = 250_000;
    private static final int MAX_BYTES = 20 * 1024 * 1024;
    private static final int MAX_LINES = 420_000;
    private static final int MAX_LINE = 2048;
    private static final String CURRENT = "wonhee-managed-blocklist-v1.txt";
    private static final String PREVIOUS = "wonhee-managed-blocklist-v1.previous";

    private RootBlocklistStore() { }

    static final class Snapshot {
        final List<String> domains;
        final String sha256;

        Snapshot(List<String> domains, String sha256) {
            this.domains = Collections.unmodifiableList(domains);
            this.sha256 = sha256;
        }

        String summary() {
            return domains.size() + " unique domains · SHA-256 " + sha256.substring(0, 12);
        }
    }

    private static final class LimitedInputStream extends FilterInputStream {
        private long read;
        LimitedInputStream(InputStream delegate) { super(delegate); }

        private void counted(int amount) throws IOException {
            if (amount > 0 && (read += amount) > MAX_BYTES) {
                throw new IOException("Blocklist exceeds 20 MiB import limit.");
            }
        }
        @Override public int read() throws IOException {
            int value = super.read();
            if (value >= 0) counted(1);
            return value;
        }
        @Override public int read(byte[] bytes, int off, int len) throws IOException {
            int value = in.read(bytes, off, len);
            counted(value);
            return value;
        }
    }

    static Snapshot parse(InputStream stream) throws IOException {
        if (stream == null) throw new IOException("No readable list data.");
        LinkedHashSet<String> domains = new LinkedHashSet<>();
        int lines = 0;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new LimitedInputStream(stream), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (++lines > MAX_LINES) throw new IOException("Too many list lines.");
                if (line.length() > MAX_LINE) throw new IOException("Blocklist line too long.");
                String value = line.trim();
                if (value.isEmpty() || value.startsWith("#") || value.startsWith("!")) continue;
                String[] fields = value.split("\\s+");
                int begin;
                if (fields.length == 1) {
                    begin = 0;
                } else if (fields.length >= 2 && sinkAddress(fields[0])) {
                    begin = 1;
                } else {
                    throw new IOException("Unsupported blocklist syntax. Import HOSTS or plain domains.");
                }
                for (int index = begin; index < fields.length; index++) {
                    String name = fields[index].toLowerCase(Locale.ROOT);
                    if (name.startsWith("#")) break;
                    if (skipLocal(name)) continue;
                    if (!RootTrackerPolicy.validDomain(name)) {
                        throw new IOException("Invalid domain in blocklist. No snapshot changed.");
                    }
                    domains.add(name);
                    if (domains.size() > MAX_DOMAINS) {
                        throw new IOException("Blocklist exceeds 250,000 unique domain limit.");
                    }
                }
            }
        }
        if (domains.isEmpty()) throw new IOException("No usable blocked domains.");
        ArrayList<String> result = new ArrayList<>(domains);
        return new Snapshot(result, checksum(result));
    }

    private static boolean sinkAddress(String addr) {
        return addr.equals("0.0.0.0") || addr.equals("127.0.0.1")
                || addr.equals("::") || addr.equals("::1") || addr.equals("0");
    }

    private static boolean skipLocal(String name) {
        return name.equals("localhost") || name.equals("localhost.localdomain")
                || name.endsWith(".local") || name.endsWith(".internal")
                || name.endsWith(".arpa");
    }

    private static String checksum(List<String> domains) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            for (String name : domains) {
                sha.update(name.getBytes(StandardCharsets.US_ASCII));
                sha.update((byte) '\n');
            }
            StringBuilder hex = new StringBuilder();
            for (byte b : sha.digest()) hex.append(String.format(Locale.ROOT, "%02x", b & 0xff));
            return hex.toString();
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 unavailable.", unavailable);
        }
    }

    private static File file(File dir, String name) { return new File(dir, name); }

    static Snapshot current(File dir) throws IOException {
        File source = file(dir, CURRENT);
        if (!source.isFile()) return null;
        try (FileInputStream in = new FileInputStream(source)) {
            return parse(in);
        }
    }

    static Snapshot previous(File dir) throws IOException {
        File source = file(dir, PREVIOUS);
        if (!source.isFile()) return null;
        try (FileInputStream in = new FileInputStream(source)) {
            return parse(in);
        }
    }

    private static void writeSnapshot(File destination, Snapshot snapshot) throws IOException {
        try (FileOutputStream stream = new FileOutputStream(destination, false);
                BufferedWriter out = new BufferedWriter(
                        new OutputStreamWriter(stream, StandardCharsets.US_ASCII))) {
            for (String domain : snapshot.domains) {
                out.write(domain);
                out.write('\n');
            }
            out.flush();
            stream.getFD().sync();
        }
    }

    private static void replaceAtomically(File source, File destination) throws IOException {
        Files.move(source.toPath(), destination.toPath(),
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    static synchronized Snapshot importFrom(File dir, InputStream input) throws IOException {
        Snapshot incoming = parse(input);
        File currentFile = file(dir, CURRENT);
        File staged = File.createTempFile("wonhee-import-", ".tmp", dir);
        File backupStage = null;
        try {
            writeSnapshot(staged, incoming);
            // Keep one known-good previous snapshot. Never rewrite the active
            // file before the replacement has been fully validated and synced.
            if (currentFile.isFile()) {
                Snapshot prior = current(dir);
                backupStage = File.createTempFile("wonhee-backup-", ".tmp", dir);
                writeSnapshot(backupStage, prior);
                replaceAtomically(backupStage, file(dir, PREVIOUS));
                backupStage = null;
            }
            replaceAtomically(staged, currentFile);
            return incoming;
        } finally {
            staged.delete();
            if (backupStage != null) backupStage.delete();
        }
    }

    static synchronized Snapshot restorePrevious(File dir) throws IOException {
        Snapshot prior = previous(dir);
        if (prior == null) throw new IOException("No previous snapshot to restore.");
        File staged = File.createTempFile("wonhee-restore-", ".tmp", dir);
        try {
            writeSnapshot(staged, prior);
            replaceAtomically(staged, file(dir, CURRENT));
            return prior;
        } finally {
            staged.delete();
        }
    }

    static synchronized void clear(File dir) throws IOException {
        Files.deleteIfExists(file(dir, CURRENT).toPath());
        // Preserve one previous snapshot for user-controlled restoration.
    }
}
