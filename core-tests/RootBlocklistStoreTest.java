package com.yooshastan.wonheeproxy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

/** Pure-Java tests: no Android device, DNS writes, or firewall mutations. */
public final class RootBlocklistStoreTest {
    private static void check(boolean ok, String reason) {
        if (!ok) throw new AssertionError(reason);
    }

    private static ByteArrayInputStream input(String text) {
        return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("wonhee-blocklist-");
        try {
            String hosts = "# sample HOSTS list\n"
                    + "0.0.0.0 ad.example.com tracker.example.net\n"
                    + "127.0.0.1 ad.example.com\n"
                    + "::1 localhost\n"
                    + "advertising.example.org\n";
            RootBlocklistStore.Snapshot first =
                    RootBlocklistStore.importFrom(dir.toFile(), input(hosts));
            check(first.domains.size() == 3, "deduplicate hosts and plain domains");
            check(first.sha256.length() == 64, "SHA-256");
            check(RootBlocklistStore.current(dir.toFile()).domains.size() == 3,
                    "read committed snapshot");
            RootTrackerPolicy.Config filter = RootTrackerPolicy.compileWithManaged(
                    true, "", "safe.ad.example.com", dir.toFile());
            check(filter.shouldBlock("ad.example.com"), "imported block");
            check(filter.shouldBlock("x.ad.example.com"), "suffix block");
            check(!filter.shouldBlock("safe.ad.example.com"), "allow precedence");
            check(!filter.shouldBlock("notad.example.com"), "label boundary");
            check(!RootTrackerPolicy.compileWithManaged(false, "", "", dir.toFile())
                    .shouldBlock("ad.example.com"), "off preserves off");
            RootBlocklistStore.Snapshot next =
                    RootBlocklistStore.importFrom(dir.toFile(), input("0.0.0.0 new.example.org\n"));
            check(next.domains.size() == 1, "replacement size");
            check(RootBlocklistStore.previous(dir.toFile()).sha256.equals(first.sha256),
                    "backup equals prior good snapshot");

            for (String invalid : new String[]{
                    "0.0.0.0 *.wildcard.example.org\n",
                    "||ad.example.com^\n",
                    "0.0.0.0 ad.example.com\nallow example.org\n",
                    "https://example.com\n"}) {
                try {
                    RootBlocklistStore.importFrom(dir.toFile(), input(invalid));
                    throw new AssertionError("accepted invalid import " + invalid);
                } catch (IOException expected) { /* current snapshot unchanged */ }
            }
            check(RootBlocklistStore.current(dir.toFile()).sha256.equals(next.sha256),
                    "invalid import does not replace current");
            RootBlocklistStore.Snapshot restored =
                    RootBlocklistStore.restorePrevious(dir.toFile());
            check(restored.sha256.equals(first.sha256), "restored previous snapshot");
            RootBlocklistStore.clear(dir.toFile());
            check(RootBlocklistStore.current(dir.toFile()) == null, "cleared current");
            check(RootBlocklistStore.previous(dir.toFile()) != null,
                    "backup preserved after clearing current");

            StringBuilder many = new StringBuilder();
            for (int i = 0; i < 1200; i++) {
                many.append("0.0.0.0 ad-").append(i).append(".example.net\n");
            }
            RootBlocklistStore.Snapshot sample =
                    RootBlocklistStore.importFrom(dir.toFile(), input(many.toString()));
            check(sample.domains.size() == 1200, "larger catalog accepted");
            System.out.println("RootBlocklistStoreTest PASS");
        } finally {
            try (Stream<Path> paths = Files.walk(dir)) {
                paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); }
                    catch (IOException ignore) { /* test temp cleanup */ }
                });
            }
        }
    }
}
