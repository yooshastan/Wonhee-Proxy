package com.yooshastan.wonheeproxy;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Strict parsing of aggregate-only, root-verified Wonhee DNS relay counters. */
final class RootDnsCounters {
    private static final Pattern RECORD = Pattern.compile(
            "^WN_DNS_STATS_V1 pid=([0-9]{1,7}) received=([0-9]{1,20}) "
            + "blocked=([0-9]{1,20}) forwarded=([0-9]{1,20}) failed=([0-9]{1,20})$");

    final int pid;
    final long received;
    final long blocked;
    final long forwarded;
    final long failed;

    private RootDnsCounters(int pid, long received, long blocked, long forwarded, long failed) {
        this.pid = pid;
        this.received = received;
        this.blocked = blocked;
        this.forwarded = forwarded;
        this.failed = failed;
    }

    static RootDnsCounters parse(String raw, int expectedPid) {
        Matcher match = RECORD.matcher(raw == null ? "" : raw.trim());
        if (!match.matches()) throw new IllegalStateException("DNS stats snapshot format mismatch.");
        try {
            int pid = Integer.parseInt(match.group(1));
            long received = Long.parseLong(match.group(2));
            long blocked = Long.parseLong(match.group(3));
            long forwarded = Long.parseLong(match.group(4));
            long failed = Long.parseLong(match.group(5));
            if (pid < 2 || pid != expectedPid || received < 0 || blocked < 0
                    || forwarded < 0 || failed < 0
                    || blocked > received || forwarded > received
                    || blocked > received - forwarded) {
                throw new IllegalStateException("DNS stats snapshot does not match owned relay.");
            }
            return new RootDnsCounters(pid, received, blocked, forwarded, failed);
        } catch (NumberFormatException invalid) {
            throw new IllegalStateException("DNS stats count outside supported range.", invalid);
        }
    }

    String summary() {
        return "DNS relay counters (since this relay started; last periodic snapshot):\n"
                + "Received queries: " + received
                + "\nBlocked replies: " + blocked
                + "\nForwarded replies: " + forwarded
                + "\nFailed or dropped: " + failed
                + "\nNo domain names, client identifiers or query history stored.";
    }
}
