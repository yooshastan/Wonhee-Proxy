package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Read-only privacy-preserving evidence from root 'ss -tnpe'.
 *
 * Never emit unrelated socket addresses, usernames, process command lines,
 * raw status lines, ports, keys or tokens. This does not establish packet
 * delivery, Android Network binding, firewall coverage, or leak prevention.
 */
final class RootHomeTcpSocketEvidence {
    private static final Pattern TARGET = Pattern.compile(
            "(?<![0-9.])10\\.0\\.0\\.169(?:%[a-zA-Z0-9_]+)?:4533(?![0-9])");
    private static final Pattern UID = Pattern.compile(
            "(?:^|\\s)uid[:=]([0-9]{1,7})(?:\\s|$)");
    private static final Pattern MARK = Pattern.compile(
            "(?:^|\\s)(?:fwmark|mark)[:=](0x[0-9a-fA-F]{1,8}|[0-9]{1,10})(?:\\s|$)");
    private static final Pattern STATE = Pattern.compile(
            "^(?:ESTAB|SYN-SENT|SYN-RECV|FIN-WAIT-1|FIN-WAIT-2|TIME-WAIT|"
                    + "CLOSE-WAIT|LAST-ACK|LISTEN|CLOSING|CLOSE|UNKNOWN)$");

    private RootHomeTcpSocketEvidence() { }

    private static String uidLabel(String line, int mokaUid, int braveUid) {
        Matcher m = UID.matcher(line);
        int count = 0, seen = -1;
        while (m.find()) {
            count++;
            try { seen = Integer.parseInt(m.group(1)); }
            catch (NumberFormatException invalid) { return "UNKNOWN_UID"; }
        }
        if (count != 1) return "UNKNOWN_UID";
        if (seen == mokaUid) return "MOKA";
        if (seen == braveUid) return "BRAVE_APP_UID";
        return "OTHER_OR_ISOLATED_UID";
    }

    private static String markLabel(String line) {
        Matcher m = MARK.matcher(line);
        if (!m.find()) return "MARK_NOT_VISIBLE";
        String mark = m.group(1);
        if (m.find()) return "MARK_AMBIGUOUS";
        return "mark=" + mark;
    }

    /** Parser uses only known exact endpoint: no arbitrary remote addresses returned. */
    static String summarize(String inventory, int mokaUid, int braveUid) {
        if (inventory == null || inventory.length() > 300000
                || mokaUid < 10000 || braveUid < 10000
                || mokaUid == braveUid) {
            return "SOCKET_INVENTORY_UNAVAILABLE_OR_UNVERIFIED";
        }
        List<String> matches = new ArrayList<>();
        int matched = 0;
        for (String raw : inventory.split("\\r?\\n")) {
            if (!TARGET.matcher(raw).find()) continue;
            matched++;
            if (matches.size() >= 12) continue;
            String line = raw.trim().replaceAll("\\s+", " ");
            String[] tokens = line.split(" ");
            String state = tokens.length > 0 && STATE.matcher(tokens[0]).matches()
                    ? tokens[0] : "STATE_UNVERIFIED";
            matches.add(uidLabel(line, mokaUid, braveUid) + " " + state
                    + " " + markLabel(line));
        }
        if (matched == 0) return "NO_ENDPOINT_SOCKET_VISIBLE_AT_SNAPSHOT";
        return "ENDPOINT_SOCKETS=" + matched + " " + String.join("; ", matches)
                + (matched > matches.size() ? "; ADDITIONAL_REDACTED" : "")
                + " (UID/mark fields may be omitted by Android ss)";
    }
}
