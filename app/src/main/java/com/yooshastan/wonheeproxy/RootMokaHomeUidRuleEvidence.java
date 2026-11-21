package com.yooshastan.wonheeproxy;

/**
 * Read-only, strict Android ip-rule inventory for a single destination/UID
 * selector. Does not treat an unrelated rule as Wonhee-owned.
 */
final class RootMokaHomeUidRuleEvidence {
    static final int PRIORITY = 12700;
    static final int TABLE = 51002;
    static final String TARGET = "10.0.0.169";
    static final class Snapshot {
        final int exact;
        final boolean conflict;
        Snapshot(int exact, boolean conflict) {
            this.exact = exact;
            this.conflict = conflict;
        }
    }
    private RootMokaHomeUidRuleEvidence() { }

    static Snapshot inspect(String listing, int uid) {
        if (listing == null || listing.length() > 100000 || uid < 10000 || uid > 99999) {
            throw new IllegalArgumentException("Invalid UID policy inventory.");
        }
        int exact = 0;
        boolean conflict = false;
        String uidToken = uid + "-" + uid;
        for (String raw : listing.split("\\r?\\n")) {
            String line = raw.trim().replaceAll("\\s+", " ");
            if (line.isEmpty()) continue;
            String[] tokens = line.split(" ");
            boolean pref = tokens[0].equals(PRIORITY + ":");
            boolean homeTable = line.matches(
                    ".*\\b(?:lookup|table) " + TABLE + "(?:\\s|$).*");
            if (!pref && !homeTable) continue;

            boolean from = false, dest = false, ingress = false, owner = false;
            boolean table = false, unknown = false;
            if (!pref) { conflict = true; continue; }
            for (int i = 1; i < tokens.length; i++) {
                if (i + 1 >= tokens.length) { unknown = true; break; }
                String kind = tokens[i++];
                String value = tokens[i];
                switch (kind) {
                    case "from":
                        if (from || !value.equals("all")) unknown = true;
                        from = true;
                        break;
                    case "to":
                        if (dest || !(value.equals(TARGET)
                                || value.equals(TARGET + "/32"))) unknown = true;
                        dest = true;
                        break;
                    case "iif":
                        if (ingress || !value.equals("lo")) unknown = true;
                        ingress = true;
                        break;
                    case "uidrange":
                        if (owner || !value.equals(uidToken)) unknown = true;
                        owner = true;
                        break;
                    case "lookup":
                    case "table":
                        if (table || !value.equals(Integer.toString(TABLE))) unknown = true;
                        table = true;
                        break;
                    default:
                        unknown = true;
                }
            }
            if (!unknown && from && dest && ingress && owner && table) exact++;
            else conflict = true;
        }
        if (exact > 1) conflict = true;
        return new Snapshot(exact, conflict);
    }
}
