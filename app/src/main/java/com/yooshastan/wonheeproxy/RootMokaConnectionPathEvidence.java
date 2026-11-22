package com.yooshastan.wonheeproxy;

/**
 * Non-executing interpretation of the journal/rule/route observations.
 * This distinguishes absence of routing from proof of packet delivery.
 */
final class RootMokaConnectionPathEvidence {
    private RootMokaConnectionPathEvidence() { }

    /**
     * READ-ONLY: a verified, separately journaled Brave selector may share
     * Home table 51002 at a different priority (12699). Exclude ONLY that
     * single exact rule from Moka's diagnostic inventory. Unknown rules still
     * flag a conflict; never use this function to authorize kernel changes.
     */
    static RootMokaHomeUidRuleEvidence.Snapshot mokaWithBrave(
            String policy, int mokaUid, int braveUid,
            boolean braveJournalMatches) {
        if (policy == null || mokaUid < 10000) {
            throw new IllegalArgumentException("Missing UID routing evidence.");
        }
        if (!braveJournalMatches || braveUid < 10000
                || braveUid == mokaUid
                || RootBraveHomePilotPlan.exactSelector(policy, braveUid) != 1) {
            return RootMokaHomeUidRuleEvidence.inspect(policy, mokaUid);
        }
        StringBuilder filtered = new StringBuilder();
        for (String raw : policy.split("\\r?\\n")) {
            String line = RootBraveHomePilotPlan.normalized(raw);
            if (line.startsWith(RootBraveHomePilotPlan.PRIORITY + ":")) {
                // Already verified to be the one exact Brave rule.
                continue;
            }
            filtered.append(raw).append('\n');
        }
        return RootMokaHomeUidRuleEvidence.inspect(filtered.toString(), mokaUid);
    }

    static String selectorState(boolean journalPresent,
            RootMokaHomeUidRuleEvidence.Snapshot rule, String lastOutcome) {
        if (rule == null || rule.conflict || rule.exact > 1) {
            return "SELECTOR_CONFLICT_OR_UNVERIFIED";
        }
        if (journalPresent && rule.exact == 1) return "SELECTOR_PRESENT_WITH_JOURNAL";
        if (journalPresent) return "JOURNAL_PRESENT_RULE_MISSING";
        if (rule.exact == 1) return "RULE_PRESENT_WITHOUT_OWNERSHIP_JOURNAL";
        if ("CLEAN_STOPPED".equals(lastOutcome)) return "NO_RULE_AFTER_SAFE_STOP";
        if ("ROLLED_BACK".equals(lastOutcome)) return "NO_RULE_AFTER_ROLLBACK";
        if (lastOutcome != null && lastOutcome.startsWith("REFUSED_")) {
            return "NO_RULE_AFTER_REFUSAL";
        }
        if ("ACTIVE_VERIFIED".equals(lastOutcome)) {
            return "NO_RULE_AFTER_PRIOR_VERIFICATION";
        }
        return "NO_RULE_NO_RECORDED_ACTIVATION";
    }

    static String syntheticRoute(String raw, String homeDevice) {
        if (raw == null || raw.isEmpty()) return "ROUTE_GET_UNAVAILABLE";
        String normalized = " " + raw.replaceAll("\\s+", " ").trim() + " ";
        if (normalized.contains(" unreachable ")
                || normalized.contains(" prohibit ")
                || normalized.contains(" blackhole ")) {
            return "ROUTE_UNREACHABLE";
        }
        if (homeDevice != null && homeDevice.matches("wnm[0-9a-f]{12}")
                && normalized.contains(" dev " + homeDevice + " ")
                && normalized.contains(" table 51002 ")) {
            return "SYNTHETIC_HOME_TABLE_51002";
        }
        if (normalized.matches(".* dev (rmnet\\S*|ccmni\\S*) .*")) {
            return "SYNTHETIC_CELLULAR";
        }
        if (normalized.contains(" dev ")) return "SYNTHETIC_OTHER_INTERFACE";
        return "SYNTHETIC_UNKNOWN";
    }
}
