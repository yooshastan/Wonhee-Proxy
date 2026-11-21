package com.yooshastan.wonheeproxy;

/**
 * Non-executing interpretation of the journal/rule/route observations.
 * This distinguishes absence of routing from proof of packet delivery.
 */
final class RootMokaConnectionPathEvidence {
    private RootMokaConnectionPathEvidence() { }

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
