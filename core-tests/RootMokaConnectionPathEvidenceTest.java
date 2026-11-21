package com.yooshastan.wonheeproxy;

public final class RootMokaConnectionPathEvidenceTest {
    private static int checks;
    private static void check(boolean b) {
        checks++;
        if (!b) throw new AssertionError("Moka path evidence #" + checks);
    }
    public static void main(String[] args) {
        var absent = new RootMokaHomeUidRuleEvidence.Snapshot(0,false);
        var owned = new RootMokaHomeUidRuleEvidence.Snapshot(1,false);
        var conflict = new RootMokaHomeUidRuleEvidence.Snapshot(0,true);
        check("NO_RULE_AFTER_SAFE_STOP".equals(
                RootMokaConnectionPathEvidence.selectorState(false, absent, "CLEAN_STOPPED")));
        check("NO_RULE_AFTER_ROLLBACK".equals(
                RootMokaConnectionPathEvidence.selectorState(false, absent, "ROLLED_BACK")));
        check("NO_RULE_AFTER_REFUSAL".equals(
                RootMokaConnectionPathEvidence.selectorState(false, absent, "REFUSED_CELLULAR_REQUIRED")));
        check("NO_RULE_AFTER_PRIOR_VERIFICATION".equals(
                RootMokaConnectionPathEvidence.selectorState(false, absent, "ACTIVE_VERIFIED")));
        check("NO_RULE_NO_RECORDED_ACTIVATION".equals(
                RootMokaConnectionPathEvidence.selectorState(false, absent, "NEVER_REQUESTED")));
        check("JOURNAL_PRESENT_RULE_MISSING".equals(
                RootMokaConnectionPathEvidence.selectorState(true, absent, "ACTIVE_VERIFIED")));
        check("SELECTOR_PRESENT_WITH_JOURNAL".equals(
                RootMokaConnectionPathEvidence.selectorState(true, owned, "ACTIVE_VERIFIED")));
        check("RULE_PRESENT_WITHOUT_OWNERSHIP_JOURNAL".equals(
                RootMokaConnectionPathEvidence.selectorState(false, owned, "CLEAN_STOPPED")));
        check("SELECTOR_CONFLICT_OR_UNVERIFIED".equals(
                RootMokaConnectionPathEvidence.selectorState(true, conflict, "ACTIVE_VERIFIED")));
        check("SELECTOR_CONFLICT_OR_UNVERIFIED".equals(
                RootMokaConnectionPathEvidence.selectorState(true, null, "ACTIVE_VERIFIED")));
        check("SYNTHETIC_HOME_TABLE_51002".equals(
                RootMokaConnectionPathEvidence.syntheticRoute(
                        "10.0.0.169 dev wnm4ea140588150 table 51002 src 10.77.0.3 uid 10300\n cache",
                        "wnm4ea140588150")));
        check("SYNTHETIC_CELLULAR".equals(
                RootMokaConnectionPathEvidence.syntheticRoute(
                        "10.0.0.169 dev rmnet16 table rmnet16 src 100.106.183.223 uid 10300",
                        "wnm4ea140588150")));
        check("SYNTHETIC_OTHER_INTERFACE".equals(
                RootMokaConnectionPathEvidence.syntheticRoute(
                        "10.0.0.169 dev wlan0 src 192.168.50.2", "wnm4ea140588150")));
        check("ROUTE_UNREACHABLE".equals(
                RootMokaConnectionPathEvidence.syntheticRoute(
                        "unreachable 10.0.0.169", "wnm4ea140588150")));
        check("ROUTE_GET_UNAVAILABLE".equals(
                RootMokaConnectionPathEvidence.syntheticRoute(null,"wnm4ea140588150")));
        check("SYNTHETIC_OTHER_INTERFACE".equals(
                RootMokaConnectionPathEvidence.syntheticRoute(
                        "10.0.0.169 dev wnm4ea140588150 src 10.77.0.3",
                        "wnm4ea140588150")));
        System.out.println("MOKA_CONNECTION_PATH_EVIDENCE " + checks + " PASS");
    }
}
