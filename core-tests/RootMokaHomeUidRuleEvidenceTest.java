package com.yooshastan.wonheeproxy;

public final class RootMokaHomeUidRuleEvidenceTest {
    private static int count;
    static void require(boolean b) { count++; if (!b) throw new AssertionError("UID rule " + count); }
    static final String BASE = "0: from all lookup local\n"
            + "10000: from all fwmark 0xc0000/0xd0000 lookup legacy_system\n";
    static final String RULE = "12700: from all to 10.0.0.169 iif lo uidrange 10300-10300 lookup 51002\n";
    public static void main(String[] args) {
        var empty = RootMokaHomeUidRuleEvidence.inspect(BASE,10300);
        require(empty.exact == 0 && !empty.conflict);
        var owned = RootMokaHomeUidRuleEvidence.inspect(BASE+RULE,10300);
        require(owned.exact == 1 && !owned.conflict);
        var reordered = RootMokaHomeUidRuleEvidence.inspect(BASE +
                "12700: from all iif lo uidrange 10300-10300 to 10.0.0.169/32 table 51002\n",10300);
        require(reordered.exact == 1 && !reordered.conflict);
        require(RootMokaHomeUidRuleEvidence.inspect(BASE + RULE + RULE,10300).conflict);
        require(RootMokaHomeUidRuleEvidence.inspect(BASE +
                "12700: from all to 10.0.0.169 iif lo uidrange 10301-10301 lookup 51002\n",10300).conflict);
        require(RootMokaHomeUidRuleEvidence.inspect(BASE +
                "12700: from all to 10.0.0.169 iif lo uidrange 10300-10300 fwmark 0x0/0x20000 lookup 51002\n",10300).conflict);
        require(RootMokaHomeUidRuleEvidence.inspect(BASE +
                "12699: from all to 10.0.0.169 iif lo uidrange 10300-10300 lookup 51002\n",10300).conflict);
        require(RootMokaHomeUidRuleEvidence.inspect(BASE +
                "12700: from all lookup main\n",10300).conflict);
        require(RootMokaHomeUidRuleEvidence.inspect(BASE +
                "12700: from all to 10.0.0.169/24 iif lo uidrange 10300-10300 lookup 51002\n",10300).conflict);
        System.out.println("MOKA_HOME_UID_RULE_EVIDENCE " + count + " PASS");
    }
}
