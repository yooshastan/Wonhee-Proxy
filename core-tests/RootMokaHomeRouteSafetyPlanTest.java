package com.yooshastan.wonheeproxy;

public final class RootMokaHomeRouteSafetyPlanTest {
    private static int checks;
    static void check(boolean yes) { if (!yes) throw new AssertionError("Gate failed " + checks); checks++; }
    public static void main(String[] args) {
        var p = RootMokaHomeRouteSafetyPlan.compile(10300,"wnm4ea140588150");
        check(!p.activationAllowed());
        check(p.gates.size() == 10);
        check(p.candidateSelector.contains("uidrange 10300-10300"));
        check(p.candidateSelector.contains("to 10.0.0.169/32 lookup 51002"));
        check(p.candidateTerminal.contains("unreachable 10.0.0.169/32"));
        try { RootMokaHomeRouteSafetyPlan.compile(0,"wlan0");throw new AssertionError(); }
        catch(IllegalArgumentException expected) {checks++;}
        for (int missing=0;missing<8;missing++) {
            boolean[] proof={true,true,true,true,true,true,true,true};
            proof[missing]=false;
            String state=RootMokaHomeRouteSafetyPlan.evaluate(true,proof[0],proof[1],proof[2],proof[3],proof[4],proof[5],proof[6],proof[7]);
            check(state.startsWith("REFUSE_"));
        }
        check(RootMokaHomeRouteSafetyPlan.evaluate(false,true,true,true,true,true,true,true,true)
                .equals("BLOCK_HOME_UNREACHABLE"));
        check(RootMokaHomeRouteSafetyPlan.evaluate(true,true,true,true,true,true,true,true,true)
                .equals("STILL_LOCKED_DEVICE_PACKET_PROOF"));
        System.out.println("MOKA_HOME_ROUTE_SAFETY " + checks + " PASS");
    }
}
