package com.yooshastan.wonheeproxy;

public final class RootMokaHomeTerminalRouteEvidenceTest {
    static int passed;
    private static void check(boolean yes) {
        passed++;
        if (!yes) throw new AssertionError("Route evidence failed check " + passed);
    }
    private static final String DEV = "wnm4ea140588150";
    private static RootMokaHomeTerminalRouteEvidence.Snapshot checkLines(
            String terminal) {
        return RootMokaHomeTerminalRouteEvidence.inspect(
                "10.0.0.169 dev " + DEV + " scope link\n"
                + "10.77.0.0/24 dev " + DEV + " scope link\n"
                + terminal, DEV);
    }
    public static void main(String[] args) {
        var base = checkLines("");
        check(base.homePresent && !base.terminalPresent && !base.collision);
        var safe = checkLines("unreachable 10.0.0.169 metric 42700\n");
        check(safe.homePresent && safe.terminalPresent && !safe.collision);
        var longer = checkLines(
                "unreachable 10.0.0.169/32 proto boot metric 42700\n");
        check(longer.homePresent && longer.terminalPresent && !longer.collision);
        var wrongMetric = checkLines("unreachable 10.0.0.169 metric 123\n");
        check(!wrongMetric.terminalPresent && wrongMetric.collision);
        var unknown = checkLines("unreachable 10.0.0.169 via 1.1.1.1 metric 42700\n");
        check(unknown.collision);
        var duplicated = checkLines("unreachable 10.0.0.169 metric 42700\n"
                + "unreachable 10.0.0.169 metric 42700\n");
        check(duplicated.collision);
        var foreign = checkLines("10.0.0.169 via 100.106.183.223 dev rmnet16\n");
        check(foreign.collision);
        var missing = RootMokaHomeTerminalRouteEvidence.inspect(
                "10.77.0.0/24 dev " + DEV + "\n", DEV);
        check(!missing.homePresent && !missing.terminalPresent && !missing.collision);
        try {
            RootMokaHomeTerminalRouteEvidence.inspect("", "rmnet16");
            throw new AssertionError("Wrong device accepted");
        } catch (IllegalArgumentException expected) { passed++; }
        System.out.println("MOKA_HOME_TERMINAL_ROUTE_EVIDENCE " + passed + " PASS");
    }
}
