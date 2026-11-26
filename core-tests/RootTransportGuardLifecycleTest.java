package com.yooshastan.wonheeproxy;

public final class RootTransportGuardLifecycleTest {
    private static void check(boolean ok) { if (!ok) throw new AssertionError(); }
    private static final class Trial implements RootTransportGuardLifecycle.Kernel,
            RootTransportGuardLifecycle.Journal {
        boolean pending, mark, rule, conflict, gone;
        String order = "";
        int failAfter;
        public boolean pending() { return pending; }
        public void intent() { pending = true; order += "J"; }
        public void clear() { check(!mark && !rule || gone); pending = false; order += "C"; }
        public RootTransportGuardLifecycle.State inspect() {
            if (conflict) return RootTransportGuardLifecycle.State.CONFLICT;
            if (gone) return RootTransportGuardLifecycle.State.GONE;
            if (rule) return mark ? RootTransportGuardLifecycle.State.ACTIVE
                    : RootTransportGuardLifecycle.State.RULE_ONLY;
            return mark ? RootTransportGuardLifecycle.State.MARKED
                    : RootTransportGuardLifecycle.State.BASELINE;
        }
        public void mark() throws Exception {
            check(pending && !mark && !rule); mark = true; order += "M";
            if (failAfter == 1) throw new Exception();
        }
        public void insert() throws Exception {
            check(pending && mark && !rule); rule = true; order += "I";
            if (failAfter == 2) throw new Exception();
        }
        public void remove() throws Exception {
            check(pending && rule);
            if (failAfter == 3) throw new Exception();
            rule = false; order += "R";
        }
        public void unmark() { check(pending && mark && !rule); mark = false; order += "U"; }
    }
    public static void main(String[] args) throws Exception {
        Trial t = new Trial();
        check(RootTransportGuardLifecycle.start(t,t)
                == RootTransportGuardLifecycle.Outcome.ACTIVE_STRUCTURAL_ONLY);
        check(t.order.equals("JMI"));
        check(RootTransportGuardLifecycle.start(t,t) == RootTransportGuardLifecycle.Outcome.REFUSED);
        check(RootTransportGuardLifecycle.stop(t,t) == RootTransportGuardLifecycle.Outcome.CLEAN);
        check(t.order.equals("JMIRUC"));
        for (int failure : new int[]{1,2}) {
            t = new Trial(); t.failAfter = failure;
            check(RootTransportGuardLifecycle.start(t,t) == RootTransportGuardLifecycle.Outcome.ROLLED_BACK);
            check(!t.pending && !t.rule && !t.mark);
        }
        t = new Trial(); t.pending = true; t.mark = true; t.rule = true; t.failAfter = 3;
        check(RootTransportGuardLifecycle.stop(t,t) == RootTransportGuardLifecycle.Outcome.RECOVERY_PAUSED);
        check(t.pending && t.mark && t.rule);
        t.failAfter = 0;
        check(RootTransportGuardLifecycle.stop(t,t) == RootTransportGuardLifecycle.Outcome.CLEAN);
        check(t.order.equals("RUC"));
        t = new Trial(); t.pending = true; t.conflict = true;
        check(RootTransportGuardLifecycle.stop(t,t) == RootTransportGuardLifecycle.Outcome.RECOVERY_PAUSED);
        check(t.pending && t.order.isEmpty());
        t = new Trial(); t.pending = true; t.rule = true;
        check(RootTransportGuardLifecycle.stop(t,t) == RootTransportGuardLifecycle.Outcome.CLEAN);
        check(t.order.equals("RC"));
        t = new Trial(); t.pending = true; t.gone = true;
        check(RootTransportGuardLifecycle.stop(t,t) == RootTransportGuardLifecycle.Outcome.CLEAN);
        check(t.order.equals("C"));
        System.out.println("RootTransportGuardLifecycleTest passed");
    }
}
