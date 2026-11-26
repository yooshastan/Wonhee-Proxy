package com.yooshastan.wonheeproxy;

/** Journal-first, exact-owned transport trial state machine. A successful
 * start is structural evidence, never authorization for credential traffic. */
final class RootTransportGuardLifecycle {
    enum State { BASELINE, MARKED, ACTIVE, RULE_ONLY, GONE, CONFLICT }
    interface Kernel {
        State inspect() throws Exception;
        void mark() throws Exception;
        void insert() throws Exception;
        void remove() throws Exception;
        void unmark() throws Exception;
    }
    interface Journal {
        boolean pending() throws Exception;
        void intent() throws Exception;
        void clear() throws Exception;
    }
    enum Outcome { ACTIVE_STRUCTURAL_ONLY, CLEAN, REFUSED, ROLLED_BACK, RECOVERY_PAUSED }
    private RootTransportGuardLifecycle() {}

    static Outcome start(Kernel kernel, Journal journal) throws Exception {
        if (journal.pending() || kernel.inspect() != State.BASELINE) return Outcome.REFUSED;
        journal.intent(); // immutable identity and prior state before any kernel write
        if (!journal.pending()) throw new IllegalStateException("Missing durable intent");
        try {
            if (kernel.inspect() != State.BASELINE) throw new IllegalStateException();
            kernel.mark();
            if (kernel.inspect() != State.MARKED) throw new IllegalStateException();
            kernel.insert();
            if (kernel.inspect() != State.ACTIVE) throw new IllegalStateException();
            return Outcome.ACTIVE_STRUCTURAL_ONLY;
        } catch (Exception failure) {
            return stop(kernel, journal) == Outcome.CLEAN
                    ? Outcome.ROLLED_BACK : Outcome.RECOVERY_PAUSED;
        }
    }

    static Outcome stop(Kernel kernel, Journal journal) {
        try {
            if (!journal.pending()) return Outcome.CLEAN;
            State state = kernel.inspect();
            if (state == State.CONFLICT) return Outcome.RECOVERY_PAUSED;
            if (state == State.ACTIVE || state == State.RULE_ONLY) {
                kernel.remove(); // revoke exception BEFORE restoring transport mark
                state = kernel.inspect();
                if (state != State.MARKED && state != State.BASELINE)
                    return Outcome.RECOVERY_PAUSED;
            }
            if (state == State.MARKED) {
                kernel.unmark();
                state = kernel.inspect();
            }
            if (state != State.BASELINE && state != State.GONE)
                return Outcome.RECOVERY_PAUSED;
            journal.clear();
            return journal.pending() ? Outcome.RECOVERY_PAUSED : Outcome.CLEAN;
        } catch (Exception failure) {
            return Outcome.RECOVERY_PAUSED;
        }
    }
}
