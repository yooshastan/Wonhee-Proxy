package com.yooshastan.wonheeproxy;

public final class RootMultiRecoveryPolicyTest {
    public static void main(String[] args) {
        long now = 1_700_000_000_000L;
        check(RootMultiRecoveryPolicy.permitted(true, true, false, 0, 0, now),
                "explicitly enabled intent permits first recovery");
        check(!RootMultiRecoveryPolicy.permitted(false, true, false, 0, 0, now),
                "disabled setting never performs recovery");
        check(!RootMultiRecoveryPolicy.permitted(true, false, false, 0, 0, now),
                "no desired session means no recovery");
        check(!RootMultiRecoveryPolicy.permitted(true, true, true, 0, 0, now),
                "manual stop wins over persisted intent");
        check(!RootMultiRecoveryPolicy.permitted(true, true, false, 1, now + 1, now),
                "backoff must be honored");
        check(RootMultiRecoveryPolicy.permitted(true, true, false, 1, now, now),
                "retry resumes when due");
        check(!RootMultiRecoveryPolicy.permitted(true, true, false, 6, 0, now),
                "six failures exhaust automatic attempts");
        check(RootMultiRecoveryPolicy.nextAttemptAt(now, 1) == now + 5_000L,
                "first retry delay");
        check(RootMultiRecoveryPolicy.nextAttemptAt(now, 3) == now + 30_000L,
                "third retry delay");
        check(RootMultiRecoveryPolicy.nextAttemptAt(now, 6) == now + 300_000L,
                "last retry delay");
        check(RootMultiRecoveryPolicy.nextAttemptAt(Long.MAX_VALUE - 1, 6)
                        == Long.MAX_VALUE, "overflow is bounded");
        System.out.println("RootMultiRecoveryPolicyTest: PASS");
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}
