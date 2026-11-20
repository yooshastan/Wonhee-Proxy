package com.yooshastan.wonheeproxy;

/** Executable refusal matrix. Deliberately no root, network, or Android state. */
public final class RootMokaHomePolicySafetyCaseTest {
    private static void check(boolean ok, String label) {
        if (!ok) throw new AssertionError(label);
    }

    private static RootMokaHomePolicySafetyCase.Evidence evidence(
            boolean a, boolean b, boolean c, boolean d, boolean e,
            boolean f, boolean g, boolean h) {
        return new RootMokaHomePolicySafetyCase.Evidence(
                10300, "10.0.0.169", 4533, true, a, b, c, d, e, f, g, h);
    }

    public static void main(String[] args) {
        var s = RootMokaHomePolicySafetyCase.Gate.READY_FOR_DEVICE_TEST;
        check(RootMokaHomePolicySafetyCase.assess(evidence(true,true,true,true,true,true,true,true)) == s,
                "full evidence permits device test only");
        check(RootMokaHomePolicySafetyCase.currentLabGate(10300, true)
                == RootMokaHomePolicySafetyCase.Gate.MISSING_IPV4_DENY,
                "current lab must refuse activation");
        check(RootMokaHomePolicySafetyCase.assess(evidence(false,true,true,true,true,true,true,true))
                == RootMokaHomePolicySafetyCase.Gate.MISSING_IPV4_DENY, "v4 leak");
        check(RootMokaHomePolicySafetyCase.assess(evidence(true,false,true,true,true,true,true,true))
                == RootMokaHomePolicySafetyCase.Gate.MISSING_IPV6_DENY, "v6 leak");
        check(RootMokaHomePolicySafetyCase.assess(evidence(true,true,false,true,true,true,true,true))
                == RootMokaHomePolicySafetyCase.Gate.MISSING_UNDERLAY_ISOLATION,
                "underlay escape");
        check(RootMokaHomePolicySafetyCase.assess(evidence(true,true,true,false,true,true,true,true))
                == RootMokaHomePolicySafetyCase.Gate.MISSING_TCP_PORT_ENFORCEMENT,
                "port escape");
        check(RootMokaHomePolicySafetyCase.assess(evidence(true,true,true,true,false,true,true,true))
                == RootMokaHomePolicySafetyCase.Gate.MISSING_DNS_ISOLATION,
                "DNS escape");
        check(RootMokaHomePolicySafetyCase.assess(evidence(true,true,true,true,true,false,true,true))
                == RootMokaHomePolicySafetyCase.Gate.MISSING_CRASH_RECOVERY,
                "crash");
        check(RootMokaHomePolicySafetyCase.assess(evidence(true,true,true,true,true,true,false,true))
                == RootMokaHomePolicySafetyCase.Gate.MISSING_STOP_PROOF,
                "stop");
        check(RootMokaHomePolicySafetyCase.assess(evidence(true,true,true,true,true,true,true,false))
                == RootMokaHomePolicySafetyCase.Gate.NO_LOSS_TEST, "link loss");
        check(RootMokaHomePolicySafetyCase.assess(new RootMokaHomePolicySafetyCase.Evidence(
                10300,"10.0.0.170",4533,true,true,true,true,true,true,true,true,true))
                == RootMokaHomePolicySafetyCase.Gate.BAD_HOME_DESTINATION,
                "destination change");
        check(RootMokaHomePolicySafetyCase.assess(new RootMokaHomePolicySafetyCase.Evidence(
                10300,"10.0.0.169",4533,false,true,true,true,true,true,true,true,true))
                == RootMokaHomePolicySafetyCase.Gate.NO_OWNED_HOME_LINK,
                "orphaned link");
        System.out.println("MOKA_HOME_POLICY_SAFETY_CASE: 12/12 PASS");
    }
}
