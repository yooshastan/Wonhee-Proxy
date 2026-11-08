package com.yooshastan.wonheeproxy;

public final class RootTrackerPolicyTest {
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        RootTrackerPolicy.Config off = RootTrackerPolicy.compile(false, "", "");
        check(!off.shouldBlock("app-measurement.com") && off.serialized().isEmpty(), "off mode");
        RootTrackerPolicy.Config on = RootTrackerPolicy.compile(true,
                " Telemetry.Example.COM\ncustom.example.net\n", "metrics.telemetry.example.com");
        check(on.shouldBlock("app-measurement.com"), "built-in");
        check(on.explain("metrics.telemetry.example.com").startsWith("ALLOWLIST"), "allow explanation");
        check(on.explain("x.app-measurement.com").startsWith("BLOCKLIST"), "block explanation");
        check(on.explain("ordinary.example.net").startsWith("NO MATCH"), "no match");
        check(on.explain("bad name").startsWith("INVALID DOMAIN"), "domain validation");
        check(on.shouldBlock("x.app-measurement.com"), "subdomain");
        check(!on.shouldBlock("notapp-measurement.com"), "boundary");
        check(on.shouldBlock("other.telemetry.example.com"), "custom");
        check(!on.shouldBlock("metrics.telemetry.example.com"), "allow override");
        check(!on.shouldBlock("sub.metrics.telemetry.example.com"), "allow child");
        check(on.serialized().contains("block telemetry.example.com\n"), "serialized custom");
        check(on.serialized().contains("allow metrics.telemetry.example.com\n"), "serialized allow");
        for (String bad : new String[]{"*.example.com", "https://example.com", "10.0.0.1",
                "example..com", "localhost", "company.local", "foo_internal.com"}) {
            try {
                RootTrackerPolicy.compile(true, bad, "");
                throw new AssertionError("accepted invalid domain " + bad);
            } catch (IllegalArgumentException expected) { /* refused */ }
        }
        System.out.println("RootTrackerPolicyTest PASS");
    }
}
