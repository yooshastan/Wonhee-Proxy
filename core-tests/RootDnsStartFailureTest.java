package com.yooshastan.wonheeproxy;

public final class RootDnsStartFailureTest {
    private static void check(boolean truth, String message) {
        if (!truth) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        String upstream = "DNS activation REFUSED before firewall changes "
                + "[UPSTREAM_ROUTE]: private://secret.internal:443 "
                + "https://private.example/dns-query token=123.";
        String rendered = RootDnsStartFailure.summary(upstream);
        check(rendered.contains("UPSTREAM_ROUTE"),
                "Must preserve validated upstream routing phase");
        check(rendered.contains("Chosen DNS bootstrap"),
                "Must offer a read-only next step");
        check(!rendered.contains("secret.internal") && !rendered.contains("token=123")
                && !rendered.contains("private.example"),
                "Never echo potentially sensitive raw failure reports");
        check(RootDnsStartFailure.summary(
                "DNS activation failed [LOCAL_DNS_HEALTH]; exact owned rules rolled back.")
                .contains("LOCAL_DNS_HEALTH"), "Must preserve post-ledger health phase");
        check(RootDnsStartFailure.summary(
                "DNS ROLLBACK NOT VERIFIED [FIREWALL_INSTALL].").contains("FIREWALL_INSTALL"),
                "Must preserve post-ledger firewall install stage");
        check(RootDnsStartFailure.summary(
                "DNS activation REFUSED [POLICY_PREFLIGHT] ").contains("Private DNS is OFF"),
                "Private DNS remains off; never recommend enabling Automatic/Custom");
        check(RootDnsStartFailure.summary(
                "DNS activation refused [NEVER_DEFINED]: peer key abc").contains("UNSPECIFIED"),
                "Unknown phase must fail closed");
        check(RootDnsStartFailure.summary(
                "No phase available: private hostname").contains("UNSPECIFIED"),
                "Missing phase must not fabricate attribution");
        check(RootDnsStartFailure.summary(null).contains("UNSPECIFIED"),
                "Null report must be handled");
        check(!RootDnsStartFailure.summary(
                "No phase available: https://secret.example").contains("secret.example"),
                "Unknown report must not echo upstream data");
        System.out.println("RootDnsStartFailureTest passed");
    }
}
