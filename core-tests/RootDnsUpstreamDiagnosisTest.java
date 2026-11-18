package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

/** Pure tests; no root access or external DNS traffic. */
public final class RootDnsUpstreamDiagnosisTest {
    private static void expected(String expected, int code, String output) {
        String actual = RootDnsUpstreamDiagnosis.classify(code,
                Collections.singletonList(output));
        if (!expected.equals(actual)) {
            throw new AssertionError(expected + " != " + actual);
        }
    }
    public static void main(String[] args) {
        expected("VERIFIED", 0, "VERIFIED A_COUNT=2");
        expected("UPSTREAM_BIND_FAILED", 1, "REFUSED BIND_FAILED");
        expected("UPSTREAM_INTERFACE_UNAVAILABLE", 1, "REFUSED INTERFACE_UNAVAILABLE");
        expected("UPSTREAM_CONNECT_TLS", 1, "REFUSED TLS_OR_CONNECT_FAILED");
        expected("UPSTREAM_HTTP_INVALID", 1, "REFUSED HTTP_NOT_200");
        expected("UPSTREAM_HTTP_INVALID", 1, "REFUSED WRONG_CONTENT_TYPE");
        expected("UPSTREAM_REPLY_INVALID", 1, "REFUSED DNS_REPLY_INVALID");
        expected("UPSTREAM_REPLY_INVALID", 1, "REFUSED DNS_REPLY_TOO_LARGE");
        expected("UPSTREAM_PROBE_UNAVAILABLE", 1, "REFUSED QUERY_UNAVAILABLE");
        expected("UPSTREAM_PROBE_UNAVAILABLE", 1, "REFUSED REFUSED_SECRET");
        expected("UPSTREAM_PROBE_UNAVAILABLE", 0, "REFUSED BIND_FAILED");
        expected("UPSTREAM_PROBE_UNAVAILABLE", 1, "VERIFIED A_COUNT=2");
        expected("UPSTREAM_PROBE_UNAVAILABLE", 1,
                "REFUSED TLS_OR_CONNECT_FAILED https://secret.example/token=abc");
        expected("UPSTREAM_PROBE_UNAVAILABLE", 1,
                "REFUSED TLS_OR_CONNECT_FAILED\nsecret");
        if (!RootDnsUpstreamDiagnosis.UNAVAILABLE.equals(
                RootDnsUpstreamDiagnosis.classify(1, Arrays.asList(
                        "REFUSED BIND_FAILED", "IP_PRIVATE")))) {
            throw new AssertionError("multiple stdout lines cannot be trusted");
        }
        for (String stage : Arrays.asList(
                "UPSTREAM_BIND_FAILED", "UPSTREAM_INTERFACE_UNAVAILABLE",
                "UPSTREAM_CONNECT_TLS", "UPSTREAM_HTTP_INVALID",
                "UPSTREAM_REPLY_INVALID", "UPSTREAM_PROBE_UNAVAILABLE")) {
            String summary = RootDnsStartFailure.summary(
                    "DNS activation REFUSED before firewall changes [" + stage
                            + "]: https://private.example/dns-query key=secret");
            if (!summary.contains(stage)
                    || summary.contains("private.example")
                    || summary.contains("key=secret")
                    || summary.contains("UNSPECIFIED")) {
                throw new AssertionError("stage leaked or was not recognized: " + stage);
            }
        }
        System.out.println("RootDnsUpstreamDiagnosisTest passed");
    }
}
