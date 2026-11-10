package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class RootLivePeerRouteAuditTest {
    private static void check(boolean good, String why) {
        if (!good) throw new AssertionError(why);
    }

    public static void main(String[] args) {
        String[] skip = {
                "192.168.50.141:48874", "10.0.0.169:4533", "127.0.0.1:53535",
                "100.65.3.4:443", "192.0.2.1:443", "198.51.100.1:443",
                "203.0.113.1:443", "0.0.0.0:443", "224.0.0.251:5353",
                "[fe80::1]:5228", "[fd12::1]:5228", "[2001:db8::7]:443",
                "localhost:443", "1.1.1.1;rm:443", "*:*", "[::]:443",
                "[2607:f8b0::bc%wlan0]:5228", "[2607:f8b0::bc]:0",
                "[2607:f8b0::bc]:65536", "142.251.157.120:abc"
        };
        for (String one : skip) {
            check(RootLivePeerRouteAudit.literalPublicPeer(one) == null,
                    "Refuse unsafe/local/multicast/non-public remote peer: " + one);
        }
        check("142.251.157.120".equals(
                RootLivePeerRouteAudit.literalPublicPeer("142.251.157.120:443")),
                "Allow only canonical public IPv4 literals");
        check(RootLivePeerRouteAudit.literalPublicPeer(
                "[2607:f8b0:4023:c0b::bc]:5228").contains(":"),
                "Allow validated public IPv6 global-unicast literal");
        check(RootLivePeerRouteAudit.literalPublicPeer(
                "141.207.129.233:4500") != null, "Public carrier endpoint may be counted");

        Set<Integer> uids = new LinkedHashSet<>(
                Arrays.asList(1000, 10170, 10180));
        RootLivePeerRouteAudit.Aggregate aggregate =
                new RootLivePeerRouteAudit.Aggregate(uids);
        List<String> tcp = Arrays.asList(
                "ESTAB 0 0 192.168.50.84:51760 "
                        + "[2607:f8b0:4023:c0b::bc]:5228 uid:10180 "
                        + "ino:451 sk:ff fwmark:0xf009f",
                "ESTAB 0 0 192.168.50.84:52113 "
                        + "142.251.157.120:443 uid:10170 ino:452",
                "    sk:aa fwmark:0xc009f",
                "ESTAB 0 0 192.168.50.84:52200 "
                        + "192.168.50.141:48874 uid:10170 fwmark:0xf009f",
                "ESTAB 0 0 192.168.50.84:52001 "
                        + "142.251.157.120:443 uid:10170 fwmark:0xf009f",
                "ESTAB 0 0 192.168.50.84:52111 "
                        + "142.251.157.120:443 uid:10170",
                "ESTAB 0 0 192.168.50.84:52112 "
                        + "142.251.157.120:443 uid:10170 fwmark:0xf009f "
                        + "uid:10180",
                "ESTAB 0 0 192.168.50.84:52113 "
                        + "142.251.157.120:443 uid:999999 fwmark:0x0"
        );
        List<String> udp = Arrays.asList(
                "ESTAB 0 0 192.168.50.84:43696 "
                        + "216.239.36.158:443 uid:10170 ino:222 fwmark:0xf009f",
                "UNCONN 0 0 192.168.50.84:60424 "
                        + "141.207.129.233:4500 uid:1000 fwmark:0xc009f",
                "UNCONN 0 0 192.168.50.84:5353 *:* "
                        + "uid:1000 fwmark:0xc009f"
        );
        aggregate.accept(tcp, udp);
        aggregate.accept(Collections.emptyList(), Collections.emptyList());
        check(aggregate.samples == 2, "Count voluntary samples, not real flows");
        check(aggregate.forUid(10170).size() == 3,
                "Keep three distinct Messages public UID/mark/transport combinations");
        check(aggregate.forUid(10180).size() == 1,
                "Keep public IPv6 push socket mark");
        check(aggregate.forUid(1000).size() == 1,
                "Keep carrier public peer but omit mDNS multicast");
        check(aggregate.missingOrAmbiguousMark >= 1,
                "Missing marks remain unknown, never silently zero");
        check(aggregate.localOrUnconnected >= 2,
                "Private KDE and wildcard UDP sockets must be omitted");
        check(aggregate.rejectedMalformed >= 1,
                "Ambiguous duplicate UIDs must be refused");
        RootLivePeerRouteAudit.Candidate first = aggregate.forUid(10180).get(0);
        check(first.uid == 10180 && first.family == 6 && first.protectedMark(),
                "Actual protected socket mark and observed public IPv6 peer");
        check(!aggregate.forUid(1000).get(0).protectedMark(),
                "Observed public UDP/4500 system mark is not protected");
        int udp443Count = 0;
        for (RootLivePeerRouteAudit.Candidate candidate : aggregate.forUid(10170)) {
            if (candidate.udp443) {
                udp443Count++;
                check("UDP".equals(candidate.transport),
                        "Only UDP/443 can carry the port-specific hint");
            }
        }
        check(udp443Count == 1,
                "Detect candidate UDP/443 without calling TLS/QUIC confirmed");
        check(!aggregate.forUid(1000).get(0).udp443,
                "Android Wi-Fi Calling UDP/4500 must not be mistaken for QUIC");

        for (String protocol : new String[]{"TCP", "UDP"}) {
            RootLivePeerRouteAudit.Aggregate capped =
                    new RootLivePeerRouteAudit.Aggregate(
                            Collections.singleton(10170));
            List<String> lines = new ArrayList<>();
            for (int i = 10; i < 50; i++) {
                lines.add("ESTAB 0 0 192.168.50.84:4567 142.251.157."
                        + i + ":443 uid:10170 fwmark:0xc009f");
            }
            if ("TCP".equals(protocol)) capped.accept(
                    lines, Collections.emptyList());
            else capped.accept(Collections.emptyList(), lines);
            check(capped.forUid(10170).size()
                            == RootLivePeerRouteAudit.MAX_CANDIDATES_PER_UID,
                    "Bound candidates per UID regardless of input volume");
            check(capped.candidateLimitReached > 0,
                    "Report overflow without inventing route verdicts");
        }
        RootLivePeerRouteAudit.Aggregate huge =
                new RootLivePeerRouteAudit.Aggregate(uids);
        huge.accept(Collections.nCopies(
                        RootLivePeerRouteAudit.MAX_SS_LINES + 1, "bad"),
                Collections.emptyList());
        check(!huge.complete, "Refuse oversized diagnostic tool response");

        // Actual report must never contain any Candidate, endpoint or port.
        // The only safe output here is aggregate counts and route categories.
        check(RootLivePeerRouteAudit.MAX_ROUTE_QUERIES
                        <= RootLivePeerRouteAudit.MAX_TOTAL_CANDIDATES,
                "Bound future root ip route get calls per run");
        System.out.println("RootLivePeerRouteAuditTest passed");
    }
}
