package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class RootLiveSocketMarkEvidenceTest {
    private static void check(boolean yes, String why) {
        if (!yes) throw new AssertionError(why);
    }

    public static void main(String[] args) {
        Set<Integer> target = new LinkedHashSet<>(
                Arrays.asList(1000, 10170, 10180));
        String privateEndpoint = "142.251.157.120:443";
        List<String> tcp = Arrays.asList(
                "ESTAB 0 0 192.168.50.84:43696 " + privateEndpoint
                        + " uid:10170 ino:123 sk:abcdef fwmark:0x20000",
                "ESTAB 0 0 192.168.50.84:53000 2607:f8b0::bc:5228 "
                        + "uid:10180 ino:124 sk:abcdef",
                "ESTAB 0 0 192.168.50.84:59000 192.0.2.5:5228",
                "ESTAB 0 0 192.168.50.84:61000 198.51.100.3:443",
                "    uid:1000 ino:125 sk:abcdef fwmark:0xc0000");
        List<String> udp = Arrays.asList(
                "UNCONN 0 0 192.168.50.84:12345 203.0.113.5:443 "
                        + "uid:10170 ino:126 fwmark:0x0",
                "UNCONN 0 0 192.168.50.84:12346 203.0.113.7:443 "
                        + "uid:10170 ino:127 fwmark:0x10001",
                "UNCONN 0 0 192.168.50.84:12347 203.0.113.8:443 "
                        + "uid:10170 ino:128 fwmark:0x10002",
                "UNCONN 0 0 192.168.50.84:12348 203.0.113.9:443 "
                        + "uid:10170 ino:129 fwmark:0x10003",
                "UNCONN 0 0 192.168.50.84:12349 203.0.113.10:443 "
                        + "uid:10170 ino:130 fwmark:0x10004",
                "UNCONN 0 0 192.168.50.84:12350 203.0.113.11:443 "
                        + "uid:99999 ino:131 fwmark:0x20000");
        RootLiveSocketMarkEvidence.Snapshot one =
                RootLiveSocketMarkEvidence.parse(tcp, udp, target);
        check(one.complete, "Valid sample should parse");
        check(one.forUid(10170).tcp == 1 && one.forUid(10170).udp == 5,
                "TCP + UDP ownership count");
        check(one.forUid(10170).protectedSockets == 1,
                "Only actual observed fwmark with protected bit can be protected");
        check(one.forUid(10170).ordinaryMarked == 5,
                "Explicit zero is not treated as missing; other explicit marks count");
        check(one.forUid(10180).markUnavailable == 1
                        && one.forUid(10180).protectedSockets == 0,
                "Missing ss fwmark must NEVER silently imply zero or protected");
        check(one.forUid(1000).ordinaryMarked == 1
                        && one.forUid(1000).protectedSockets == 0,
                "System sample's mark without protected bit is unprotected");
        check(one.unidentified == 1, "Records with no UID must remain anonymous");
        check(RootLiveSocketMarkEvidence.boundedMarks(one.forUid(10170)).size() == 4,
                "Marked socket example list must remain bounded");

        String report = RootLiveSocketMarkEvidence.safeSummary(
                "Google Messages", 10170, one.forUid(10170));
        check(!report.contains(privateEndpoint) && !report.contains("192.168.50.84")
                        && !report.contains("ino:") && !report.contains("sk:"),
                "Report may not include private endpoints, inode or socket cookies");
        check(report.contains("fwmark available on 6"),
                "Only explicitly observed marks should be counted");

        RootLiveSocketMarkEvidence.Snapshot other =
                RootLiveSocketMarkEvidence.parse(Collections.singletonList(
                        "ESTAB 0 0 local peer uid:10170 ino:12"), Collections.emptyList(),
                        target);
        one.mergeMax(other);
        check(one.forUid(10170).tcp == 1 && one.forUid(10170).udp == 5,
                "Multiple passive samples should use max socket counts, never sum flows");

        RootLiveSocketMarkEvidence.Snapshot ambiguous =
                RootLiveSocketMarkEvidence.parse(Arrays.asList(
                        "ESTAB 0 0 local peer uid:10170 uid:10180 fwmark:0x20000",
                        "ESTAB 0 0 local peer uid:10170 fwmark:0x20000 fwmark:0x0"
                ), Collections.emptyList(), target);
        check(!ambiguous.complete, "Ambiguous UID or repeated marks must fail closed");

        RootLiveSocketMarkEvidence.Snapshot unsupported =
                RootLiveSocketMarkEvidence.parse(null, Collections.emptyList(), target);
        check(!unsupported.complete, "Absent ss output cannot prove socket isolation");

        RootLiveSocketMarkEvidence.Snapshot empty =
                RootLiveSocketMarkEvidence.parse(Collections.emptyList(),
                        Collections.emptyList(), target);
        check(empty.forUid(10170).visible() == 0,
                "Unobserved transient sockets cannot be declared safe");
        check(RootLiveSocketMarkEvidence.safeSummary("Messages", 10170,
                        empty.forUid(10170)).contains("NO SOCKETS OBSERVED"),
                "Missing ephemeral socket must be called unobserved");

        // Bounded, cancellation-aware observation: stop after a defined
        // monotonic window, never start an unbounded background sampler.
        check(RootLiveSocketMarkEvidence.burstAllowed(0, 0L, false),
                "First voluntary burst sample should be allowed");
        check(RootLiveSocketMarkEvidence.burstAllowed(10, 2000L, false),
                "A healthy sample is allowed inside bounded window");
        check(!RootLiveSocketMarkEvidence.burstAllowed(
                RootLiveSocketMarkEvidence.MAX_BURST_SAMPLES, 2000L, false),
                "Sample maximum must stop even when fast");
        check(!RootLiveSocketMarkEvidence.burstAllowed(10,
                RootLiveSocketMarkEvidence.MAX_BURST_MILLIS, false),
                "Wall clock maximum must stop the sampler");
        check(!RootLiveSocketMarkEvidence.burstAllowed(5, 500L, true),
                "User Stop must prevent the next query");
        check(!RootLiveSocketMarkEvidence.burstAllowed(1, -1L, false),
                "Clock reset refuses unexpected elapsed times");
        System.out.println("RootLiveSocketMarkEvidenceTest passed");
    }
}
