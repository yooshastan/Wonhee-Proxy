package com.yooshastan.wonheeproxy;

public final class RootHomeTcpSocketEvidenceTest {
    private static int n;
    private static void check(boolean c) {
        if (!c) throw new AssertionError("HOME_TCP_SOCKET_EVIDENCE #" + ++n);
        n++;
    }
    public static void main(String[] args) {
        String private1 = "SYN-SENT 0 1 10.77.0.3:41000 10.0.0.169:4533 users:((\"moka\",pid=11,fd=123)) uid:10393 ino:123 fwmark:0x10000\n";
        String private2 = "ESTAB 0 0 10.77.0.3:41002 10.0.0.169:4533 uid:10308 ino:2 mark:0x20\n";
        String other = "ESTAB 0 0 10.77.0.3:41003 10.0.0.169:4533 uid:99001 ino:3\n";
        String secret = "ESTAB 0 0 10.1.2.3:9999 203.0.113.8:443 users:((\"PASSWORD-SECRET\",pid=5,fd=2)) uid:10393\n";
        String out = RootHomeTcpSocketEvidence.summarize(
                private1 + private2 + other + secret, 10393, 10308);
        check(out.contains("ENDPOINT_SOCKETS=3"));
        check(out.contains("MOKA SYN-SENT mark=0x10000"));
        check(out.contains("BRAVE_APP_UID ESTAB mark=0x20"));
        check(out.contains("OTHER_OR_ISOLATED_UID ESTAB MARK_NOT_VISIBLE"));
        check(!out.contains("PASSWORD-SECRET"));
        check(!out.contains("203.0.113.8"));
        check(!out.contains("pid="));
        check(!out.contains("10.77.0.3"));
        check("NO_ENDPOINT_SOCKET_VISIBLE_AT_SNAPSHOT".equals(
                RootHomeTcpSocketEvidence.summarize(secret,10393,10308)));
        check(!RootHomeTcpSocketEvidence.summarize(
                "SYN-SENT 0 1 10.0.0.169:45330 10.0.0.1:4533",10393,10308)
                .contains("ENDPOINT_SOCKETS"));
        check("SOCKET_INVENTORY_UNAVAILABLE_OR_UNVERIFIED".equals(
                RootHomeTcpSocketEvidence.summarize(null,10393,10308)));
        check("SOCKET_INVENTORY_UNAVAILABLE_OR_UNVERIFIED".equals(
                RootHomeTcpSocketEvidence.summarize(private1,10393,10393)));
        check(RootHomeTcpSocketEvidence.summarize(
                "SYN-SENT 0 1 10.0.0.1:3444 10.0.0.169:4533 uid:10393 uid:10308",
                10393,10308).contains("UNKNOWN_UID"));
        check(RootHomeTcpSocketEvidence.summarize(
                "SYN-SENT 0 1 10.0.0.1:3444 10.0.0.169:4533",
                10393,10308).contains("MARK_NOT_VISIBLE"));
        System.out.println("HOME_TCP_SOCKET_EVIDENCE " + n + " PASS");
    }
}
