package com.yooshastan.wonheeproxy;

public final class RootDnsProbePolicyTest {
    private static void require(boolean value) { if (!value) throw new AssertionError(); }

    private static void refuses(String protocol, String url, String bootstrap) {
        try {
            RootDnsProbePolicy.parse(protocol, url, bootstrap);
            throw new AssertionError("Accepted unsafe DNS config: " + protocol + " " + url);
        } catch (IllegalArgumentException expected) { /* fail closed */ }
    }

    public static void main(String[] unused) {
        RootDnsProbePolicy doh = RootDnsProbePolicy.parse("doh",
                "https://cloudflare-dns.com/dns-query", "1.1.1.1");
        require("doh".equals(doh.protocol) && doh.family == 4 && doh.port == 443);
        RootDnsProbePolicy doh3 = RootDnsProbePolicy.parse("doh3",
                "https://cloudflare-dns.com/dns-query", "2606:4700:4700::1111");
        require("doh3".equals(doh3.protocol) && doh3.family == 6);
        RootDnsProbePolicy doq = RootDnsProbePolicy.parse("doq",
                "quic://dns.adguard-dns.com", "94.140.14.14");
        require("doq".equals(doq.protocol) && doq.port == 853 && doq.family == 4);
        require("dns.adguard-dns.com".equals(doq.hostname));
        require(RootDnsProbePolicy.parse("doq", "quic://dns.example:8853",
                "2606:4700:4700::1111").port == 8853);
        refuses("doq", "https://dns.example/dns-query", "1.1.1.1");
        refuses("doq", "quic://dns.example/path", "1.1.1.1");
        refuses("doq", "quic://user@dns.example", "1.1.1.1");
        refuses("doq", "quic://dns.example?x=1", "1.1.1.1");
        refuses("doq", "quic://dns.example", "dns.example");
        refuses("doq", "quic://dns.example", "fe80::1%wlan0");
        refuses("doh3", "http://dns.example/dns-query", "1.1.1.1");
        refuses("doh3", "https://dns.example", "1.1.1.1");
        refuses("unknown", "quic://dns.example", "1.1.1.1");
        System.out.println("RootDnsProbePolicyTest passed");
    }
}
