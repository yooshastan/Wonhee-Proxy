package com.yooshastan.wonheeproxy;

public final class DoHProbePolicyTest {
    private static void require(boolean value) { if (!value) throw new AssertionError(); }

    private static void refuses(String url, String bootstrap) {
        try {
            DoHProbePolicy.parse(url, bootstrap);
            throw new AssertionError("Accepted unsafe DoH configuration: " + url);
        } catch (IllegalArgumentException expected) { /* strict fail */ }
    }

    public static void main(String[] unused) {
        DoHProbePolicy publicDns = DoHProbePolicy.parse(
                "https://cloudflare-dns.com/dns-query", "1.1.1.1");
        require(publicDns.family == 4 && publicDns.port == 443);
        require("cloudflare-dns.com".equals(publicDns.hostname));
        DoHProbePolicy custom = DoHProbePolicy.parse(
                "https://resolver.private.test:8443/custom/dns", "2606:4700:4700::1111");
        require(custom.family == 6 && custom.port == 8443);
        refuses("http://dns.example/dns-query", "1.1.1.1");
        refuses("https://username:password@dns.example/dns-query", "1.1.1.1");
        refuses("https://dns.example/dns-query?token=secret", "1.1.1.1");
        refuses("https://dns.example/dns-query#fragment", "1.1.1.1");
        refuses("https://dns.example", "1.1.1.1");
        refuses("https://dns.example/dns-query", "resolver.example");
        refuses("https://dns.example/dns-query", "fe80::1%eth0");
        refuses("https://dns.example/dns-query", "10.0.0.999");
        require(DoHProbePolicy.approvedTunnel(true, true, true,
                "wnm123", "wnm123", "wnm123"));
        require(!DoHProbePolicy.approvedTunnel(true, true, true,
                "wnm123", "wnm456", "wnm123"));
        require(!DoHProbePolicy.approvedTunnel(true, true, true,
                "wnm123", "wnm123", "wlan0"));
        require(!DoHProbePolicy.approvedTunnel(true, false, true,
                "wnm123", "wnm123", "wnm123"));
        require(!DoHProbePolicy.approvedTunnel(false, true, true,
                "wnm123", "wnm123", "wnm123"));
        require(!DoHProbePolicy.approvedTunnel(true, true, false,
                "wnm123", "wnm123", "wnm123"));
        System.out.println("DoHProbePolicyTest passed");
    }
}
