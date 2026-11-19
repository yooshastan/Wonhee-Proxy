package com.yooshastan.wonheeproxy;

/** No kernel or root calls. Mock Android iproute2 output only. */
public final class RootIsolatedWireGuardKernelListingTest {
    private static final String DEV = "wnm68fe81200daa";
    private static void match(RootIsolatedWireGuardKernelListing.Match expected,
            RootIsolatedWireGuardKernelListing.Match actual, String reason) {
        if (expected != actual) {
            throw new AssertionError(reason + ": " + actual);
        }
    }

    public static void main(String[] args) {
        RootIsolatedWireGuardKernelListing.Match exact =
                RootIsolatedWireGuardKernelListing.Match.EXACT;
        RootIsolatedWireGuardKernelListing.Match foreign =
                RootIsolatedWireGuardKernelListing.Match.FOREIGN_OR_CHANGED;
        RootIsolatedWireGuardKernelListing.Match absent =
                RootIsolatedWireGuardKernelListing.Match.ABSENT;
        String link = "16: " + DEV
                + ": <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue "
                + "state UNKNOWN mode DEFAULT group default qlen 1000 "
                + "wireguard\n";
        match(exact, RootIsolatedWireGuardKernelListing.interfaceKind(link, DEV),
                "Exact WireGuard kernel link");
        match(exact, RootIsolatedWireGuardKernelListing.interfaceUp(link, DEV),
                "Link's UP flag");
        match(absent, RootIsolatedWireGuardKernelListing.interfaceUp(
                link.replace("NOARP,UP,LOWER_UP", "NOARP"), DEV),
                "A stopped link must not pretend to be up");
        match(absent, RootIsolatedWireGuardKernelListing.interfaceKind("", DEV),
                "Missing kernel interface");
        match(foreign, RootIsolatedWireGuardKernelListing.interfaceKind(
                link.replace("wireguard", "dummy"), DEV),
                "Foreign link type");
        match(foreign, RootIsolatedWireGuardKernelListing.interfaceKind(
                link.replace(DEV, DEV + "a"), DEV),
                "Prefix-colliding tunnel name");

        String v4 = "16: " + DEV
                + "    inet 10.150.0.2/32 scope global " + DEV + "\n";
        match(exact, RootIsolatedWireGuardKernelListing.address(
                v4, 4, "10.150.0.2/32", DEV), "IPv4 host");
        match(absent, RootIsolatedWireGuardKernelListing.address(
                "", 4, "10.150.0.2/32", DEV), "IPv4 address missing");
        match(foreign, RootIsolatedWireGuardKernelListing.address(
                v4.replace("10.150.0.2/32", "10.150.0.3/32"),
                4, "10.150.0.2/32", DEV), "Foreign IPv4 address");
        String v6 = "16: " + DEV + "    inet6 2001:db8::2/128 scope global\n"
                + "16: " + DEV + "    inet6 fe80::123/64 scope link\n";
        match(exact, RootIsolatedWireGuardKernelListing.address(
                v6, 6, "2001:db8::2/128", DEV), "IPv6 host + link-local");
        match(foreign, RootIsolatedWireGuardKernelListing.address(
                v6.replace("2001:db8::2/128", "2001:db8::3/128"),
                6, "2001:db8::2/128", DEV), "Foreign IPv6 global address");

        String v4route = "default dev " + DEV + " scope link\n";
        match(exact, RootIsolatedWireGuardKernelListing.privateRoute(
                v4route, 4, "0.0.0.0/0", DEV), "Private IPv4 default");
        match(foreign, RootIsolatedWireGuardKernelListing.privateRoute(
                "default via 192.168.50.1 dev wlan0\n", 4,
                "0.0.0.0/0", DEV), "Foreign default route");
        match(foreign, RootIsolatedWireGuardKernelListing.privateRoute(
                v4route + v4route, 4, "0.0.0.0/0", DEV),
                "Duplicate routes cannot be treated as owned");
        match(absent, RootIsolatedWireGuardKernelListing.privateRoute(
                "10.0.0.0/24 dev " + DEV, 4, "0.0.0.0/0", DEV),
                "No default route present");
        match(exact, RootIsolatedWireGuardKernelListing.privateRoute(
                "10.0.0.169 dev " + DEV, 4, "10.0.0.169/32", DEV),
                "Exact private Home IPv4 host (bare /32 output)");
        match(exact, RootIsolatedWireGuardKernelListing.privateRoute(
                "2001:db8::3 dev " + DEV, 6, "2001:db8::3/128", DEV),
                "Exact IPv6 host route (bare /128 output)");
        match(absent, RootIsolatedWireGuardKernelListing.privateRoute(
                "10.0.0.169 dev " + DEV, 4, "10.0.0.0/24", DEV),
                "A non-host network must never match a bare host");
        match(exact, RootIsolatedWireGuardKernelListing.privateRoute(
                "default dev " + DEV + " metric 100\n",
                6, "::/0", DEV), "IPv6 default");
        match(foreign, RootIsolatedWireGuardKernelListing.privateRoute(
                "default dev wnm68fe81200daaevil\n", 6, "::/0", DEV),
                "A prefix-matching interface is not an owned route");
        match(foreign, RootIsolatedWireGuardKernelListing.privateRoute(
                v4route, 4, "10.0.0.999/32", DEV),
                "Invalid numeric host must not be accepted");
        System.out.println("RootIsolatedWireGuardKernelListingTest passed");
    }
}
