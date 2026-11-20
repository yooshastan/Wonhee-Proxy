package com.yooshastan.wonheeproxy;

/** Pure-Java regression: strip wg-quick-only options without shell pipes. */
public final class RootIsolatedWireGuardSetconfCodecTest {
    private static final String LOCAL =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private static final String REMOTE =
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
    private static final String PSK =
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=";

    private static void check(boolean ok, String why) {
        if (!ok) throw new AssertionError(why);
    }

    private static void reject(String raw, String why) {
        try {
            RootIsolatedWireGuardSetconfCodec.stripCanonicalQuick(raw);
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Invalid wg setconf output accepted: " + why);
    }

    public static void main(String[] args) {
        String quick = "[Interface]\n"
                + "Address = 10.150.0.2/32, fd00::2/128\n"
                + "DNS = 10.1.2.3\n"
                + "MTU = 1320\n"
                + "PrivateKey = " + LOCAL + "\n"
                + "ListenPort = 51820\n"
                + "\n[Peer]\n"
                + "PublicKey = " + REMOTE + "\n"
                + "PreSharedKey = " + PSK + "\n"
                + "AllowedIPs = 0.0.0.0/0, ::/0\n"
                + "Endpoint = vpn.example.invalid:51820\n"
                + "PersistentKeepalive = 25\n";
        String result = RootIsolatedWireGuardSetconfCodec.stripCanonicalQuick(quick);
        check(result.contains("[Interface]\nPrivateKey = " + LOCAL)
                        && result.contains("ListenPort = 51820")
                        && result.contains("[Peer]\nPublicKey = " + REMOTE)
                        && result.contains("PresharedKey = " + PSK)
                        && result.contains("AllowedIPs = 0.0.0.0/0, ::/0")
                        && result.contains("Endpoint = vpn.example.invalid:51820")
                        && result.contains("PersistentKeepalive = 25"),
                "All wg setconf fields must survive canonicalization");
        check(result.contains("PresharedKey = " + PSK)
                        && !result.contains("PreSharedKey = "),
                "Upstream WireGuard PreSharedKey must normalize to wg setconf spelling");
        // Some hand-written profiles already use the wg setconf spelling.
        check(result.equals(RootIsolatedWireGuardSetconfCodec.stripCanonicalQuick(
                        quick.replace("PreSharedKey = ", "PresharedKey = "))),
                "Both supported exact PSK spellings normalize identically");
        check(!result.contains("Address = ") && !result.contains("DNS = ")
                        && !result.contains("MTU = ") && !result.contains("Table = ")
                        && !result.contains("PostUp") && !result.contains("PreDown")
                        && !result.contains("wlan") && !result.contains("wg-quick"),
                "No DNS/main-route/script/policy commands in wg setconf payload");
        check(result.equals(RootIsolatedWireGuardSetconfCodec
                        .stripCanonicalQuick(result)),
                "Canonical peer-only setconf conversion must be stable");
        reject(quick.replace("PrivateKey", "Address"), "missing interface key");
        reject(quick.replace("PublicKey", "Endpoint"), "missing peer public key");
        reject(quick.replace("AllowedIPs = 0.0.0.0/0, ::/0\n", ""),
                "missing AllowedIPs");
        reject(quick.replace("[Peer]", "[Peer]\n[Peer]"), "multiple peers");
        reject(quick.replace("ListenPort = 51820",
                "ListenPort = 51820\nListenPort = 51820"), "duplicate ListenPort");
        reject(quick.replace("PreSharedKey = " + PSK,
                        "PreSharedKey = " + PSK + "\nPresharedKey = " + PSK),
                "Both spellings of the same preshared key may not appear twice");
        reject(quick.replace("PreSharedKey = " + PSK,
                        "PRESHAREDKEY = " + PSK),
                "Only the two recognized PSK spellings are accepted");

        reject(quick.replace("MTU = 1320",
                "PostUp = ip route add default dev wlan0"), "script injection");
        reject(quick.replace("MTU = 1320",
                "FwMark = 0x1234"), "unreviewed netd socket fwmark");
        reject(quick.replace("MTU = 1320",
                "Unrecognized = escape"), "unknown option fail-closed");
        reject(quick + "[Peer]\nPublicKey = " + REMOTE,
                "second peer section");
        check(RootIsolatedWireGuardSetconfCodec.stripCanonicalQuick(
                "[Interface]\nPrivateKey = " + LOCAL
                        + "\nAddress = 10.5.0.2/32\n"
                        + "[Peer]\nPublicKey = " + REMOTE
                        + "\nAllowedIPs = 0.0.0.0/0\n").contains(REMOTE),
                "IPv4-only valid WireGuard profile accepted");
        System.out.println("RootIsolatedWireGuardSetconfCodecTest passed");
    }
}
