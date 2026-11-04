package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

public final class VpnPeerSnippetPolicyTest {
    private static final String GOOD =
            "[Peer]\n"
            + "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            + "Endpoint = home.example.net:51820\n"
            + "AllowedIPs = 10.77.0.0/24, 192.168.50.0/24\n"
            + "PersistentKeepalive = 25\n";

    private static void accept() {
        String value = VpnPeerSnippetPolicy.checkedPrivatePeer(
                GOOD, Arrays.asList("0.0.0.0/0", "::/0"));
        if (!value.startsWith("[Peer]\n") || !value.endsWith("\n")
                || !value.contains("AllowedIPs = 10.77.0.0/24")) {
            throw new AssertionError("New peer lost required fields or separators.");
        }
        VpnPeerSnippetPolicy.checkedPrivatePeer(
                "[Peer]\nPublicKey = dummy\nEndpoint = home:51820\nAllowedIPs = 172.16.3.1/32\n",
                Collections.singletonList("0.0.0.0/0"));
    }

    private static void reject(String snippet, String... existing) {
        try {
            VpnPeerSnippetPolicy.checkedPrivatePeer(snippet, Arrays.asList(existing));
            throw new AssertionError("Accepted unsafe extra peer");
        } catch (IllegalArgumentException expected) { }
    }

    public static void main(String[] args) {
        accept();
        reject("[Interface]\nPrivateKey = dummy\n" + GOOD);
        reject(GOOD + "[Peer]\nPublicKey = dummy\n");
        reject(GOOD.replace("10.77.0.0/24, 192.168.50.0/24", "0.0.0.0/0"));
        reject(GOOD.replace("10.77.0.0/24, 192.168.50.0/24", "::/0"));
        reject(GOOD.replace("10.77.0.0/24, 192.168.50.0/24", "8.8.8.0/24"));
        reject(GOOD.replace("10.77.0.0/24, 192.168.50.0/24", "10.0.0.0/7"));
        reject(GOOD, "10.77.0.1/32");
        reject(GOOD, "192.168.0.0/16");
        reject(GOOD.replace("10.77.0.0/24, 192.168.50.0/24", "10.77.0.0/24,10.77.0.128/25"));
        reject(GOOD.replace("AllowedIPs", "PrivateKey"));
        reject(GOOD.replace("PublicKey", "BadKey"));
        reject(GOOD.replace("10.77.0.0/24, 192.168.50.0/24", "10.077.0.0/24"));
        reject(GOOD.replace("10.77.0.0/24, 192.168.50.0/24", "10.77.0.1/abc"));
        reject("");
        System.out.println("PASS VpnPeerSnippetPolicyTest");
    }
}
