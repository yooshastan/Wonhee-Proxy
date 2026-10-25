import com.yooshastan.wonheeproxy.core.EndpointSelector;

public final class EndpointSelectorTest {
    private static void equal(String expected, String actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError("Expected " + expected + ", found " + actual);
        }
    }

    public static void main(String[] args) {
        if (!EndpointSelector.samePrivateSubnet("10.20.30.99", 24, "10.20.30.40")) {
            throw new AssertionError("Home LAN should match");
        }
        if (EndpointSelector.samePrivateSubnet("192.168.1.42", 24, "10.20.30.40")) {
            throw new AssertionError("Other subnet should not match");
        }
        if (EndpointSelector.samePrivateSubnet("10.20.30.99", 24, "198.51.100.42")) {
            throw new AssertionError("Public host cannot be treated as a LAN endpoint");
        }
        if (EndpointSelector.samePrivateSubnet("10.20.30.99", 24, "proxy.example.net")) {
            throw new AssertionError("Hostnames must not be resolved during selection");
        }
        if (!EndpointSelector.samePrivateSubnet("172.16.1.10", 16, "172.16.50.20")) {
            throw new AssertionError("RFC1918 172.16 address should match");
        }
        if (EndpointSelector.samePrivateSubnet("172.32.1.10", 16, "172.32.50.20")) {
            throw new AssertionError("Non-private addresses must never match");
        }
        equal("10.20.30.40", EndpointSelector.select("198.51.100.42", "10.20.30.40",
                EndpointSelector.Mode.AUTO, true).host);
        equal("198.51.100.42", EndpointSelector.select("198.51.100.42", "10.20.30.40",
                EndpointSelector.Mode.AUTO, false).host);
        equal("198.51.100.42", EndpointSelector.select("198.51.100.42", "10.20.30.40",
                EndpointSelector.Mode.PUBLIC, true).host);
        equal("10.20.30.40", EndpointSelector.select("198.51.100.42", "10.20.30.40",
                EndpointSelector.Mode.LAN, false).host);
        System.out.println("Endpoint selection tests passed");
    }
}
