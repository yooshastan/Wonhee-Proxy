import com.yooshastan.wonheeproxy.core.ProxyEndpoint;

public final class ProxyEndpointTest {
    static void invalid(Runnable action) {
        try {
            action.run();
            throw new AssertionError("Expected validation failure");
        } catch (IllegalArgumentException expected) { }
    }

    public static void main(String[] args) {
        ProxyEndpoint mt = ProxyEndpoint.mtproto(
                " Proxy.Example ", 443, "aabbccddeeff00112233445566778899");
        if (!mt.telegramDeepLink().equals(
                "tg://proxy?server=Proxy.Example&port=443&secret=aabbccddeeff00112233445566778899")) {
            throw new AssertionError("MTProto link incorrect");
        }
        if (mt.safeDescription().contains("aabbccdd")) {
            throw new AssertionError("Secret exposed in safe description");
        }
        ProxyEndpoint socks = ProxyEndpoint.socks5("localhost", 1080, "me+you", "a&b");
        if (!socks.telegramDeepLink().contains("user=me%2Byou&pass=a%26b")) {
            throw new AssertionError("SOCKS5 URI escaping incorrect");
        }
        invalid(() -> ProxyEndpoint.mtproto("bad\nhost", 443, "aabbccddeeff00112233445566778899"));
        invalid(() -> ProxyEndpoint.mtproto("example.com", 0, "aabbccddeeff00112233445566778899"));
        invalid(() -> ProxyEndpoint.mtproto("example.com", 443, "not-hex"));
        invalid(() -> ProxyEndpoint.socks5("example.com", 1080, "", "secret"));
        System.out.println("Wonhee endpoint validation passed");
    }
}
