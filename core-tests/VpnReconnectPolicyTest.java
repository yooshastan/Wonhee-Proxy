import com.yooshastan.wonheeproxy.VpnReconnectPolicy;

public final class VpnReconnectPolicyTest {
    public static void main(String[] args) {
        check(VpnReconnectPolicy.canAttempt(true, true, false, false, false, 0, 100, 0));
        check(!VpnReconnectPolicy.canAttempt(false, true, false, false, false, 0, 100, 0));
        check(!VpnReconnectPolicy.canAttempt(true, false, false, false, false, 0, 100, 0));
        check(!VpnReconnectPolicy.canAttempt(true, true, true, false, false, 0, 100, 0));
        check(!VpnReconnectPolicy.canAttempt(true, true, false, true, false, 0, 100, 0));
        check(!VpnReconnectPolicy.canAttempt(true, true, false, false, true, 0, 100, 0));
        check(!VpnReconnectPolicy.canAttempt(true, true, false, false, false, 3, 100, 0));
        check(!VpnReconnectPolicy.canAttempt(true, true, false, false, false, 1, 99, 100));
        check(VpnReconnectPolicy.canAttempt(true, true, false, false, false, 1, 100, 100));
        check(VpnReconnectPolicy.retryDelayMs(1) == 10_000);
        check(VpnReconnectPolicy.retryDelayMs(2) == 20_000);
        check(VpnReconnectPolicy.retryDelayMs(3) == 40_000);
    }

    private static void check(boolean ok) {
        if (!ok) throw new AssertionError("VPN recovery policy failed");
    }
}
