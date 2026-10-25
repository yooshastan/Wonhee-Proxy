import com.yooshastan.wonheeproxy.core.ProxyEndpoint;
import com.yooshastan.wonheeproxy.core.ProxyProbe;
import java.net.InetAddress;
import java.net.ServerSocket;

public final class ProxyProbeTest {
    public static void main(String[] args) throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            ProxyEndpoint endpoint = ProxyEndpoint.socks5(
                    server.getInetAddress().getHostAddress(), server.getLocalPort(), "", "");
            ProxyProbe.Result result = ProxyProbe.check(endpoint, 1000);
            if (result.status != ProxyProbe.Status.REACHABLE || result.elapsedMillis < 0) {
                throw new AssertionError("Expected localhost TCP reachability");
            }
            if (!result.safeSummary().startsWith("TCP port")) {
                throw new AssertionError("Expected TCP-only status wording");
            }
        }
        System.out.println("Wonhee TCP probe passed");
    }
}
