import com.yooshastan.wonheeproxy.core.ProbeHistory;
import com.yooshastan.wonheeproxy.core.ProxyProbe;

public final class ProbeHistoryTest {
    public static void main(String[] args) {
        ProbeHistory history = new ProbeHistory();
        if (history.sampleCount() != 0 || history.recentSampleCount() != 0) {
            throw new AssertionError("History should start empty");
        }
        history.record(ProxyProbe.Status.REACHABLE, 42);
        history.record(ProxyProbe.Status.TIMEOUT, 4000);
        history.record(ProxyProbe.Status.DNS_FAILURE, 3);
        if (history.sampleCount() != 3 || history.reachableCount() != 1
                || history.failedCount() != 2 || history.recentReachableCount() != 1) {
            throw new AssertionError("Incorrect monitoring statistics");
        }
        for (int i = 0; i < 40; i++) history.record(ProxyProbe.Status.REACHABLE, 50);
        if (history.recentSampleCount() != 32 || history.recentReachableCount() != 32) {
            throw new AssertionError("History must be bounded and roll forward");
        }
        String report = history.redactedSnapshot(true, 19000);
        if (!report.contains("TCP samples: 43")
                || !report.contains("Not an MTProto/SOCKS5 handshake test.")) {
            throw new AssertionError("Incomplete redacted TCP diagnostics");
        }
        if (report.contains("server=") || report.contains("secret=")
                || report.contains("password=")) {
            throw new AssertionError("Sensitive endpoints must never enter diagnostics");
        }
        boolean failed = false;
        try {
            history.record(null, 1);
        } catch (IllegalArgumentException expected) { failed = true; }
        if (!failed) throw new AssertionError("Null statuses must be rejected");
        System.out.println("Wonhee foreground monitoring tests passed");
    }
}
