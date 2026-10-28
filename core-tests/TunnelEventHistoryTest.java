package com.yooshastan.wonheeproxy;

public final class TunnelEventHistoryTest {
    public static void main(String[] args) {
        TunnelEventHistory history = new TunnelEventHistory();
        if (!history.render().contains("Waiting")) throw new AssertionError("empty history");

        history.observe(false, false, -1);
        history.observe(false, false, -1);
        if (history.size() != 1) throw new AssertionError("duplicate state not collapsed");

        history.observe(true, true, -1);
        history.observe(true, true, 12);
        history.observe(true, true, 181);
        history.observe(true, true, 180);
        if (history.size() != 5) throw new AssertionError("expected state changes");
        if (!history.render().startsWith("• Recent WireGuard handshake observed"))
            throw new AssertionError("newest observation should be first");

        for (int i = 0; i < 50; i++) {
            history.observe(i % 2 == 0, false, -1);
        }
        if (history.size() != 12) throw new AssertionError("history must be bounded");
        String text = history.render();
        if (text.contains("Secret") || text.contains("Endpoint"))
            throw new AssertionError("report should contain only fixed local states");
        System.out.println("PASS TunnelEventHistoryTest");
    }
}
