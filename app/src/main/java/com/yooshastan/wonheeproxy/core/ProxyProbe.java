package com.yooshastan.wonheeproxy.core;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.concurrent.TimeUnit;

/**
 * Explicit TCP connection test; not a SOCKS/MTProto handshake, VPN, or leak check.
 * Run only after user consent, off the Android UI thread. Never log exceptions.
 */
public final class ProxyProbe {
    public enum Status { REACHABLE, TIMEOUT, DNS_FAILURE, UNREACHABLE }

    public static final class Result {
        public final Status status;
        public final long elapsedMillis;

        private Result(Status status, long elapsedMillis) {
            this.status = status;
            this.elapsedMillis = elapsedMillis;
        }

        public String safeSummary() {
            switch (status) {
                case REACHABLE: return "TCP port responded in " + elapsedMillis + " ms.";
                case TIMEOUT: return "TCP connection timed out.";
                case DNS_FAILURE: return "Host could not be resolved.";
                default: return "TCP connection failed or was refused.";
            }
        }
    }

    private ProxyProbe() { }

    public static Result check(ProxyEndpoint endpoint, int timeoutMillis) {
        if (endpoint == null || timeoutMillis < 200 || timeoutMillis > 10000) {
            throw new IllegalArgumentException("Invalid test configuration.");
        }
        long start = System.nanoTime();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(endpoint.host, endpoint.port), timeoutMillis);
            return new Result(Status.REACHABLE, elapsed(start));
        } catch (SocketTimeoutException timedOut) {
            return new Result(Status.TIMEOUT, elapsed(start));
        } catch (UnknownHostException notResolved) {
            return new Result(Status.DNS_FAILURE, elapsed(start));
        } catch (IOException unavailable) {
            return new Result(Status.UNREACHABLE, elapsed(start));
        }
    }

    private static long elapsed(long started) {
        return Math.max(0L, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started));
    }
}
