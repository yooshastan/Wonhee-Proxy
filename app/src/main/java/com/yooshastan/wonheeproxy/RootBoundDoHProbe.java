package com.yooshastan.wonheeproxy;

import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Locale;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * One user-triggered DoH diagnostic. Socket originates from an EXACT Android
 * Network, to a NUMERIC address, then the standard TLS trust manager verifies
 * the separately configured DoH hostname. No default-network fallback.
 * Root-only links lacking an Android Network are deliberately unavailable.
 */
final class RootBoundDoHProbe {
    private static final int MAX_REPLY = 4096;
    private static final int MAX_HEADER = 8192;
    private static final int TIMEOUT_MS = 6000;

    private RootBoundDoHProbe() { }

    static Network exactNetwork(ConnectivityManager manager, String requiredInterface) {
        if (manager == null || requiredInterface == null || requiredInterface.isEmpty()) return null;
        Network match = null;
        for (Network network : manager.getAllNetworks()) {
            LinkProperties properties = manager.getLinkProperties(network);
            if (properties == null || !requiredInterface.equals(properties.getInterfaceName())) continue;
            if (match != null) return null; // No ambiguous binding.
            match = network;
        }
        return match;
    }

    static int probe(Network network, DoHProbePolicy policy) throws Exception {
        if (network == null || policy == null) {
            throw new IllegalStateException("No explicitly verified tunnel network for DoH.");
        }
        // The address has already passed numeric-only validation; never resolve
        // an upstream hostname using Android's normal or Private DNS resolver.
        InetAddress destination = InetAddress.getByName(policy.bootstrapAddress);
        if (destination.getAddress().length != (policy.family == 4 ? 4 : 16)) {
            throw new IllegalArgumentException("DoH bootstrap address family mismatch.");
        }
        byte[] question = DoHWireMessage.question("example.com",
                new SecureRandom().nextInt(65536));
        String path = java.net.URI.create(policy.url).getRawPath();
        String hostHeader = policy.port == 443 ? policy.hostname
                : policy.hostname + ":" + policy.port;
        String headers = "POST " + path + " HTTP/1.1\r\n"
                + "Host: " + hostHeader + "\r\n"
                + "Accept: application/dns-message\r\n"
                + "Content-Type: application/dns-message\r\n"
                + "Cache-Control: no-store\r\n"
                + "Connection: close\r\n"
                + "Content-Length: " + question.length + "\r\n\r\n";
        try (Socket plain = network.getSocketFactory().createSocket()) {
            plain.connect(new InetSocketAddress(destination, policy.port), TIMEOUT_MS);
            plain.setSoTimeout(TIMEOUT_MS);
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket tls = (SSLSocket) factory.createSocket(
                    plain, policy.hostname, policy.port, false)) {
                tls.setSoTimeout(TIMEOUT_MS);
                SSLParameters parameters = tls.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                parameters.setServerNames(java.util.Collections.singletonList(
                        new SNIHostName(policy.hostname)));
                tls.setSSLParameters(parameters);
                tls.startHandshake(); // Platform CA validation + exact hostname check.
                OutputStream out = tls.getOutputStream();
                out.write(headers.getBytes(StandardCharsets.US_ASCII));
                out.write(question);
                out.flush();
                byte[] answer = readResponse(tls.getInputStream());
                return DoHWireMessage.verifiedAnswers(answer, question);
            }
        }
    }

    /** Parse only HTTP/1.1 200 + application/dns-message; never follow redirects. */
    private static byte[] readResponse(InputStream in) throws IOException {
        int[] budget = {MAX_HEADER};
        String status = readLine(in, budget);
        if (!status.matches("HTTP/1\\.[01] 200(?: .*)?")) {
            throw new IOException("DoH server did not return HTTP 200; redirects are forbidden.");
        }
        String contentType = "";
        long contentLength = -1;
        boolean chunked = false;
        while (true) {
            String line = readLine(in, budget);
            if (line.isEmpty()) break;
            int sep = line.indexOf(':');
            if (sep < 1) throw new IOException("Malformed DoH HTTP response header.");
            String key = line.substring(0, sep).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(sep + 1).trim().toLowerCase(Locale.ROOT);
            if ("content-type".equals(key)) {
                contentType = value;
            } else if ("content-length".equals(key)) {
                try { contentLength = Long.parseLong(value); }
                catch (NumberFormatException invalid) { throw new IOException("Invalid DoH response length."); }
            } else if ("transfer-encoding".equals(key)) {
                if (!"chunked".equals(value)) throw new IOException("Unsupported DoH transfer encoding.");
                chunked = true;
            } else if ("content-encoding".equals(key) && !"identity".equals(value)) {
                throw new IOException("Compressed DoH replies are not supported.");
            }
        }
        if (!contentType.equals("application/dns-message")
                && !contentType.startsWith("application/dns-message;")) {
            throw new IOException("DoH response is not DNS wireformat.");
        }
        if (contentLength > MAX_REPLY || (chunked && contentLength >= 0)) {
            throw new IOException("DoH response length/encoding is unsafe.");
        }
        if (chunked) return readChunked(in, budget);
        return readBounded(in, contentLength);
    }

    private static byte[] readChunked(InputStream in, int[] budget) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine(in, budget);
            // Reject chunk extensions (not needed for a small DNS wire reply).
            if (!sizeLine.matches("[0-9a-fA-F]{1,8}")) throw new IOException("Invalid DoH chunk size.");
            long size = Long.parseLong(sizeLine, 16);
            if (size > MAX_REPLY - result.size()) throw new IOException("DoH reply too large.");
            if (size == 0) {
                // No trailers required for DNS; reject unexpected headers.
                if (!readLine(in, budget).isEmpty()) throw new IOException("Unexpected DoH trailers.");
                return result.toByteArray();
            }
            for (int i = 0; i < size; i++) {
                int next = in.read();
                if (next < 0) throw new IOException("Truncated DoH response.");
                result.write(next);
            }
            if (in.read() != '\r' || in.read() != '\n') {
                throw new IOException("Invalid DoH chunk terminator.");
            }
        }
    }

    private static byte[] readBounded(InputStream in, long length) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (length == 0) throw new IOException("Empty DoH reply.");
        while (length < 0 || out.size() < length) {
            int next = in.read();
            if (next < 0) break;
            if (out.size() >= MAX_REPLY) throw new IOException("DoH reply too large.");
            out.write(next);
        }
        if (length >= 0 && out.size() != length) throw new IOException("Truncated DoH reply.");
        return out.toByteArray();
    }

    private static String readLine(InputStream in, int[] remaining) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        while (true) {
            if (--remaining[0] <= 0) throw new IOException("DoH HTTP header exceeded limit.");
            int b = in.read();
            if (b < 0) throw new IOException("Incomplete DoH HTTP response.");
            if (b == '\r') {
                if (--remaining[0] <= 0 || in.read() != '\n') {
                    throw new IOException("Invalid DoH HTTP line break.");
                }
                return line.toString("US-ASCII");
            }
            if (b < 32 || b > 126) throw new IOException("Invalid DoH HTTP header byte.");
            line.write(b);
        }
    }
}
