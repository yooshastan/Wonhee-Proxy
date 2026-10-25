package com.yooshastan.wonheeproxy.core;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Immutable, validated Telegram proxy profile. Credentials are never logged or stored here. */
public final class ProxyEndpoint {
    public enum Type { MTPROTO, SOCKS5 }

    public final Type type;
    public final String host;
    public final int port;
    private final String secret;
    private final String username;
    private final String password;

    private ProxyEndpoint(Type type, String host, int port, String secret,
                          String username, String password) {
        if (type == null || host == null || host.trim().isEmpty() || port < 1 || port > 65535) {
            throw new IllegalArgumentException("Enter a valid host and TCP port (1–65535).");
        }
        String normalized = host.trim();
        if (normalized.length() > 255 || normalized.contains("://")) {
            throw new IllegalArgumentException("Enter a hostname or IP address, not a URL.");
        }
        for (int i = 0; i < normalized.length(); i++) {
            char c = normalized.charAt(i);
            if (Character.isISOControl(c) || Character.isWhitespace(c)
                    || c == '/' || c == '?' || c == '#' || c == '@' || c == '\\') {
                throw new IllegalArgumentException("The host contains invalid characters.");
            }
        }
        this.type = type;
        this.host = normalized;
        this.port = port;
        this.secret = secret == null ? "" : secret.trim();
        this.username = username == null ? "" : username;
        this.password = password == null ? "" : password;
    }

    public static ProxyEndpoint mtproto(String host, int port, String secret) {
        ProxyEndpoint result = new ProxyEndpoint(Type.MTPROTO, host, port, secret, "", "");
        if (!result.secret.matches("(?i)[0-9a-f]{32,1024}") || (result.secret.length() & 1) != 0) {
            throw new IllegalArgumentException("MTProto secret must be an even-length hex string (at least 32 characters).");
        }
        return result;
    }

    public static ProxyEndpoint socks5(String host, int port, String username, String password) {
        if ((username == null || username.isEmpty()) && password != null && !password.isEmpty()) {
            throw new IllegalArgumentException("SOCKS5 password requires a username.");
        }
        return new ProxyEndpoint(Type.SOCKS5, host, port, "", username, password);
    }

    /** Telegram deep link. Only pass to the intended Telegram/Ultgram package. */
    public String telegramDeepLink() {
        String prefix = type == Type.MTPROTO ? "tg://proxy?" : "tg://socks?";
        StringBuilder uri = new StringBuilder(prefix)
                .append("server=").append(encode(host))
                .append("&port=").append(port);
        if (type == Type.MTPROTO) {
            uri.append("&secret=").append(encode(secret));
        } else if (!username.isEmpty()) {
            uri.append("&user=").append(encode(username))
                    .append("&pass=").append(encode(password));
        }
        return uri.toString();
    }

    /** Safe to display or log; intentionally excludes credentials and secrets. */
    public String safeDescription() {
        return type.name().toUpperCase(Locale.ROOT) + " " + host + ":" + port;
    }

    private static String encode(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        StringBuilder output = new StringBuilder();
        final char[] hex = "0123456789ABCDEF".toCharArray();
        for (byte raw : bytes) {
            int b = raw & 0xff;
            if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
                    || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' || b == '~') {
                output.append((char) b);
            } else {
                output.append('%').append(hex[b >>> 4]).append(hex[b & 15]);
            }
        }
        return output.toString();
    }
}
