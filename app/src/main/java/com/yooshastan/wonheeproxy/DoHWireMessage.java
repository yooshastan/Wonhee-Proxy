package com.yooshastan.wonheeproxy;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/** Minimal RFC 8484 application/dns-message probe codec; never an OS resolver. */
final class DoHWireMessage {
    private DoHWireMessage() { }

    static byte[] question(String hostname, int id) {
        if (id < 0 || id > 65535 || hostname == null || hostname.length() > 253) {
            throw new IllegalArgumentException("Invalid DNS question.");
        }
        String name = hostname.toLowerCase(java.util.Locale.ROOT);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        write16(out, id);
        write16(out, 0x0100); // RD, standard query
        write16(out, 1); // QDCOUNT
        write16(out, 0); // ANCOUNT
        write16(out, 0); // NSCOUNT
        write16(out, 0); // ARCOUNT
        for (String label : name.split("\\.", -1)) {
            if (label.length() < 1 || label.length() > 63 || !label.matches("[a-z0-9-]+")
                    || label.startsWith("-") || label.endsWith("-")) {
                throw new IllegalArgumentException("Invalid DNS question label.");
            }
            byte[] part = label.getBytes(StandardCharsets.US_ASCII);
            out.write(part.length);
            out.write(part, 0, part.length);
        }
        out.write(0);
        write16(out, 1); // A
        write16(out, 1); // IN
        return out.toByteArray();
    }

    static int verifiedAnswers(byte[] response, byte[] question) {
        if (response == null || question == null || response.length < 12
                || response.length > 4096 || question.length < 17
                || word(response, 0) != word(question, 0)) {
            throw new IllegalArgumentException("DNS response missing or transaction mismatch.");
        }
        int flags = word(response, 2);
        int questions = word(response, 4);
        int answers = word(response, 6);
        if ((flags & 0x8000) == 0 || (flags & 0x7800) != 0
                || (flags & 0x0200) != 0 || (flags & 0x000f) != 0
                || questions != 1 || answers < 1) {
            throw new IllegalArgumentException("DoH server did not return a successful, complete answer.");
        }
        // For this fixed diagnostic query, require the exact uncompressed
        // question to appear in the reply. No answer data are logged/stored.
        int qLength = question.length - 12;
        if (12 + qLength > response.length) {
            throw new IllegalArgumentException("Truncated DoH question echo.");
        }
        for (int i = 0; i < qLength; i++) {
            if (response[12 + i] != question[12 + i]) {
                throw new IllegalArgumentException("DoH reply does not match the question.");
            }
        }
        int offset = 12 + qLength;
        int ipv4Answers = 0;
        if (answers > 64) throw new IllegalArgumentException("Unreasonable DoH answer count.");
        for (int i = 0; i < answers; i++) {
            offset = skipName(response, offset);
            if (offset + 10 > response.length) {
                throw new IllegalArgumentException("Truncated DoH resource record.");
            }
            int type = word(response, offset);
            int klass = word(response, offset + 2);
            int rdlength = word(response, offset + 8);
            offset += 10;
            if (offset + rdlength > response.length) {
                throw new IllegalArgumentException("Truncated DoH answer body.");
            }
            if (type == 1 && klass == 1 && rdlength == 4) ipv4Answers++;
            offset += rdlength;
        }
        if (ipv4Answers < 1) {
            throw new IllegalArgumentException("DoH reply has no valid IPv4 A answer.");
        }
        return ipv4Answers;
    }

    private static int skipName(byte[] message, int offset) {
        for (int labels = 0; labels < 128; labels++) {
            if (offset >= message.length) {
                throw new IllegalArgumentException("Truncated DoH answer name.");
            }
            int len = message[offset] & 0xff;
            if ((len & 0xc0) == 0xc0) {
                if (offset + 1 >= message.length) {
                    throw new IllegalArgumentException("Truncated DoH name pointer.");
                }
                int pointer = ((len & 0x3f) << 8) | (message[offset + 1] & 0xff);
                if (pointer < 12 || pointer >= offset) {
                    throw new IllegalArgumentException("Invalid DoH name pointer.");
                }
                return offset + 2;
            }
            if ((len & 0xc0) != 0) throw new IllegalArgumentException("Invalid DoH label encoding.");
            offset++;
            if (len == 0) return offset;
            if (offset + len > message.length) {
                throw new IllegalArgumentException("Truncated DoH name label.");
            }
            offset += len;
        }
        throw new IllegalArgumentException("DoH answer name exceeds label limit.");
    }

    private static void write16(ByteArrayOutputStream out, int value) {
        out.write((value >>> 8) & 0xff);
        out.write(value & 0xff);
    }

    private static int word(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }
}
