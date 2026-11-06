package com.yooshastan.wonheeproxy;

import java.util.Arrays;

public final class DoHWireMessageTest {
    private static void require(boolean value) { if (!value) throw new AssertionError(); }

    private static void refuses(byte[] reply, byte[] question) {
        try {
            DoHWireMessage.verifiedAnswers(reply, question);
            throw new AssertionError("Accepted invalid DoH response");
        } catch (IllegalArgumentException expected) { /* strict fail */ }
    }

    public static void main(String[] unused) {
        byte[] question = DoHWireMessage.question("example.com", 0x1122);
        require(question[0] == 0x11 && question[1] == 0x22);
        require(question[2] == 1 && question[5] == 1);
        // A valid compressed answer for example.com => 192.0.2.1
        byte[] reply = Arrays.copyOf(question, question.length + 16);
        reply[2] = (byte) 0x81;
        reply[3] = (byte) 0x80;
        reply[7] = 1;
        int n = question.length;
        byte[] answer = {(byte) 0xc0, 0x0c, 0, 1, 0, 1,
                0, 0, 0, 60, 0, 4, (byte) 192, 0, 2, 1};
        System.arraycopy(answer, 0, reply, n, answer.length);
        require(DoHWireMessage.verifiedAnswers(reply, question) == 1);

        byte[] bad = Arrays.copyOf(reply, reply.length);
        bad[0] ^= 1;
        refuses(bad, question);
        bad = Arrays.copyOf(reply, reply.length);
        bad[2] = 0x01; // not a response
        refuses(bad, question);
        bad = Arrays.copyOf(reply, reply.length);
        bad[3] = (byte) 0x83; // NXDOMAIN
        refuses(bad, question);
        bad = Arrays.copyOf(reply, reply.length);
        bad[12] ^= 1; // different DNS question
        refuses(bad, question);
        bad = Arrays.copyOf(reply, reply.length);
        bad[n + 1] = 0x7f; // pointer outside previous DNS data
        refuses(bad, question);
        bad = Arrays.copyOf(reply, n + 10); // answer truncated
        refuses(bad, question);
        bad = Arrays.copyOf(reply, reply.length);
        bad[n + 3] = 28; // AAAA with 4-byte body
        refuses(bad, question);
        refuses(new byte[0], question);
        require(DoHWireMessage.question("example.com", 7).length == question.length);
        try {
            DoHWireMessage.question("bad..domain", 0);
            throw new AssertionError("Invalid question accepted");
        } catch (IllegalArgumentException expected) { /* strict fail */ }
        System.out.println("DoHWireMessageTest passed");
    }
}
