package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Tests human-facing network port templates without any Android/network access. */
public final class RootCommonProtocolPresetsTest {
    private static void expected(String name, int[][] pairs) {
        RootCommonProtocolPresets.Preset preset = null;
        for (RootCommonProtocolPresets.Preset candidate : RootCommonProtocolPresets.PRESETS) {
            if (candidate.label.equals(name)) {
                preset = candidate;
                break;
            }
        }
        if (preset == null) throw new AssertionError("Missing preset: " + name);
        List<RootCategoryProtocolRule.Rule> rules = preset.rules(AppUseCategories.PRIVATE);
        if (rules.size() != pairs.length) {
            throw new AssertionError(name + " has wrong number of port selectors");
        }
        Set<String> expected = new HashSet<>();
        for (int[] pair : pairs) expected.add(pair[0] + "/" + pair[1]);
        for (RootCategoryProtocolRule.Rule rule : rules) {
            if (!expected.remove(rule.transport + "/" + rule.destinationPort)
                    || rule.category != AppUseCategories.PRIVATE) {
                throw new AssertionError("Unexpected rule in " + name);
            }
        }
        if (!expected.isEmpty()) throw new AssertionError("Missing ports in " + name);
        RootCategoryProtocolRule.validateAndSort(rules);
    }

    public static void main(String[] args) {
        expected("Web · HTTP", new int[][]{{6, 80}});
        expected("Secure Web · HTTPS", new int[][]{{6, 443}});
        expected("HTTP/3 · QUIC", new int[][]{{17, 443}});
        expected("DNS · conventional", new int[][]{{6, 53}, {17, 53}});
        expected("Encrypted DNS · DoT/DoQ", new int[][]{{6, 853}, {17, 853}});
        expected("SSH / SFTP", new int[][]{{6, 22}});
        expected("Email · IMAP", new int[][]{{6, 143}, {6, 993}});
        expected("Email · POP3", new int[][]{{6, 110}, {6, 995}});
        expected("Email · SMTP", new int[][]{{6, 25}, {6, 465}, {6, 587}});
        expected("Time sync · NTP", new int[][]{{17, 123}});
        expected("Remote desktop · RDP", new int[][]{{6, 3389}, {17, 3389}});
        expected("Secure messaging · MQTT", new int[][]{{6, 1883}, {6, 8883}});
        String[] labels = RootCommonProtocolPresets.labels();
        if (labels.length != 12 || labels.length != RootCommonProtocolPresets.PRESETS.length) {
            throw new AssertionError("User-visible protocol preset list mismatch");
        }
        for (String label : labels) {
            if (label.toLowerCase(java.util.Locale.ROOT).contains("gps")
                    || label.toLowerCase(java.util.Locale.ROOT).contains("location")) {
                throw new AssertionError("Location is not a reliable protocol/port");
            }
        }
        try {
            RootCommonProtocolPresets.get(-1);
            throw new AssertionError("Negative preset index accepted");
        } catch (IllegalArgumentException expected) { }
        try {
            RootCommonProtocolPresets.get(labels.length);
            throw new AssertionError("OOB preset index accepted");
        } catch (IllegalArgumentException expected) { }
        try {
            RootCommonProtocolPresets.get(0).rules(99);
            throw new AssertionError("Unknown category accepted");
        } catch (IllegalArgumentException expected) { }
        System.out.println("RootCommonProtocolPresetsTest passed");
    }
}
