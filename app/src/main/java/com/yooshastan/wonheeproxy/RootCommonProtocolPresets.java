package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Human-readable *port-based* templates. These identify transport metadata
 * only; they do not assert which application protocol is actually in use.
 * No GPS/localization traffic template is possible from ports alone.
 *
 * Every preset expands to an explicit list of TCP/UDP destination port
 * selectors, not an implicit packet classifier.
 */
final class RootCommonProtocolPresets {
    static final class Preset {
        final String label;
        final String explanation;
        private final int[][] selectors;

        Preset(String label, String explanation, int[][] selectors) {
            this.label = label;
            this.explanation = explanation;
            this.selectors = selectors;
        }

        List<RootCategoryProtocolRule.Rule> rules(int category) {
            if (!AppUseCategories.valid(category)) {
                throw new IllegalArgumentException("Unknown app category.");
            }
            List<RootCategoryProtocolRule.Rule> list = new ArrayList<>();
            for (int[] selector : selectors) {
                list.add(new RootCategoryProtocolRule.Rule(
                        selector[0], selector[1], category));
            }
            return Collections.unmodifiableList(list);
        }

        String selectorsLabel() {
            StringBuilder out = new StringBuilder();
            for (int[] selector : selectors) {
                if (out.length() != 0) out.append(" · ");
                out.append(selector[0] == RootProtocolRouteDraft.TCP ? "TCP" : "UDP");
                out.append('/').append(selector[1]);
            }
            return out.toString();
        }
    }

    static final Preset[] PRESETS = {
            new Preset("Web · HTTP", "Common unencrypted web port; not proof of HTTP",
                    new int[][]{{6, 80}}),
            new Preset("Secure Web · HTTPS", "Common TLS/web port; not proof of HTTPS",
                    new int[][]{{6, 443}}),
            new Preset("HTTP/3 · QUIC", "Common HTTP/3 port; any UDP app may use it",
                    new int[][]{{17, 443}}),
            new Preset("DNS · conventional",
                    "Typical plaintext DNS transport ports (UDP and TCP)",
                    new int[][]{{17, 53}, {6, 53}}),
            new Preset("Encrypted DNS · DoT/DoQ",
                    "Typical DoT TCP/853 and DoQ UDP/853; DoH usually uses HTTPS",
                    new int[][]{{6, 853}, {17, 853}}),
            new Preset("SSH / SFTP", "Typical SSH and SFTP service port",
                    new int[][]{{6, 22}}),
            new Preset("Email · IMAP", "IMAP and IMAPS for receiving email",
                    new int[][]{{6, 143}, {6, 993}}),
            new Preset("Email · POP3", "POP3 and POP3S for receiving email",
                    new int[][]{{6, 110}, {6, 995}}),
            new Preset("Email · SMTP",
                    "Common SMTP and submission ports; provider settings vary",
                    new int[][]{{6, 25}, {6, 465}, {6, 587}}),
            new Preset("Time sync · NTP", "Typical NTP synchronization",
                    new int[][]{{17, 123}}),
            new Preset("Remote desktop · RDP",
                    "Common Windows Remote Desktop transport ports",
                    new int[][]{{6, 3389}, {17, 3389}}),
            new Preset("Secure messaging · MQTT",
                    "Common MQTT and MQTT-over-TLS IoT ports",
                    new int[][]{{6, 1883}, {6, 8883}})
    };

    private RootCommonProtocolPresets() { }

    static String[] labels() {
        String[] labels = new String[PRESETS.length];
        for (int i = 0; i < PRESETS.length; i++) {
            labels[i] = PRESETS[i].label;
        }
        return labels;
    }

    static Preset get(int index) {
        if (index < 0 || index >= PRESETS.length) {
            throw new IllegalArgumentException("Unknown protocol preset.");
        }
        return PRESETS[index];
    }
}
