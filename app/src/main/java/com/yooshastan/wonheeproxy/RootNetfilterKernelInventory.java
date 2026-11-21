package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Pure, READ-ONLY interpretation of procfs extension lists and mangle OUTPUT
 * chain listings. Do not infer that listed extensions can safely alter Android
 * socket marks. In particular, a preexisting connmark_mangle_OUTPUT chain is
 * NOT owned by Wonhee and must never be changed by the multi-exit installer.
 */
final class RootNetfilterKernelInventory {
    static final class Family {
        final boolean moduleListsReadable;
        final boolean owner;
        final boolean tcp;
        final boolean udp;
        final boolean markMatch;
        final boolean connmarkMatch;
        final boolean markTarget;
        final boolean connmarkTarget;
        final boolean bpfMatch;
        final boolean outputReadable;
        final boolean existingConnmarkJump;
        final boolean unexpectedOutput;
        Family(boolean moduleListsReadable, boolean owner, boolean tcp,
                boolean udp, boolean markMatch, boolean connmarkMatch,
                boolean markTarget, boolean connmarkTarget, boolean bpfMatch,
                boolean outputReadable, boolean existingConnmarkJump,
                boolean unexpectedOutput) {
            this.moduleListsReadable = moduleListsReadable;
            this.owner = owner;
            this.tcp = tcp;
            this.udp = udp;
            this.markMatch = markMatch;
            this.connmarkMatch = connmarkMatch;
            this.markTarget = markTarget;
            this.connmarkTarget = connmarkTarget;
            this.bpfMatch = bpfMatch;
            this.outputReadable = outputReadable;
            this.existingConnmarkJump = existingConnmarkJump;
            this.unexpectedOutput = unexpectedOutput;
        }
        boolean basicExtensionsRegistered() {
            return moduleListsReadable && owner && tcp && udp && markMatch
                    && connmarkMatch && markTarget && connmarkTarget;
        }
    }

    static final class Report {
        final Family ipv4;
        final Family ipv6;
        Report(Family ipv4, Family ipv6) {
            this.ipv4 = ipv4;
            this.ipv6 = ipv6;
        }
        boolean bothFamiliesRegistered() {
            return ipv4.basicExtensionsRegistered() && ipv6.basicExtensionsRegistered();
        }
        boolean foreignOutputChainsPresent() {
            return ipv4.existingConnmarkJump || ipv6.existingConnmarkJump
                    || ipv4.unexpectedOutput || ipv6.unexpectedOutput;
        }
        /** Even fully registered extensions never authorize rule installation. */
        boolean activationAllowed() { return false; }
        String summary() {
            return "REGISTERED NETFILTER EXTENSIONS: IPv4 "
                    + (ipv4.basicExtensionsRegistered() ? "PRESENT" : "CHECK REQUIRED")
                    + ", IPv6 "
                    + (ipv6.basicExtensionsRegistered() ? "PRESENT" : "CHECK REQUIRED")
                    + "; mangle OUTPUT pre-existing jumps: "
                    + (foreignOutputChainsPresent() ? "PRESERVE / AUDIT" : "NOT OBSERVED")
                    + ". Module registration does not prove packet marking, "
                    + "DNS isolation, rpdb compatibility, ownership or fail-closed routing. "
                    + "No changes made. Activation disabled.";
        }
    }

    private RootNetfilterKernelInventory() { }

    static Report review(String v4Matches, String v4Targets, String v4Output,
            String v6Matches, String v6Targets, String v6Output) {
        return new Report(family(v4Matches, v4Targets, v4Output),
                family(v6Matches, v6Targets, v6Output));
    }

    private static Family family(String matches, String targets, String output) {
        boolean valid = matches != null && !matches.trim().isEmpty()
                && targets != null && !targets.trim().isEmpty()
                && !matches.contains("No such file")
                && !targets.contains("No such file");
        Set<String> m = names(matches);
        Set<String> t = names(targets);
        boolean outputReadable = output != null
                && output.contains("-P OUTPUT ")
                && !output.contains("Permission denied");
        boolean jump = false;
        boolean foreign = false;
        if (outputReadable) {
            for (String row : output.split("\\r?\\n")) {
                String rule = row.trim();
                if (rule.startsWith("-A OUTPUT ")) {
                    if (rule.equals("-A OUTPUT -j connmark_mangle_OUTPUT")) {
                        jump = true;
                    } else {
                        foreign = true;
                    }
                }
            }
        }
        return new Family(valid, m.contains("owner"), m.contains("tcp"),
                m.contains("udp"), m.contains("mark"),
                m.contains("connmark"), t.contains("MARK"),
                t.contains("CONNMARK"), m.contains("bpf"), outputReadable,
                jump, foreign);
    }

    private static Set<String> names(String text) {
        Set<String> result = new HashSet<>();
        if (text == null) return result;
        for (String line : Arrays.asList(text.split("\\r?\\n"))) {
            String item = line.trim();
            if (item.matches("[a-zA-Z][a-zA-Z0-9_]*")) result.add(item);
        }
        return result;
    }
}
