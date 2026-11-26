package com.yooshastan.wonheeproxy;

/** Captured Android Pixel 8a module/OUTPUT evidence. No kernel calls. */
public final class RootNetfilterKernelInventoryTest {
    private static void check(boolean yes, String error) {
        if (!yes) throw new AssertionError(error);
    }

    public static void main(String[] args) {
        String matches = "u32\ntime\nowner\nconntrack\nbpf\nbpf\n"
                + "connmark\nmark\nsocket\nmultiport\nudp\ntcp\n";
        String targets = "NFQUEUE\nREJECT\nCONNMARK\nCONNMARK\nMARK\n";
        String output = "-P OUTPUT ACCEPT\n-A OUTPUT -j connmark_mangle_OUTPUT\n";
        RootNetfilterKernelInventory.Report observed =
                RootNetfilterKernelInventory.review(matches, targets, output,
                        matches, targets, output);
        check(observed.bothFamiliesRegistered(),
                "Observed v4/v6 module lists register required extensions");
        check(observed.ipv4.bpfMatch && observed.ipv6.bpfMatch,
                "Recorded Android module list also contains BPF matcher");
        check(observed.foreignOutputChainsPresent(),
                "Android's connmark_mangle_OUTPUT jump must be treated as foreign");
        check(observed.ipv4.outputReadable && observed.ipv6.outputReadable,
                "Existing OUTPUT policy was visible");
        check(!observed.activationAllowed()
                        && observed.summary().contains("Activation disabled"),
                "Registered modules cannot activate routing");

        RootNetfilterKernelInventory.Report missingV6 =
                RootNetfilterKernelInventory.review(matches, targets, output,
                        matches, "REJECT\nCONNMARK\n", output);
        check(!missingV6.bothFamiliesRegistered(),
                "Missing IPv6 MARK target must refuse any full-stack assumption");

        RootNetfilterKernelInventory.Report spoof =
                RootNetfilterKernelInventory.review(
                        matches.replace("owner\n", "owner_maybe\n"),
                        targets, output, matches, targets, output);
        check(!spoof.bothFamiliesRegistered(),
                "Exact extension names required");

        RootNetfilterKernelInventory.Report unreadable =
                RootNetfilterKernelInventory.review(
                        "No such file or directory", targets, output,
                        matches, targets, output);
        check(!unreadable.bothFamiliesRegistered(),
                "Unreadable procfs list must not be accepted");

        RootNetfilterKernelInventory.Report extraOutput =
                RootNetfilterKernelInventory.review(matches, targets,
                        "-P OUTPUT ACCEPT\n-A OUTPUT -j custom_firewall\n",
                        matches, targets, output);
        check(extraOutput.ipv4.unexpectedOutput
                        && extraOutput.foreignOutputChainsPresent(),
                "Unrecognized OUTPUT entries are foreign, never Wonhee-owned");
        check(!extraOutput.activationAllowed(),
                "Unknown chains must never authorize mutation");
        System.out.println("RootNetfilterKernelInventoryTest passed");
    }
}
