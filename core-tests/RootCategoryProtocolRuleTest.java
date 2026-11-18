package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Pure unit tests: NO Android, root sockets, VPN routes or kernel writes. */
public final class RootCategoryProtocolRuleTest {
    static RootMultiTunnelPlan.Entry tunnel(String name, String address,
            String... routes) {
        return new RootMultiTunnelPlan.Entry(name, Arrays.asList(routes),
                Collections.singletonList(address));
    }

    private static void refused(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Unsafe category transport rule was accepted.");
    }

    public static void main(String[] args) {
        RootCategoryProtocolRule.Rule tcp443 =
                new RootCategoryProtocolRule.Rule(6, 443, AppUseCategories.REGIONAL);
        RootCategoryProtocolRule.Rule tcpAll =
                new RootCategoryProtocolRule.Rule(6, 0, AppUseCategories.PRIVATE);
        RootCategoryProtocolRule.Rule udp443 =
                new RootCategoryProtocolRule.Rule(17, 443, AppUseCategories.MEDIA);
        List<RootCategoryProtocolRule.Rule> global =
                RootCategoryProtocolRule.validateAndSort(
                        Arrays.asList(tcpAll, udp443, tcp443));
        if (global.size() != 3
                || global.get(0).destinationPort != 443
                || global.get(1).destinationPort != 0
                || RootCategoryProtocolRule.matchingCategory(global, 6, 443,
                        AppUseCategories.EVERYDAY) != AppUseCategories.REGIONAL
                || RootCategoryProtocolRule.matchingCategory(global, 6, 80,
                        AppUseCategories.EVERYDAY) != AppUseCategories.PRIVATE
                || RootCategoryProtocolRule.matchingCategory(global, 17, 443,
                        AppUseCategories.EVERYDAY) != AppUseCategories.MEDIA
                || RootCategoryProtocolRule.matchingCategory(global, 17, 80,
                        AppUseCategories.FINANCE) != AppUseCategories.FINANCE) {
            throw new AssertionError("Global selectors must override base app category.");
        }

        refused(() -> RootCategoryProtocolRule.validateAndSort(
                Arrays.asList(tcp443, tcp443)));
        refused(() -> new RootCategoryProtocolRule.Rule(1, 443, 0));
        refused(() -> new RootCategoryProtocolRule.Rule(6, -1, 0));
        refused(() -> new RootCategoryProtocolRule.Rule(6, 65536, 0));
        refused(() -> new RootCategoryProtocolRule.Rule(6, 443, 99));
        List<RootCategoryProtocolRule.Rule> twentyOne = new ArrayList<>();
        for (int p = 1; p <= 21; p++) {
            twentyOne.add(new RootCategoryProtocolRule.Rule(6, p, 0));
        }
        refused(() -> RootCategoryProtocolRule.validateAndSort(twentyOne));

        RootMultiTunnelPlan.Entry nl = tunnel("NL", "10.151.0.2/32",
                "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry us = tunnel("US", "10.152.0.2/32",
                "0.0.0.0/0", "::/0");
        RootPerAppUidPolicyPlan.App app =
                new RootPerAppUidPolicyPlan.App("com.example.store", 10342, "NL");
        Map<Integer, String> targets = new HashMap<>();
        targets.put(AppUseCategories.REGIONAL, "US");
        RootPerAppUidPolicyPlan.Plan plan =
                RootPerAppUidPolicyPlan.prepare("NL", Arrays.asList(nl, us),
                        Collections.singletonList(app), Collections.emptyList(),
                        Collections.singletonList(tcp443), targets);
        if (plan.activationAllowed() || plan.rules.size() != 2
                || plan.rules.get(0).transport != 6
                || plan.rules.get(0).destinationPort != 443
                || !plan.rules.get(0).tunnelName.equals("US")
                || !plan.rules.get(1).tunnelName.equals("NL")) {
            throw new AssertionError("Global category rule must beat ordinary app category.");
        }
        RootProtocolRouteDraft.Override appOverride =
                new RootProtocolRouteDraft.Override("com.example.store", 6, 443, "NL");
        RootPerAppUidPolicyPlan.Plan explicitPlan =
                RootPerAppUidPolicyPlan.prepare("NL", Arrays.asList(nl, us),
                        Collections.singletonList(app),
                        Collections.singletonList(appOverride),
                        Collections.singletonList(tcp443), targets);
        if (explicitPlan.rules.size() != 3
                || !explicitPlan.rules.get(0).tunnelName.equals("NL")
                || !explicitPlan.rules.get(1).tunnelName.equals("US")
                || !explicitPlan.rules.get(2).tunnelName.equals("NL")) {
            throw new AssertionError("Explicit app protocol overrides must be first.");
        }
        refused(() -> RootPerAppUidPolicyPlan.prepare("NL",
                Arrays.asList(nl, us), Collections.singletonList(app),
                Collections.emptyList(), Collections.singletonList(tcp443),
                Collections.emptyMap()));
        targets.put(AppUseCategories.REGIONAL, "missing");
        refused(() -> RootPerAppUidPolicyPlan.prepare("NL",
                Arrays.asList(nl, us), Collections.singletonList(app),
                Collections.emptyList(), Collections.singletonList(tcp443), targets));

        System.out.println("RootCategoryProtocolRuleTest passed");
    }
}
