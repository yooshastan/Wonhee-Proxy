package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Non-executing CI contract: no root shell, no kernel state changes. */
public final class RootIsolatedWireGuardBootstrapPlanTest {
    private static RootMultiTunnelPlan.Entry tunnel(String name, String address,
            String... routes) {
        return new RootMultiTunnelPlan.Entry(name, Arrays.asList(routes),
                Collections.singletonList(address));
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void reject(Runnable action, String message) {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Unsafe bootstrap accepted: " + message);
    }

    public static void main(String[] args) {
        RootMultiTunnelPlan.Entry eu = tunnel("Europe", "10.150.0.2/32",
                "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry us = tunnel("America", "10.151.0.2/32",
                "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry home = tunnel("Fedora Home", "10.6.0.2/32",
                "10.0.0.169/32", "10.77.0.0/24");
        List<RootMultiTunnelPlan.Entry> chosen = Arrays.asList(eu, us, home);
        RootPerAppUidPolicyPlan.Plan uidPlan =
                RootPerAppUidPolicyPlan.prepare("Europe", chosen,
                        Arrays.asList(
                                new RootPerAppUidPolicyPlan.App(
                                        "com.example.privacy", 10341, "Europe"),
                                new RootPerAppUidPolicyPlan.App(
                                        "com.example.commerce", 10342, "America")));
        RootIsolatedWireGuardBootstrapPlan.Plan plan =
                RootIsolatedWireGuardBootstrapPlan.compile(chosen, uidPlan);
        check(!plan.activationAllowed() && plan.devices == 3
                        && plan.privateRoutes == uidPlan.routes.size(),
                "Planning is non-executing but covers both full exits and Home");
        check(plan.summary().contains("DRY RUN ONLY")
                        && plan.summary().contains("NOT VERIFIED"),
                "No tunnel connection or ownership may be claimed");
        int create = 0, secret = 0, up = 0, address = 0, privateRoute = 0;
        for (RootIsolatedWireGuardBootstrapPlan.Step step : plan.steps) {
            String cmd = step.install;
            if (step.kind.equals("LINK_CREATE")) create++;
            if (step.kind.equals("PEER_CONFIG")) {
                secret++;
                check(step.requiresSecretHandoff()
                                && step.install.isEmpty() && step.inverse.isEmpty(),
                        "Never write private WireGuard config into shell commands");
            }
            if (step.kind.equals("LINK_UP")) up++;
            if (step.kind.equals("HOST_ADDRESS")) address++;
            if (step.kind.equals("PRIVATE_ROUTE")) {
                privateRoute++;
                check(cmd.matches("ip -[46] route add table 5100[0-7] .* dev wnm[0-9a-f]{12}"),
                        "Peer routes must target a dedicated private table");
            }
            check(!cmd.contains("wg-quick")
                            && !cmd.contains("route add default")
                            && !cmd.contains("route replace")
                            && !cmd.contains("ip route add")
                            && !cmd.contains(" table main")
                            && !cmd.contains("private-key")
                            && !cmd.contains("private_key")
                            && !cmd.contains("DNS="),
                    "Bootstrap cannot affect default/main routes or leak secrets");
        }
        check(create == 3 && secret == 3 && up == 3 && address == 3
                        && privateRoute == 6,
                "Each interface must have create/configure/address/up/route stages");
        List<RootIsolatedWireGuardBootstrapPlan.Step> rollback =
                plan.rollbackOrder();
        check(rollback.get(0).kind.equals("PRIVATE_ROUTE")
                        && rollback.get(rollback.size() - 1).kind.equals("LINK_CREATE")
                        && rollback.get(rollback.size() - 1).inverse
                                .contains("ip link del"),
                "Rollback reverses private routes before deleting owned link");
        check(plan.steps.equals(
                RootIsolatedWireGuardBootstrapPlan.compile(chosen, uidPlan).steps)
                == false, "Steps are immutable plan objects, not shared instances");
        try {
            plan.steps.clear();
            throw new AssertionError("Immutable startup plan was mutable");
        } catch (UnsupportedOperationException expected) { }

        // A /24 address could mutate Android's ordinary connected routes.
        RootMultiTunnelPlan.Entry badAddress = tunnel("Europe", "10.150.0.2/24",
                "0.0.0.0/0", "::/0");
        List<RootMultiTunnelPlan.Entry> nonHost = Arrays.asList(badAddress, us, home);
        RootPerAppUidPolicyPlan.Plan nonHostUid =
                RootPerAppUidPolicyPlan.prepare("Europe", nonHost,
                        Collections.singletonList(
                                new RootPerAppUidPolicyPlan.App(
                                        "com.example.privacy", 10341, "Europe")));
        reject(() -> RootIsolatedWireGuardBootstrapPlan.compile(nonHost, nonHostUid),
                "Connected IPv4 /24 could introduce a main-table route");

        RootMultiTunnelPlan.Entry nonHostV6 =
                new RootMultiTunnelPlan.Entry("Europe",
                        Arrays.asList("0.0.0.0/0", "::/0"),
                        Arrays.asList("10.150.0.2/32", "fd00:1::2/64"));
        List<RootMultiTunnelPlan.Entry> nonHost6 =
                Arrays.asList(nonHostV6, us, home);
        RootPerAppUidPolicyPlan.Plan uid6 =
                RootPerAppUidPolicyPlan.prepare("Europe", nonHost6,
                        Collections.singletonList(
                                new RootPerAppUidPolicyPlan.App(
                                        "com.example.privacy", 10341, "Europe")));
        reject(() -> RootIsolatedWireGuardBootstrapPlan.compile(nonHost6, uid6),
                "Connected IPv6 /64 could introduce a main-table route");

        List<RootMultiTunnelPlan.Entry> missing = Arrays.asList(eu, home);
        reject(() -> RootIsolatedWireGuardBootstrapPlan.compile(missing, uidPlan),
                "Bootstrap must reject route entries missing from selection");
        RootPerAppUidPolicyPlan.Route moved = uidPlan.routes.get(0);
        List<RootPerAppUidPolicyPlan.Route> corrupted =
                new ArrayList<>(uidPlan.routes);
        corrupted.set(0, new RootPerAppUidPolicyPlan.Route(moved.family,
                moved.destination, moved.device, moved.table + 1));
        RootPerAppUidPolicyPlan.Plan mismatch =
                new RootPerAppUidPolicyPlan.Plan(uidPlan.defaultExit, corrupted,
                        uidPlan.rules);
        reject(() -> RootIsolatedWireGuardBootstrapPlan.compile(chosen, mismatch),
                "Changing a peer route to the wrong private table is refused");

        System.out.println("RootIsolatedWireGuardBootstrapPlanTest passed");
    }
}
