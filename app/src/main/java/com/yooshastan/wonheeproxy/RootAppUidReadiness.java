package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.pm.PackageManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * READ-ONLY bridge from user draft preferences to the pure UID + transport
 * route planner. Does not invoke root, open network sockets, or touch Android
 * VpnService, DNS, firewall, routing tables or existing WireGuard interfaces.
 *
 * Every app UID is resolved again from the installed package manager on each
 * preview, not inferred from screenshots or cached across app installations.
 */
final class RootAppUidReadiness {
    private RootAppUidReadiness() { }

    static String describe(Context context) {
        try {
            AppRoutingDraftStore drafts = new AppRoutingDraftStore(context);
            List<SecureTunnelProfileStore.Profile> saved =
                    new SecureTunnelProfileStore(context).load();
            String defaultName = drafts.categoryTunnel(AppUseCategories.EVERYDAY);
            if (defaultName.isEmpty()) {
                return "READ-ONLY UID CHECK\nSet the Everyday category's "
                        + "device-wide Internet tunnel first. No traffic changed.";
            }
            Map<String, Integer> assignments = drafts.appCategories();
            List<RootProtocolRouteDraft.Override> overrides =
                    drafts.allProtocolRules();
            List<RootCategoryProtocolRule.Rule> globalRules =
                    drafts.categoryProtocolRules();
            Map<Integer, String> categoryExits = new HashMap<>();
            for (RootCategoryProtocolRule.Rule global : globalRules) {
                // Never infer a fallback for a category-wide override.
                String target = drafts.categoryTunnel(global.category);
                if (target.isEmpty()) {
                    return "READ-ONLY UID CHECK\nA global transport category "
                            + "does not have a selected tunnel. Set its "
                            + "category destination first.";
                }
                categoryExits.put(global.category, target);
            }
            Set<String> packages = new HashSet<>(assignments.keySet());
            for (RootProtocolRouteDraft.Override rule : overrides) {
                packages.add(rule.packageName);
            }
            if (packages.isEmpty()) {
                return "READ-ONLY UID CHECK\nAssign an app to a category or "
                        + "save a TCP/UDP protocol rule first. No traffic changed.";
            }
            if (packages.size() > 100) {
                return "READ-ONLY UID CHECK\nToo many assigned apps for "
                        + "the experimental reserved routing range.";
            }
            Map<String, SecureTunnelProfileStore.Profile> byName = new HashMap<>();
            for (SecureTunnelProfileStore.Profile profile : saved) {
                if (byName.put(profile.name, profile) != null) {
                    return "READ-ONLY UID CHECK\nConflicting saved tunnel names.";
                }
            }
            Set<String> selectedNames = new HashSet<>();
            selectedNames.add(defaultName);
            PackageManager pm = context.getPackageManager();
            List<RootPerAppUidPolicyPlan.App> resolved = new ArrayList<>();
            for (String pkg : packages) {
                final int uid;
                try {
                    uid = pm.getPackageUid(pkg, 0);
                } catch (PackageManager.NameNotFoundException unavailable) {
                    return "READ-ONLY UID CHECK\nAn assigned app is no longer "
                            + "installed or visible. Review Apps before using it.";
                }
                String[] owners = pm.getPackagesForUid(uid);
                if (owners == null || owners.length != 1 || !pkg.equals(owners[0])) {
                    // A shared UID cannot be isolated into individual packages
                    // with Linux uidrange. Refuse ambiguous package identity.
                    return "READ-ONLY UID CHECK\nAn assigned app has an "
                            + "unverified or shared Android UID. Per-app "
                            + "isolation would be unsafe.";
                }
                int category = drafts.appCategory(pkg);
                String target = drafts.categoryTunnel(category);
                if (target.isEmpty()) target = defaultName;
                selectedNames.add(target);
                resolved.add(new RootPerAppUidPolicyPlan.App(pkg, uid, target));
            }
            for (RootProtocolRouteDraft.Override rule : overrides) {
                selectedNames.add(rule.tunnelName);
            }
            selectedNames.addAll(categoryExits.values());
            List<SecureTunnelProfileStore.Profile> selected = new ArrayList<>();
            for (String name : selectedNames) {
                SecureTunnelProfileStore.Profile profile = byName.get(name);
                if (profile == null) {
                    return "READ-ONLY UID CHECK\nA category or protocol rule "
                            + "references a tunnel that was deleted or renamed.";
                }
                selected.add(profile);
            }
            RootPerAppUidPolicyPlan.Plan plan =
                    RootPerAppUidPolicyPlan.prepare(defaultName,
                            RootMultiKernelSession.previewAppUidRoutes(selected),
                            resolved, overrides, globalRules, categoryExits);
            return plan.summary()
                    + "\nGLOBAL RULE SCOPE: This read-only proposal only "
                    + "checks explicitly assigned, launcher-visible apps. "
                    + "It does not enumerate or enforce every Android "
                    + "system/background UID. No traffic changed.";
        } catch (Exception | LinkageError invalid) {
            // Never leak raw encrypted profiles, WireGuard keys, DNS URLs,
            // app package inventories or private shell error text.
            return "READ-ONLY UID CHECK\nUnable to validate the proposed "
                    + "routing policy. Review the saved categories, full-exit "
                    + "tunnels and protocol rules; nothing was changed.";
        }
    }
}
