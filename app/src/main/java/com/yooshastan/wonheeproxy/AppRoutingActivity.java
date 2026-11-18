package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.res.ColorStateList;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.text.Editable;
import android.text.TextWatcher;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Consumer-friendly planning screen for a future root UID routing engine.
 * All category/target changes are local metadata. NO per-app routing is
 * installed, and this screen never invokes root or Android VpnService.
 */
public final class AppRoutingActivity extends Activity {
    private static final int BACKGROUND = 0xff15101e;
    private static final int SURFACE = 0xff2b2038;
    private static final int ALT = 0xff382745;
    private static final int PINK = 0xffffaddb;
    private static final int WHITE = 0xfffff7fd;
    private static final int MUTED = 0xffc9bed2;
    private static final int PAGE_LIMIT = 60;

    private AppRoutingDraftStore drafts;
    private List<SecureTunnelProfileStore.Profile> profiles = new ArrayList<>();
    private final List<AppEntry> launchableApps = new ArrayList<>();
    private LinearLayout tabContent;
    private LinearLayout appRows;
    private TextView listStatus;
    private int activeTab; // 0 Apps, 1 Categories, 2 Protocols & Ports
    private boolean loadedApps;
    private String search = "";
    private int visibleLimit = PAGE_LIMIT;

    private static final class AppEntry {
        final String name;
        final String pkg;
        final Drawable icon;

        AppEntry(String name, String pkg, Drawable icon) {
            this.name = name;
            this.pkg = pkg;
            this.icon = icon;
        }
    }

    @Override public void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        getWindow().setStatusBarColor(BACKGROUND);
        getWindow().setNavigationBarColor(BACKGROUND);
        drafts = new AppRoutingDraftStore(this);
        refreshSavedProfiles();

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BACKGROUND);
        scroll.setOnApplyWindowInsetsListener((v, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(
                        WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            } else {
                v.setPadding(insets.getSystemWindowInsetLeft(),
                        insets.getSystemWindowInsetTop(),
                        insets.getSystemWindowInsetRight(),
                        insets.getSystemWindowInsetBottom());
            }
            return insets;
        });
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(17), dp(15), dp(17), dp(28));
        scroll.addView(page);
        setContentView(scroll);
        scroll.requestApplyInsets();

        text(page, "APP ROUTING", 23, PINK);
        LinearLayout notice = card(page);
        text(notice, "PLANNING ONLY · NOT ACTIVE", 15, PINK);
        text(notice, "Choose an app category and its preferred tunnel. "
                + "These assignments are saved on this device but DO NOT route "
                + "any app traffic yet. Wonhee still follows the current "
                + "selected Internet and private-network routes.", 13, WHITE);
        text(notice, "Live per-app routing requires a separately tested root "
                + "UID, DNS and firewall engine. Nothing on this page starts "
                + "a VPN, changes Private DNS or disables protection.", 12, MUTED);

        LinearLayout tabs = new LinearLayout(this);
        tabs.setOrientation(LinearLayout.HORIZONTAL);
        page.addView(tabs, new LinearLayout.LayoutParams(-1, -2));
        Button apps = button(tabs, "Apps", () -> switchTab(0));
        Button categories = button(tabs, "Categories", () -> switchTab(1));
        Button protocols = button(tabs, "Protocols", () -> switchTab(2));
        apps.setTextSize(12);
        categories.setTextSize(12);
        protocols.setTextSize(12);
        apps.setLayoutParams(new LinearLayout.LayoutParams(0, dp(52), 1f));
        categories.setLayoutParams(new LinearLayout.LayoutParams(0, dp(52), 1f));
        protocols.setLayoutParams(new LinearLayout.LayoutParams(0, dp(52), 1f));

        tabContent = new LinearLayout(this);
        tabContent.setOrientation(LinearLayout.VERTICAL);
        page.addView(tabContent);
        switchTab(0);
        loadInstalledApps();
    }

    @Override protected void onResume() {
        super.onResume();
        if (drafts != null) {
            refreshSavedProfiles();
            if (tabContent != null && activeTab == 1) showCategories();
            if (tabContent != null && activeTab == 2) showGlobalProtocols();
        }
    }

    private void refreshSavedProfiles() {
        try {
            profiles = new SecureTunnelProfileStore(this).load();
        } catch (Exception unavailable) {
            profiles = new ArrayList<>();
            // A storage error must not rewrite saved assignments or profiles.
        }
    }

    private void switchTab(int next) {
        activeTab = next;
        if (next == 1) showCategories();
        else if (next == 2) showGlobalProtocols();
        else showApps();
    }

    private void showApps() {
        tabContent.removeAllViews();
        text(tabContent, "Choose how each app is used", 17, WHITE);
        text(tabContent, "Only apps with launcher icons are listed. "
                + "Android background/system processes are not enumerated "
                + "or routed in this version.", 12, MUTED);
        EditText query = new EditText(this);
        query.setSingleLine(true);
        query.setTextColor(WHITE);
        query.setHintTextColor(MUTED);
        query.setHint("Find an app");
        query.setTextSize(15);
        query.setText(search);
        tabContent.addView(query, new LinearLayout.LayoutParams(-1, dp(52)));

        listStatus = text(tabContent, loadedApps ? "Loading…" : "Finding installed apps…",
                12, MUTED);
        appRows = new LinearLayout(this);
        appRows.setOrientation(LinearLayout.VERTICAL);
        tabContent.addView(appRows);
        query.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int st, int count, int after) { }
            @Override public void onTextChanged(CharSequence s, int st, int before, int count) {
                search = s.toString();
                visibleLimit = PAGE_LIMIT;
                renderAppRows();
            }
            @Override public void afterTextChanged(Editable e) { }
        });
        renderAppRows();
    }

    private void loadInstalledApps() {
        new Thread(() -> {
            Map<String, AppEntry> found = new HashMap<>();
            try {
                PackageManager pm = getPackageManager();
                Intent intent = new Intent(Intent.ACTION_MAIN);
                intent.addCategory(Intent.CATEGORY_LAUNCHER);
                List<ResolveInfo> candidates;
                if (Build.VERSION.SDK_INT >= 33) {
                    candidates = pm.queryIntentActivities(intent,
                            PackageManager.ResolveInfoFlags.of(0L));
                } else {
                    candidates = pm.queryIntentActivities(intent, 0);
                }
                for (ResolveInfo info : candidates) {
                    if (info.activityInfo == null) continue;
                    String pkg = info.activityInfo.packageName;
                    if (!AppUseCategories.validPackageName(pkg)
                            || pkg.equals(getPackageName()) || found.containsKey(pkg)) continue;
                    CharSequence title = info.loadLabel(pm);
                    String label = title == null ? pkg : title.toString();
                    if (label.trim().isEmpty()) label = pkg;
                    Drawable icon = null;
                    try { icon = info.loadIcon(pm); } catch (RuntimeException ignored) { }
                    found.put(pkg, new AppEntry(label, pkg, icon));
                }
            } catch (RuntimeException ignored) {
                // Android package visibility varies; do not request broad inventory.
            }
            ArrayList<AppEntry> sorted = new ArrayList<>(found.values());
            sorted.sort(Comparator.comparing(a -> a.name.toLowerCase(Locale.ROOT)));
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                launchableApps.clear();
                launchableApps.addAll(sorted);
                loadedApps = true;
                if (activeTab == 0) renderAppRows();
            });
        }, "wonhee-visible-app-categories").start();
    }

    private void renderAppRows() {
        if (appRows == null || listStatus == null || activeTab != 0) return;
        appRows.removeAllViews();
        if (!loadedApps) {
            listStatus.setText("Finding launchable apps…");
            return;
        }
        String needle = search.trim().toLowerCase(Locale.ROOT);
        int matching = 0, shown = 0;
        for (AppEntry app : launchableApps) {
            if (!needle.isEmpty() && !app.name.toLowerCase(Locale.ROOT).contains(needle)
                    && !app.pkg.toLowerCase(Locale.ROOT).contains(needle)) continue;
            matching++;
            if (shown >= visibleLimit) continue;
            shown++;
            addAppRow(appRows, app);
        }
        listStatus.setText(shown + " of " + matching + " matching apps");
        if (matching > shown) {
            button(appRows, "Show more apps", () -> {
                visibleLimit += PAGE_LIMIT;
                renderAppRows();
            });
        }
        if (matching == 0) {
            text(appRows, "No matching launchable apps.", 14, MUTED);
        }
    }

    private void addAppRow(LinearLayout parent, AppEntry app) {
        LinearLayout row = card(parent);
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        row.addView(header);
        if (app.icon != null) {
            ImageView icon = new ImageView(this);
            icon.setImageDrawable(app.icon);
            header.addView(icon, new LinearLayout.LayoutParams(dp(37), dp(37)));
        }
        LinearLayout nameColumn = new LinearLayout(this);
        nameColumn.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams nameParams = new LinearLayout.LayoutParams(-1, -2);
        nameParams.leftMargin = dp(9);
        header.addView(nameColumn, nameParams);
        text(nameColumn, app.name, 15, WHITE);
        text(nameColumn, app.pkg, 10, MUTED);

        int selected;
        try {
            selected = drafts.appCategory(app.pkg);
        } catch (RuntimeException invalid) {
            text(row, "Saved app assignments are unreadable. No changes made.", 12, PINK);
            return;
        }
        Spinner picker = selector(row, AppUseCategories.LABELS);
        picker.setSelection(selected, false);
        TextView planned = text(row, plannedTunnelLabel(selected), 12, MUTED);
        picker.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View v, int idx, long id) {
                try {
                    if (drafts.appCategory(app.pkg) != idx) {
                        drafts.setAppCategory(app.pkg, idx);
                    }
                    planned.setText(plannedTunnelLabel(idx));
                } catch (RuntimeException failed) {
                    error("Category not saved", "No network settings changed. "
                            + "The app assignment could not be saved locally.");
                }
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        int count;
        try {
            count = drafts.protocolRules(app.pkg).size();
        } catch (RuntimeException invalid) {
            count = 0;
        }
        button(row, "Protocol rules · " + count + " · preview", () -> {
            Intent intent = new Intent(this, AppProtocolRulesActivity.class);
            intent.putExtra(AppProtocolRulesActivity.EXTRA_PACKAGE, app.pkg);
            startActivity(intent);
        });
    }

    private String plannedTunnelLabel(int category) {
        try {
            String name = drafts.categoryTunnel(category);
            if (name.isEmpty()) return "Draft destination: current Internet exit (not enforced)";
            for (SecureTunnelProfileStore.Profile profile : profiles) {
                if (profile.name.equals(name)) {
                    return "Draft destination: " + profile.name + " · "
                            + TunnelUseCategories.routingLabel(profile.routeMode);
                }
            }
            return "Draft destination unavailable — select a saved tunnel";
        } catch (RuntimeException unavailable) {
            return "Draft tunnel assignment unavailable";
        }
    }

    private void showCategories() {
        tabContent.removeAllViews();
        text(tabContent, "Preferred tunnel by category", 17, WHITE);
        text(tabContent, "These choices are SAVED DRAFTS, not live per-app "
                + "routes. The current root policy supports only one full "
                + "Internet default plus compatible destination-specific tunnels.",
                12, MUTED);

        for (int i = 0; i < AppUseCategories.LABELS.length; i++) {
            final int category = i;
            LinearLayout row = card(tabContent);
            text(row, AppUseCategories.label(i), 16, PINK);
            text(row, AppUseCategories.EXPLANATIONS[i], 12, MUTED);
            ArrayList<String> labels = new ArrayList<>();
            ArrayList<String> names = new ArrayList<>();
            labels.add("Use current Internet exit (draft)");
            names.add("");
            String current;
            try { current = drafts.categoryTunnel(i); }
            catch (RuntimeException failed) {
                text(row, "Draft storage unreadable; choices unchanged.", 12, PINK);
                continue;
            }
            int selected = 0;
            for (SecureTunnelProfileStore.Profile profile : profiles) {
                labels.add(profile.name + " · "
                        + TunnelUseCategories.routingLabel(profile.routeMode));
                names.add(profile.name);
                if (profile.name.equals(current)) selected = names.size() - 1;
            }
            if (!current.isEmpty() && selected == 0) {
                labels.add("Unavailable saved tunnel (choose another)");
                names.add(current);
                selected = names.size() - 1;
            }
            final String[] labelArray = labels.toArray(new String[0]);
            Spinner picker = selector(row, labelArray);
            picker.setSelection(selected, false);
            picker.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                @Override public void onItemSelected(AdapterView<?> parent, View v,
                        int idx, long id) {
                    String chosen = names.get(idx);
                    try {
                        if (!chosen.equals(drafts.categoryTunnel(category))) {
                            drafts.setCategoryTunnel(category, chosen);
                        }
                    } catch (RuntimeException invalid) {
                        error("Tunnel choice not saved", "Your saved VPN profiles "
                                + "were not changed. The draft could not be stored.");
                    }
                }
                @Override public void onNothingSelected(AdapterView<?> parent) { }
            });
        }
        text(tabContent, "Choosing two full-Internet exits here does not "
                + "enable them together. Category routing and traffic-type "
                + "rules require separate kernel/firewall/DNS validation "
                + "and are intentionally disabled.", 12, MUTED);
        button(tabContent, "Review app + protocol policy · read only", () -> {
            // The review parses encrypted profiles and current package UIDs;
            // keep this work off the UI thread. No root or network access.
            new Thread(() -> {
                final String report = RootAppUidReadiness.describe(this);
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    new AlertDialog.Builder(this).setTitle("Routing readiness · DRY RUN")
                            .setMessage(report)
                            .setPositiveButton("OK", null).show();
                });
            }, "wonhee-uid-protocol-review").start();
        });
    }

    /**
     * Global L4 traffic selectors: choose a CATEGORY first, not an app.
     * Every selector is only a saved draft until a separate, fail-closed
     * root policy engine proves multi-exit DNS, UID and firewall ownership.
     */
    private void showGlobalProtocols() {
        tabContent.removeAllViews();
        text(tabContent, "Protocols & Ports", 18, WHITE);
        LinearLayout summary = card(tabContent);
        text(summary, "GLOBAL RULES · PLANNING ONLY", 15, PINK);
        text(summary, "A rule here takes precedence over an app's ordinary "
                + "category. Example: UDP destination port 443 → Private. "
                + "The Private category then specifies the preferred tunnel.",
                13, WHITE);
        text(summary, "A more specific rule you set for an individual app "
                + "still takes priority. These are drafts only—no traffic "
                + "is currently routed, classified or inspected.", 12, MUTED);

        LinearLayout popular = card(tabContent);
        text(popular, "COMMON PROTOCOL PRESETS", 15, PINK);
        text(popular, "Pick a familiar service. Wonhee will save its "
                + "usual TCP/UDP destination ports, not inspect encrypted "
                + "traffic. You can still create custom rules below.", 12, MUTED);
        Spinner presetPicker = selector(popular, RootCommonProtocolPresets.labels());
        TextView presetPreview = text(popular, "", 12, MUTED);
        Runnable refreshPreset = () -> {
            RootCommonProtocolPresets.Preset p =
                    RootCommonProtocolPresets.get(presetPicker.getSelectedItemPosition());
            presetPreview.setText(p.explanation + "\nPorts: " + p.selectorsLabel());
        };
        presetPicker.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View item,
                    int position, long id) {
                refreshPreset.run();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        refreshPreset.run();
        text(popular, "Use the tunnel assigned to this category", 12, MUTED);
        Spinner presetCategory = selector(popular, AppUseCategories.LABELS);
        button(popular, "Use these ports · save draft", () -> {
            final RootCommonProtocolPresets.Preset chosen;
            final java.util.List<RootCategoryProtocolRule.Rule> newRules;
            final java.util.List<RootCategoryProtocolRule.Rule> currentRules;
            try {
                chosen = RootCommonProtocolPresets.get(
                        presetPicker.getSelectedItemPosition());
                newRules = chosen.rules(presetCategory.getSelectedItemPosition());
                currentRules = drafts.categoryProtocolRules();
            } catch (RuntimeException invalid) {
                error("Unavailable preset", "The protocol rule could not be prepared.");
                return;
            }
            int overlapping = 0;
            for (RootCategoryProtocolRule.Rule fresh : newRules) {
                for (RootCategoryProtocolRule.Rule old : currentRules) {
                    if (fresh.transport == old.transport
                            && fresh.destinationPort == old.destinationPort) {
                        overlapping++;
                        break;
                    }
                }
            }
            String explanation = chosen.label + " (" + chosen.selectorsLabel()
                    + ") → " + AppUseCategories.label(presetCategory.getSelectedItemPosition())
                    + ". " + (overlapping == 0 ? ""
                        : overlapping + " existing port rule(s) will be replaced. ")
                    + "This is a local draft only; no VPN traffic changes.";
            new AlertDialog.Builder(this)
                    .setTitle("Save common protocol ports?")
                    .setMessage(explanation)
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Save draft", (dialog, which) -> {
                        try {
                            drafts.putCategoryProtocolPreset(newRules);
                            showGlobalProtocols();
                        } catch (RuntimeException failed) {
                            error("Preset not saved", "The rule set exceeds its "
                                    + "limit or could not be saved. Existing "
                                    + "rules remain unchanged.");
                        }
                    }).show();
        });
        text(popular, "No GPS preset: device location uses satellites, "
                + "Wi-Fi/cell data and various online services—not one "
                + "reliable network port.", 12, MUTED);

        List<RootCategoryProtocolRule.Rule> saved;
        try {
            saved = drafts.categoryProtocolRules();
        } catch (RuntimeException invalid) {
            text(tabContent, "Protocol draft storage cannot be read; no changes "
                    + "have been made.", 13, PINK);
            return;
        }
        LinearLayout existing = card(tabContent);
        text(existing, "YOUR GLOBAL RULES · " + saved.size(), 15, PINK);
        if (saved.isEmpty()) {
            text(existing, "No rules. Apps follow their selected categories.",
                    13, MUTED);
        }
        for (RootCategoryProtocolRule.Rule rule : saved) {
            LinearLayout item = card(existing);
            text(item, rule.summary(), 14, WHITE);
            button(item, "Remove rule", () -> {
                new AlertDialog.Builder(this)
                        .setTitle("Remove global protocol rule?")
                        .setMessage("Only the locally saved rule is removed. "
                                + "No active connection is changed.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Remove", (dialog, index) -> {
                            try {
                                drafts.removeCategoryProtocolRule(
                                        rule.transport, rule.destinationPort);
                                showGlobalProtocols();
                            } catch (RuntimeException invalid) {
                                error("Could not save", "The rule was not removed.");
                            }
                        }).show();
            });
        }

        LinearLayout editor = card(tabContent);
        text(editor, "CUSTOM TCP / UDP RULE", 15, PINK);
        text(editor, "Transport", 12, MUTED);
        Spinner transport = selector(editor, new String[]{"TCP", "UDP"});
        text(editor, "Destination port", 12, MUTED);
        EditText port = new EditText(this);
        port.setTextSize(14);
        port.setTextColor(WHITE);
        port.setHintTextColor(MUTED);
        port.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        port.setSingleLine(true);
        port.setHint("Blank = all ports for this transport");
        editor.addView(port, new LinearLayout.LayoutParams(-1, dp(52)));

        text(editor, "Override app category with", 12, MUTED);
        Spinner category = selector(editor, AppUseCategories.LABELS);
        text(editor, "Set that category's tunnel under Categories. "
                + "An unset or incompatible target must be refused by "
                + "future enforcement, never silently use another exit.",
                12, MUTED);
        button(editor, "Save global rule · preview", () -> {
            int protocol = transport.getSelectedItemPosition() == 0
                    ? RootProtocolRouteDraft.TCP : RootProtocolRouteDraft.UDP;
            String typed = port.getText().toString().trim();
            final int dest;
            try {
                dest = typed.isEmpty() ? RootProtocolRouteDraft.ANY_PORT
                        : Integer.parseInt(typed);
                if (!typed.isEmpty() && dest == 0) {
                    error("Invalid port", "Enter 1–65535 or leave the port blank.");
                    return;
                }
                RootCategoryProtocolRule.Rule rule =
                        new RootCategoryProtocolRule.Rule(protocol, dest,
                                category.getSelectedItemPosition());
                drafts.putCategoryProtocolRule(rule);
                showGlobalProtocols();
            } catch (NumberFormatException invalid) {
                error("Invalid port", "Enter 1–65535 or leave the port blank.");
            } catch (RuntimeException invalid) {
                error("Rule not saved", "The selected protocol, category or "
                        + "rule limit is invalid. Existing drafts were kept.");
            }
        });
        text(tabContent, "Precedence for future implementation: individual "
                + "app protocol rule → global protocol/port rule → app "
                + "category → device default. TCP and UDP ports cannot "
                + "reliably identify HTTPS, QUIC, financial or media traffic. "
                + "This screen makes no live kernel changes.", 12, MUTED);
    }

    private Spinner selector(LinearLayout parent, String[] labels) {
        Spinner spinner = new Spinner(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(
                this, android.R.layout.simple_spinner_item, labels) {
            @Override public View getView(int position, View convert, ViewGroup group) {
                View view = super.getView(position, convert, group);
                if (view instanceof TextView) ((TextView) view).setTextColor(WHITE);
                return view;
            }
            @Override public View getDropDownView(int position, View convert, ViewGroup group) {
                View view = super.getDropDownView(position, convert, group);
                if (view instanceof TextView) ((TextView) view).setTextColor(0xff15101e);
                return view;
            }
        };
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
        spinner.setMinimumHeight(dp(50));
        parent.addView(spinner, new LinearLayout.LayoutParams(-1, -2));
        return spinner;
    }

    private void error(String heading, String explanation) {
        if (isFinishing() || isDestroyed()) return;
        new AlertDialog.Builder(this).setTitle(heading)
                .setMessage(explanation).setPositiveButton("OK", null).show();
    }

    private LinearLayout card(LinearLayout parent) {
        LinearLayout item = new LinearLayout(this);
        item.setOrientation(LinearLayout.VERTICAL);
        item.setPadding(dp(12), dp(9), dp(12), dp(9));
        GradientDrawable background = new GradientDrawable();
        background.setColor(SURFACE);
        background.setCornerRadius(dp(14));
        item.setBackground(background);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(9);
        parent.addView(item, params);
        return item;
    }

    private TextView text(LinearLayout parent, String content, int size, int color) {
        TextView text = new TextView(this);
        text.setText(content);
        text.setTextSize(size);
        text.setTextColor(color);
        text.setPadding(0, dp(3), 0, dp(4));
        parent.addView(text);
        return text;
    }

    private Button button(LinearLayout parent, String label, Runnable callback) {
        Button action = new Button(this);
        action.setText(label);
        action.setAllCaps(false);
        action.setTextSize(14);
        action.setTextColor(WHITE);
        GradientDrawable background = new GradientDrawable();
        background.setColor(ALT);
        background.setCornerRadius(dp(13));
        action.setBackground(background);
        action.setMinHeight(dp(50));
        parent.addView(action);
        action.setOnClickListener(v -> callback.run());
        return action;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
