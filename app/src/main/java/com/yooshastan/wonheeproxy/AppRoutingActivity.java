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
    private boolean categoriesTab;
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
        Button apps = button(tabs, "Apps", () -> switchTab(false));
        Button categories = button(tabs, "Category tunnels", () -> switchTab(true));
        apps.setLayoutParams(new LinearLayout.LayoutParams(0, dp(52), 1f));
        categories.setLayoutParams(new LinearLayout.LayoutParams(0, dp(52), 1f));

        tabContent = new LinearLayout(this);
        tabContent.setOrientation(LinearLayout.VERTICAL);
        page.addView(tabContent);
        switchTab(false);
        loadInstalledApps();
    }

    @Override protected void onResume() {
        super.onResume();
        if (drafts != null) {
            refreshSavedProfiles();
            if (tabContent != null && categoriesTab) showCategories();
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

    private void switchTab(boolean categories) {
        categoriesTab = categories;
        if (categories) showCategories();
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
                if (!categoriesTab) renderAppRows();
            });
        }, "wonhee-visible-app-categories").start();
    }

    private void renderAppRows() {
        if (appRows == null || listStatus == null || categoriesTab) return;
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
    }

    private String plannedTunnelLabel(int category) {
        try {
            String name = drafts.categoryTunnel(category);
            if (name.isEmpty()) return "Draft destination: current privacy default";
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
            labels.add("Use current privacy default (draft)");
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
