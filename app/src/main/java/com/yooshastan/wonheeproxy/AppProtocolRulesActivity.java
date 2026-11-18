package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.content.Intent;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

/**
 * Extra, optional transport / destination-port routing draft editor.
 *
 * It NEVER runs root commands or claims to enable app-specific traffic paths.
 * Users explicitly opt in per app and route selector; no packet inspection.
 */
public final class AppProtocolRulesActivity extends Activity {
    static final String EXTRA_PACKAGE = "wonhee.app_routing.package";
    private static final int BACKGROUND = 0xff15101e;
    private static final int SURFACE = 0xff2b2038;
    private static final int ALT = 0xff382745;
    private static final int PINK = 0xffffaddb;
    private static final int WHITE = 0xfffff7fd;
    private static final int MUTED = 0xffc9bed2;
    private AppRoutingDraftStore drafts;
    private String packageName;
    private LinearLayout page;
    private List<SecureTunnelProfileStore.Profile> profiles = new ArrayList<>();

    @Override public void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        packageName = getIntent().getStringExtra(EXTRA_PACKAGE);
        if (!AppUseCategories.validPackageName(packageName)) {
            finish();
            return;
        }
        drafts = new AppRoutingDraftStore(this);
        getWindow().setStatusBarColor(BACKGROUND);
        getWindow().setNavigationBarColor(BACKGROUND);

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
        page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(17), dp(15), dp(17), dp(26));
        scroll.addView(page);
        setContentView(scroll);
        scroll.requestApplyInsets();
        render();
    }

    private void render() {
        page.removeAllViews();
        text(page, "PROTOCOL RULES", 23, PINK);
        text(page, packageName, 12, MUTED);
        LinearLayout info = card(page);
        text(info, "PLANNING ONLY · NOT ACTIVE", 15, PINK);
        text(info, "Choose a tunnel for TCP or UDP traffic from this app, "
                + "optionally limited to one destination port. These rules "
                + "are saved locally but do NOT route any packets.", 13, WHITE);
        text(info, "A port number does not identify what an app is doing. "
                + "For example, TCP 443 can be login, shopping, media or "
                + "encrypted DNS; UDP 443 can be QUIC or other traffic. "
                + "No content inspection or automatic traffic-type guessing.",
                12, MUTED);
        try {
            profiles = new SecureTunnelProfileStore(this).load();
        } catch (Exception invalid) {
            text(page, "Unable to read the saved tunnel library. "
                    + "Existing protocol drafts were not changed.", 13, PINK);
            return;
        }
        List<RootProtocolRouteDraft.Override> saved;
        try {
            saved = drafts.protocolRules(packageName);
        } catch (RuntimeException invalid) {
            text(page, "Protocol drafts could not be read. No changes were made.",
                    13, PINK);
            return;
        }
        LinearLayout existing = card(page);
        text(existing, "YOUR RULES · " + saved.size(), 15, PINK);
        if (saved.isEmpty()) {
            text(existing, "None. This app follows its category's planned tunnel.",
                    13, MUTED);
        } else {
            for (RootProtocolRouteDraft.Override rule : saved) {
                LinearLayout line = card(existing);
                text(line, rule.summary(), 13, WHITE);
                button(line, "Remove this rule", () ->
                        new AlertDialog.Builder(this)
                                .setTitle("Remove protocol rule?")
                                .setMessage("Only the locally saved draft is removed. "
                                        + "No live network connections change.")
                                .setNegativeButton("Cancel", null)
                                .setPositiveButton("Remove", (dialog, which) -> {
                                    try {
                                        drafts.removeProtocolRule(packageName,
                                                rule.transport, rule.destinationPort);
                                        render();
                                    } catch (RuntimeException invalid) {
                                        error("Could not remove the saved rule.");
                                    }
                                }).show());
            }
        }
        LinearLayout add = card(page);
        text(add, "ADD A PROTOCOL RULE", 15, PINK);
        text(add, "Transport", 12, MUTED);
        Spinner protocol = spinner(add, new String[]{"TCP", "UDP"});
        text(add, "Destination port (optional)", 12, MUTED);
        EditText port = new EditText(this);
        port.setTextColor(WHITE);
        port.setHintTextColor(MUTED);
        port.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        port.setSingleLine(true);
        port.setHint("Blank = all ports for this transport");
        port.setTextSize(14);
        add.addView(port, new LinearLayout.LayoutParams(-1, dp(52)));

        text(add, "Preferred VPN tunnel", 12, MUTED);
        ArrayList<String> display = new ArrayList<>();
        display.add("Choose a saved tunnel");
        for (SecureTunnelProfileStore.Profile p : profiles) {
            display.add(p.name + " · "
                    + TunnelUseCategories.routingLabel(p.routeMode));
        }
        Spinner target = spinner(add, display.toArray(new String[0]));
        text(add, "Only a dual-stack full-Internet tunnel can be used "
                + "as an app-wide transport exit. A Home private split tunnel "
                + "requires destination-specific routing instead.", 12, MUTED);
        Button save = button(add, "Save rule · draft only", () -> {
            int transport = protocol.getSelectedItemPosition() == 0
                    ? RootProtocolRouteDraft.TCP : RootProtocolRouteDraft.UDP;
            String typed = port.getText().toString().trim();
            final int destPort;
            try {
                destPort = typed.isEmpty() ? RootProtocolRouteDraft.ANY_PORT
                        : Integer.parseInt(typed);
            } catch (NumberFormatException invalid) {
                error("Use a port between 1 and 65535, or leave blank.");
                return;
            }
            int selected = target.getSelectedItemPosition();
            if (selected <= 0 || selected > profiles.size()) {
                error("Choose a saved tunnel for this protocol rule.");
                return;
            }
            try {
                RootProtocolRouteDraft.Override rule =
                        new RootProtocolRouteDraft.Override(packageName, transport,
                                destPort, profiles.get(selected - 1).name);
                drafts.putProtocolRule(rule);
                render();
            } catch (RuntimeException invalid) {
                error("Cannot save this rule. Check the port, tunnel or rule limit.");
            }
        });
        save.setEnabled(!profiles.isEmpty());
        text(page, "Priority when eventually enforced: an exact "
                + "destination-port rule, then a transport-wide rule, "
                + "then this app's category tunnel, then the configured "
                + "device default. Missing required VPN routes must BLOCK "
                + "instead of falling back to ordinary Internet. "
                + "That enforcement is not implemented in this update.", 12, MUTED);
    }

    private Spinner spinner(LinearLayout box, String[] values) {
        Spinner spinner = new Spinner(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(
                this, android.R.layout.simple_spinner_item, values) {
            @Override public View getView(int p, View convert, ViewGroup parent) {
                View view = super.getView(p, convert, parent);
                if (view instanceof TextView) ((TextView) view).setTextColor(WHITE);
                return view;
            }

            @Override public View getDropDownView(int p, View convert, ViewGroup parent) {
                View view = super.getDropDownView(p, convert, parent);
                if (view instanceof TextView) {
                    ((TextView) view).setTextColor(BACKGROUND);
                }
                return view;
            }
        };
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
        spinner.setMinimumHeight(dp(50));
        box.addView(spinner, new LinearLayout.LayoutParams(-1, dp(50)));
        return spinner;
    }

    private void error(String message) {
        if (isFinishing() || isDestroyed()) return;
        new AlertDialog.Builder(this).setTitle("Wonhee")
                .setMessage(message).setPositiveButton("OK", null).show();
    }

    private LinearLayout card(LinearLayout parent) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(12), dp(9), dp(12), dp(10));
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(SURFACE);
        drawable.setCornerRadius(dp(14));
        card.setBackground(drawable);
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, -2);
        p.topMargin = dp(10);
        parent.addView(card, p);
        return card;
    }

    private TextView text(LinearLayout parent, String message, int size, int color) {
        TextView text = new TextView(this);
        text.setText(message);
        text.setTextSize(size);
        text.setTextColor(color);
        text.setPadding(0, dp(3), 0, dp(5));
        parent.addView(text);
        return text;
    }

    private Button button(LinearLayout parent, String title, Runnable action) {
        Button button = new Button(this);
        button.setAllCaps(false);
        button.setText(title);
        button.setTextSize(14);
        button.setTextColor(WHITE);
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(ALT);
        drawable.setCornerRadius(dp(13));
        button.setBackground(drawable);
        button.setMinHeight(dp(48));
        parent.addView(button, new LinearLayout.LayoutParams(-1, -2));
        button.setOnClickListener(v -> action.run());
        return button;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
