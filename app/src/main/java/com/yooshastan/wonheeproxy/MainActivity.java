package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import com.yooshastan.wonheeproxy.core.ProxyEndpoint;
import com.yooshastan.wonheeproxy.core.ProxyProbe;

/**
 * Intentionally not a VpnService. A profile is sent only to the installed
 * Ultgram package on an explicit tap; nothing is saved to disk or logged.
 */
public final class MainActivity extends Activity {
    private static final int BG = Color.rgb(18, 16, 29);
    private static final int FOREGROUND = Color.rgb(248, 241, 249);
    private static final int PINK = Color.rgb(251, 173, 216);
    private static final String[] ULT_PACKAGES = {
            "com.yooshastan.ultmessenger", "com.yooshastan.ultmessenger.beta"
    };

    private Spinner type;
    private EditText host;
    private EditText port;
    private EditText secret;
    private EditText username;
    private EditText password;
    private LinearLayout mtprotoFields;
    private LinearLayout socksFields;
    private TextView status;

    @Override
    protected void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BG);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(22);
        root.setPadding(padding, dp(26), padding, dp(30));
        scroll.addView(root);
        setContentView(scroll);

        TextView heading = text("WONHEE PROXY", 28, PINK);
        root.addView(heading);
        root.addView(text("Privacy gateway companion · Alpha 0.1", 15, FOREGROUND));
        root.addView(space(18));
        root.addView(text("Configure a server, check its TCP port, then import it into Ultgram. "
                + "This app does not start a VPN or silently redirect phone traffic.", 15, FOREGROUND));
        root.addView(space(18));

        root.addView(text("Protocol", 16, PINK));
        type = new Spinner(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item, new String[]{"MTProto", "SOCKS5"});
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        type.setAdapter(adapter);
        root.addView(type);

        host = field(root, "Server host or IP", "proxy.example.net", false, false);
        port = field(root, "Port", "443", false, true);
        port.setText("443");

        mtprotoFields = new LinearLayout(this);
        mtprotoFields.setOrientation(LinearLayout.VERTICAL);
        root.addView(mtprotoFields);
        secret = field(mtprotoFields, "MTProto secret", "Secret (hex)", true, false);

        socksFields = new LinearLayout(this);
        socksFields.setOrientation(LinearLayout.VERTICAL);
        root.addView(socksFields);
        username = field(socksFields, "SOCKS5 username (optional)", "Username", false, false);
        password = field(socksFields, "SOCKS5 password (optional)", "Password", true, false);

        type.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int index, long id) {
                mtprotoFields.setVisibility(index == 0 ? View.VISIBLE : View.GONE);
                socksFields.setVisibility(index == 1 ? View.VISIBLE : View.GONE);
                if (index == 1 && "443".equals(port.getText().toString())) {
                    port.setText("1080");
                } else if (index == 0 && "1080".equals(port.getText().toString())) {
                    port.setText("443");
                }
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        socksFields.setVisibility(View.GONE);

        root.addView(space(16));
        Button testButton = new Button(this);
        testButton.setText("Test TCP endpoint");
        root.addView(testButton);
        testButton.setOnClickListener(view -> confirmTcpTest());

        Button importButton = new Button(this);
        importButton.setText("Open in Ultgram");
        root.addView(importButton);
        importButton.setOnClickListener(view -> openInUltgram());

        status = text("No connection test has been run.", 14, FOREGROUND);
        root.addView(space(12));
        root.addView(status);
        root.addView(space(16));
        root.addView(text("Privacy note: a remote proxy can hide your direct IP from Telegram "
                + "only when Ultgram actually uses it. The proxy operator can see your IP. "
                + "Telegram account identity is unchanged. DNS ad filtering, fail-closed "
                + "routing and access to Navidrome are not enabled in this alpha.", 13, FOREGROUND));
    }

    private ProxyEndpoint readEndpoint() {
        int parsedPort;
        try {
            parsedPort = Integer.parseInt(port.getText().toString().trim());
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("Enter a numeric port from 1 to 65535.");
        }
        if (type.getSelectedItemPosition() == 0) {
            return ProxyEndpoint.mtproto(host.getText().toString(), parsedPort,
                    secret.getText().toString());
        }
        return ProxyEndpoint.socks5(host.getText().toString(), parsedPort,
                username.getText().toString(), password.getText().toString());
    }

    private void confirmTcpTest() {
        final ProxyEndpoint endpoint;
        try {
            endpoint = readEndpoint();
        } catch (IllegalArgumentException invalid) {
            status.setText(invalid.getMessage());
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Direct endpoint test")
                .setMessage("This connects directly to the named proxy server and may use your "
                        + "phone's DNS resolver. The server can see your IP. "
                        + "The test does NOT verify Telegram proxy authentication, routing or anonymity.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Run test", (dialog, selected) -> {
                    status.setText("Checking TCP reachability…");
                    new Thread(() -> {
                        ProxyProbe.Result result = ProxyProbe.check(endpoint, 3000);
                        runOnUiThread(() -> {
                            if (!isFinishing() && !isDestroyed()) {
                                status.setText(result.safeSummary()
                                        + " This is not a proxy handshake.");
                            }
                        });
                    }, "WonheeProxyTcpTest").start();
                })
                .show();
    }

    private void openInUltgram() {
        final ProxyEndpoint endpoint;
        try {
            endpoint = readEndpoint();
        } catch (IllegalArgumentException invalid) {
            status.setText(invalid.getMessage());
            return;
        }
        // Package-scoped implicit intent: never send the secret to a general chooser.
        Uri deepLink = Uri.parse(endpoint.telegramDeepLink());
        for (String packageName : ULT_PACKAGES) {
            Intent intent = new Intent(Intent.ACTION_VIEW, deepLink);
            intent.addCategory(Intent.CATEGORY_BROWSABLE);
            intent.setPackage(packageName);
            try {
                startActivity(intent);
                status.setText("Proxy profile handed to the selected Ultgram install. "
                        + "Enable it there and verify real message traffic.");
                return;
            } catch (ActivityNotFoundException ignored) {
                // Try only the other known Ultgram package, never an arbitrary client.
            }
        }
        status.setText("Ultgram was not found with the expected package IDs. "
                + "Install a compatible Ultgram APK first.");
    }

    private TextView text(String value, int sp, int color) {
        TextView label = new TextView(this);
        label.setText(value);
        label.setTextSize(sp);
        label.setTextColor(color);
        label.setPadding(0, dp(4), 0, dp(6));
        return label;
    }

    private EditText field(LinearLayout parent, String label, String hint,
                           boolean hidden, boolean numeric) {
        parent.addView(text(label, 14, PINK));
        EditText input = new EditText(this);
        input.setTextColor(FOREGROUND);
        input.setHintTextColor(Color.rgb(170, 161, 182));
        input.setHint(hint);
        input.setSingleLine(true);
        if (numeric) {
            input.setInputType(InputType.TYPE_CLASS_NUMBER);
        } else if (hidden) {
            input.setInputType(InputType.TYPE_CLASS_TEXT
                    | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        } else {
            input.setInputType(InputType.TYPE_CLASS_TEXT);
        }
        parent.addView(input);
        return input;
    }

    private View space(int height) {
        View spacer = new View(this);
        spacer.setLayoutParams(new LinearLayout.LayoutParams(1, dp(height)));
        return spacer;
    }

    private int dp(int amount) {
        return Math.round(getResources().getDisplayMetrics().density * amount);
    }
}
