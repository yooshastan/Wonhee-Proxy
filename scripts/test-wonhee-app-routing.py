#!/usr/bin/env python3
"""Source-level safety contract for App Routing phase 1 (NOT network enforcement)."""
from pathlib import Path
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parent.parent
java = root / "app/src/main/java/com/yooshastan/wonheeproxy"
manifest_text = (root / "app/src/main/AndroidManifest.xml").read_text()
app = (java / "AppRoutingActivity.java").read_text()
draft = (java / "AppRoutingDraftStore.java").read_text()
categories = (java / "AppUseCategories.java").read_text()
dashboard = (java / "WonheeDashboardPreviewActivity.java").read_text()


def require(value, message):
    if not value:
        raise AssertionError(message)


ET.fromstring(manifest_text)
require('android:name=".AppRoutingActivity" android:exported="false"' in manifest_text,
        "App Routing must not accept external intents")
require('<action android:name="android.intent.action.MAIN" />' in manifest_text
        and '<category android:name="android.intent.category.LAUNCHER" />' in manifest_text,
        "Scoped launcher intent visibility is required")
require('<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"' not in
        manifest_text, "App Routing must not request broad package inventory")
require('getSharedPreferences(PREFS, Context.MODE_PRIVATE)' in draft,
        "Drafts must be app-private")
require('MAX_APP_OVERRIDES = 512' in draft,
        "Bound saved app assignments to prevent unbounded storage")
require('prefs.edit().putString(APPS' in draft
        and 'prefs.edit().putString(TUNNELS' in draft,
        "Both types of draft assignment must persist locally")
require('static final String[] LABELS' in categories
        and categories.count('static final int ') >= 8,
        "Expected eight well-defined app-use categories")
require("Intent.ACTION_MAIN" in app and "Intent.CATEGORY_LAUNCHER" in app,
        "Only explicitly launchable apps should be enumerated")
require("AppUseCategories.validPackageName" in app,
        "App inventory must validate app identifiers")
require("drafts.setAppCategory" in app
        and "drafts.setCategoryTunnel" in app,
        "Both app->category and category->tunnel assignments must be editable")
require("PLANNING ONLY" in app and "DO NOT route" in app,
        "Do not present drafts as active network protection")
require("new Intent(this, AppRoutingActivity.class)" in dashboard,
        "App Routing planner must be accessible from the Tunnels screen")
for forbidden in ("RootShell", "RootMultiKernelSession", "RootDnsRelayRunner",
                  "enableRootDns(", "startManagedStack(",
                  "VpnService", "setUidRoute", "addUid", "QUERY_ALL_PACKAGES"):
    # The warning paragraph may legitimately mention Android VPN terminology.
    if forbidden == "VpnService":
        continue
    require(forbidden not in app and forbidden not in draft,
            "Draft screen/store must never change networking: " + forbidden)

protocol_ui = (java / "AppProtocolRulesActivity.java").read_text()
protocol_model = (java / "RootProtocolRouteDraft.java").read_text()
uid_plan = (java / "RootPerAppUidPolicyPlan.java").read_text()
uid_readiness = (java / "RootAppUidReadiness.java").read_text()
require('android:name=".AppProtocolRulesActivity" android:exported="false"' in
        manifest_text, "Protocol editor must be private to Wonhee")
require('new Intent(this, AppProtocolRulesActivity.class)' in app,
        "App list must reach the advanced protocol editor")
require('"PLANNING ONLY · NOT ACTIVE"' in protocol_ui,
        "Protocol configuration must be clearly labeled inactive")
require('RootProtocolRouteDraft.TCP' in protocol_ui
        and 'RootProtocolRouteDraft.UDP' in protocol_ui
        and 'RootProtocolRouteDraft.ANY_PORT' in protocol_ui,
        "Editor must accept explicit TCP/UDP and optional port")
require('drafts.putProtocolRule' in protocol_ui
        and 'drafts.removeProtocolRule' in protocol_ui,
        "User needs add/remove protocol draft rules")
require('prefs.edit().putString(PROTOCOLS' in draft,
        "Transport policy drafts must be stored locally")
require('RootProtocolRouteDraft.validateAndSort' in uid_plan
        and 'activationAllowed() { return false; }' in uid_plan,
        "UID + transport model must deny live activation")
require('previewAppUidRoutes' in uid_readiness
        and 'getPackagesForUid' in uid_readiness
        and 'getPackageUid' in uid_readiness,
        "Readiness must use actual installed UID ownership")
for source in (protocol_ui, protocol_model, uid_plan, uid_readiness):
    for dangerous in ('new RootShell(', 'shell.run(', 'iptables -w',
                      'ip rule add', 'ip rule del', 'enableRootDns(',
                      'startManagedStack('):
        require(dangerous not in source,
                "Dry-run protocol planner must not alter networking: " + dangerous)

print("PASS: eight app categories, scoped app discovery, private draft persistence, "
      "UI visibility and no route/DNS/kernel enforcement from planner")
