#!/usr/bin/env python3
"""Static regression check: everyday entry points must not open legacy Wonhee.

Read-only source checks. Does NOT simulate an Android task or prove UX on device.
"""
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app/src/main"
JAVA = APP / "java/com/yooshastan/wonheeproxy"
ANDROID = "{http://schemas.android.com/apk/res/android}"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


manifest = ET.parse(APP / "AndroidManifest.xml").getroot()
application = manifest.find("application")
require(application is not None, "Missing Android application manifest")
launchers = []
vpn_activity = None
for activity in application.findall("activity"):
    name = activity.get(ANDROID + "name", "")
    if name == ".VpnActivity":
        vpn_activity = activity
    for filter_ in activity.findall("intent-filter"):
        actions = {node.get(ANDROID + "name") for node in filter_.findall("action")}
        cats = {node.get(ANDROID + "name") for node in filter_.findall("category")}
        if ("android.intent.action.MAIN" in actions
                and "android.intent.category.LAUNCHER" in cats):
            launchers.append(name)
require(launchers == [".WonheeDashboardPreviewActivity"],
        f"Launcher must be everyday Home only: {launchers}")
require(vpn_activity is not None
        and vpn_activity.get(ANDROID + "finishOnTaskLaunch") == "true",
        "Legacy VpnActivity must not survive launcher task reset")

for filename in ("WonheeQuickSettingsTile.java",
                 "VpnTrafficNotificationService.java",
                 "RootMultiTrafficNotificationService.java"):
    source = (JAVA / filename).read_text(encoding="utf-8")
    require("new Intent(this, WonheeDashboardPreviewActivity.class)" in source,
            f"{filename} does not open everyday Home")
    require("new Intent(this, VpnActivity.class)" not in source,
            f"{filename} still opens the legacy VPN UI")
    require("new Intent(this, RootMultiKernelActivity.class)" not in source,
            f"{filename} still opens the root lab")

vpn = (JAVA / "VpnActivity.java").read_text(encoding="utf-8")
require("routeOldLauncherTaskToHome()" in vpn
        and "Intent.FLAG_ACTIVITY_CLEAR_TASK" in vpn,
        "Pre-upgrade restored legacy root task is not redirected")
require("if (quickImportFlow) finish();" in vpn,
        "Android file picker cancellation must return from legacy manager")
require('setTitle(imported > 0 ? "Tunnel saved" : "No tunnels added")' in vpn,
        "Import completion must present confirmation then finish")
require('getIntent().getStringExtra("wonhee.quick.action")' in vpn,
        "Legacy import helper must respect explicit Home actions")
proxy = (JAVA / "MainActivity.java").read_text(encoding="utf-8")
require("new Intent(this, WonheeDashboardPreviewActivity.class)" in proxy,
        "Proxy companion return control must target Home")

dashboard = (JAVA / "WonheeDashboardPreviewActivity.java").read_text(
    encoding="utf-8")
require("showQuickTunnelPicker(hero, false)" in dashboard,
        "Root Home selection missing")
require("showStandardTunnelPicker(hero," in dashboard,
        "Standard Home selection missing")

print("PASS: Home is the only manifest launcher, Quick Settings and both "
      "speed notifications lead Home, the proxy return control leads Home, "
      "and stranded legacy / import entry points are handled.")
