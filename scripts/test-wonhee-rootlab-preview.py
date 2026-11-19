#!/usr/bin/env python3
"""RootLab preview separation: no change to official signing or live routing."""
from pathlib import Path
import xml.etree.ElementTree as ET

repo = Path(__file__).resolve().parent.parent
gradle = (repo / "app/build.gradle").read_text()
debug_manifest = repo / "app/src/debug/AndroidManifest.xml"
debug_activity = repo / (
    "app/src/debug/java/com/yooshastan/wonheeproxy/RootlabReadinessActivity.java"
)
production_manifest = (repo / "app/src/main/AndroidManifest.xml").read_text()
assert debug_manifest.exists() and debug_activity.exists(), (
    "RootLab preview must be debug-only"
)
ET.parse(debug_manifest)
manifest = debug_manifest.read_text()
source = debug_activity.read_text()
assert 'RootlabReadinessActivity' in manifest
assert 'android:label="Wonhee Multi-Exit Readiness"' in manifest
assert 'RootlabReadinessActivity' not in production_manifest, (
    "Lab screen must never appear in official app"
)
assert "versionCode 108" in gradle and "versionName '0.15.61-connection-setup'" in gradle
assert "selector().withBuildType('debug')" in gradle
assert "output.versionCode.set(109)" in gradle
assert "output.versionName.set('0.15.62-rootlab-readiness')" in gradle
assert "applicationIdSuffix '.rootlab01562'" in gradle
assert "new ToolsInstaller(getApplicationContext(), shell)" in source
assert ".ensureToolsAvailable()" in source
assert "Private DNS" in source and "READ-ONLY" in source
assert 'wg show interfaces' in source and "wg setconf" not in source
assert "no networking changes" in source.lower()
for forbidden in (
    'shell.run(null, "ip ', 'shell.run(null, "iptables',
    '"ip -4 rule add', '"ip -6 rule add',
    '"ip -4 route add', '"ip -6 route add',
    '"ip link add', '"ip link del',
    '"iptables -A', '"ip6tables -A',
    '"wg-quick up', '"wg-quick down',
    "Settings.Global.putString",
    "RootIsolatedUidPolicyTransaction.start(",
    "RootIsolatedWireGuardTransaction.start(",
):
    assert forbidden not in source, f"RootLab inspection mutates networking: {forbidden}"
print("RootLab 0.15.62 preview separation and read-only checks PASS")
