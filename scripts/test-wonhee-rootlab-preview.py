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
assert 'RootlabTwoPeerActivity' in manifest
assert 'android:name=".RootlabApplication"' in manifest
assert 'tools:replace="android:name"' in manifest
lab_app = (repo / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlabApplication.java").read_text()
assert 'RootMultiRecoveryScheduler' not in lab_app
assert 'GoBackend.setAlwaysOnCallback' not in lab_app
for component in (
    'com.wireguard.android.backend.GoBackend$VpnService',
    '.RootMultiRecoveryJobService',
    '.RootMultiRecoveryBootReceiver',
    '.RootMultiTrafficNotificationService',
    '.WonheeQuickSettingsTile',
):
    assert component in manifest, f"Debug package must explicitly remove {component}"
assert manifest.count('tools:node="remove"') >= 7

assert 'android:label="Wonhee Two-Peer Check"' in manifest
assert 'RootlabTwoPeerActivity' not in production_manifest
two_peer = (repo / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlabTwoPeerActivity.java").read_text()
session = (repo / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlabTwoPeerSession.java").read_text()
gate = (repo / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlabTwoPeerSafetyGate.java").read_text()
link_plan = (repo / "app/src/main/java/com/yooshastan/wonheeproxy/RootIsolatedTwoPeerLinkPlan.java").read_text()
assert 'ACTION_OPEN_DOCUMENT' in two_peer and 'ACTION_CREATE_DOCUMENT' in two_peer
assert 'RootIsolatedWireGuardTransaction.start(' in session
assert 'RootIsolatedWireGuardTransaction.recover(' in session
assert 'new RootIsolatedWireGuardPreferencesJournal(' in session
assert 'new SecureTunnelProfileStore(app).save(' in session
assert 'RootIsolatedTwoPeerLinkPlan.compile(routes)' in session
assert 'RootlabTwoPeerSafetyGate(app, shell)' in session
assert 'Settings.Global.getString' in gate
assert '"off".equals(privateDns)' in gate
assert '5100[0-7]' in gate
assert 'RootIsolatedWireGuardPreferencesJournal.pendingOrUnknown' in gate
assert '"ip rule add' not in link_plan and '"iptables ' not in link_plan
assert 'connmark' not in session and 'set-mark' not in session
assert 'RootIsolatedUidPolicyTransaction.start(' not in two_peer + session
assert 'does NOT route phone apps' in two_peer
assert 'Check both profiles (no root changes)' in two_peer
assert 'session::profileReadiness' in two_peer
assert 'RootTwoPeerProfileReadiness.assess(routes, true)' in session
assert 'catch (ProfileRejected invalid)' in session
assert 'invalid.reason.name()' in session
assert 'No kernel change has been attempted by this check.' in session
assert 'record("Two-peer Start refused at PROFILE_CHECK:' in session
assert 'NO JOURNALED TUNNEL STAGES' in session
profile_check = (repo / "app/src/main/java/com/yooshastan/wonheeproxy/RootTwoPeerProfileReadiness.java").read_text()
assert 'OVERLAPPING_INTERFACE_ADDRESSES' in profile_check
assert 'INTERFACE_HOST_PREFIX_REQUIRED' in profile_check
assert 'IPV4_DEFAULT_ALLOWEDIPS_REQUIRED' in profile_check
assert 'Do not' in profile_check and 'No root networking was changed' in profile_check


assert 'android:label="Wonhee Multi-Exit Readiness"' in manifest
assert 'android:name=".WonheeDashboardPreviewActivity"' in manifest
assert 'android:enabled="false"' in manifest, (
    "The diagnostic APK cannot expose the normal Start dashboard"
)
assert 'RootlabReadinessActivity' not in production_manifest, (
    "Lab screen must never appear in official app"
)
assert "versionCode 108" in gradle and "versionName '0.15.61-connection-setup'" in gradle
assert "selector().withBuildType('debug')" in gradle
assert "output.versionCode.set(111)" in gradle
assert "output.versionName.set('0.15.62-two-peer-profile-check')" in gradle
assert "applicationIdSuffix '.rootlab01562peersfix1'" in gradle
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
