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

assert 'android:label="Wonhee Two Exits + Home Lab"' in manifest
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
assert 'RootIsolatedThreePeerLinkPlan.compile(routes, homeRoute)' in session
assert 'RootTwoExitHomeRoutingPreview.permitsHomeTarget(' in session
assert 'ip -4 route show table 51002' in session
assert 'RootIsolatedWireGuardKernelListing.privateRoute(' in session
assert 'RootIsolatedWireGuardPreferencesJournal.pendingOrUnknown' in session
assert 'new SecureTunnelProfileStore(app).delete(HOME)' in session
assert 'removeHomeProfile()' in session
assert 'Import optional Home WireGuard .conf' in two_peer
assert 'Probe Home host over Home interface' in two_peer
assert 'Probe Exit A TCP/HTTPS' in two_peer
assert 'Probe Exit B TCP/HTTPS' in two_peer
assert 'Probe Home Navidrome TCP/HTTP' in two_peer
assert 'session.probeTcp(slot, target)' in two_peer
assert 'Moka → Home routing readiness (read-only)' in two_peer
assert 'Inspect Moka Home firewall (read-only)' in two_peer
assert 'session::auditMokaHomeFirewall' in two_peer
assert 'scroll.setFitsSystemWindows(true)' in two_peer
assert 'String auditMokaHomeFirewall()' in session
assert 'String stageDetachedMokaFirewall()' in session
assert 'String attachMokaIpv6Hook()' in session
assert 'String attachMokaIpv4Hook()' in session
assert 'String stageMokaHomeFallback()' in session
assert 'String activateMokaHomeUidRoute()' in session
assert 'String diagnoseMokaBrowserPath()' in session
brave = (repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabBraveHomePilot.java').read_text()
brave_plan = (repo / 'app/src/main/java/com/yooshastan/wonheeproxy/RootBraveHomePilotPlan.java').read_text()
assert 'String activateBraveHomePilot()' in session
assert 'String auditBraveHomePilot()' in session
assert 'session::activateBraveHomePilot' in two_peer
assert 'session::auditBraveHomePilot' in two_peer
assert 'String braveStatus = new RootlabBraveHomePilot(app).recover();' in session
assert session.index('RootlabBraveHomePilot(app).recover()') < session.index('RootlabMokaHomeUidSelector(app).recover()')
assert 'RootlabBraveHomePilot.pendingOrUnknown(app)' in session
assert 'RootlabBraveHomePilot.pendingOrUnknown(app)' in gate
assert 'RootlabBraveHomePilot.pendingOrUnknown(app)' in (
    repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabTwoPeerSafetyGate.java'
).read_text()
assert 'RootBraveHomePilotPlan.exactSelector(' in brave
assert 'RootBraveHomePilotPlan.chainIsExactPrefix(' in brave
assert 'RootlabMokaHomeTerminalRoute(app).exactStaged(' in brave
assert 'RootlabMokaIpv6OutputTest(app)' in brave
assert 'RootlabMokaIpv4OutputTest(app)' in brave
assert 'com.brave.browser_nightly' in brave
assert 'ip6tables -w -t filter -I OUTPUT 1' in brave
assert 'iptables -w -t filter -I OUTPUT 1' in brave
assert 'persist(plan);' in brave
assert brave.index('persist(plan);') < brave.index('run(shell, "ip6tables')
assert brave.index('run(shell, plan.selector)') > brave.index('run(shell, "iptables -w -t filter -I OUTPUT 1')
assert 'RootBraveHomeTargetCounterEvidence.firstRule(' in brave
assert 'targetAttemptCounter(shell, plan)' in brave
assert 'run(shell, "iptables -w -t filter " + plan.count4);' in brave
assert 'RootBraveHomePilotPlan.chainFullyPopulated(' in brave
assert 'RootBraveHomeTargetCounterEvidenceTest.java' in (
    repo / '.github/workflows/build.yml'
).read_text()
assert 'RootBraveHomePilotPlanTest.java' in (
    repo / '.github/workflows/build.yml').read_text()
assert '12699' in brave_plan and 'WN_BRAVE_HOME4' in brave_plan

assert 'session::diagnoseMokaBrowserPath' in two_peer
assert 'Diagnose Moka + browser Home path' in two_peer
app_path = (repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabMokaConnectionPathDiagnostics.java').read_text()
selector = (repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabMokaHomeUidSelector.java').read_text()
assert 'RootMokaConnectionPathEvidence.selectorState(' in app_path
assert 'RootMokaConnectionPathEvidence.syntheticRoute(' in app_path
assert 'packageUid(shell, MOKA)' in app_path
assert 'packageUid(shell, CHROME)' in app_path
assert 'packageUid(shell, BRAVE)' in app_path
assert 'RootMokaIpv6CounterParser.target(' in app_path
assert 'ss -tnpe' in app_path
assert 'RootHomeTcpSocketEvidence.summarize(' in app_path
assert 'RootHomeTcpSocketEvidenceTest.java' in (repo / '.github/workflows/build.yml').read_text()
for forbidden in ('shell.run(null,', 'ip -4 rule add', 'ip -4 rule del',
                  'ip -4 route add', 'iptables -A', 'iptables -I',
                  'ip6tables -I', 'curl', 'tcpdump', 'logcat -d'):
    assert forbidden not in app_path, f'Unexpected diagnostic operation: {forbidden}'
for outcome in ('ACTIVE_VERIFIED', 'ROLLED_BACK', 'CLEAN_STOPPED',
                'RECOVERY_PAUSED'):
    assert outcome in selector
assert 'noteRefusal(code)' in selector and '"CELLULAR_REQUIRED"' in selector
assert 'RootMokaConnectionPathEvidenceTest.java' in (
    repo / '.github/workflows/build.yml').read_text()

assert 'String auditMokaHomeUidRoute()' in session
assert 'session::activateMokaHomeUidRoute' in two_peer
assert 'session::auditMokaHomeUidRoute' in two_peer
assert 'Route Moka to Home' in two_peer
uid_select = (repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabMokaHomeUidSelector.java').read_text()
assert 'commitIntent(plan);' in uid_select
assert uid_select.index('commitIntent(plan);') < uid_select.index('shell.run(null, plan.candidateSelector)')
assert 'requireFirstOutputHook(shell, uid, 4)' in uid_select
assert 'requireFirstOutputHook(shell, uid, 6)' in uid_select
assert 'new RootlabMokaHomeTerminalRoute(app)' in uid_select
assert 'exactStaged(uid, device)' in uid_select
assert 'requireCellularPhysical(app)' in uid_select
assert 'RootMokaHomeUidRuleEvidence.inspect' in uid_select
assert 'route get 10.0.0.169 uid ' in uid_select
assert 'String recover() throws Exception' in uid_select
assert 'candidateSelector.replace(' in uid_select
assert 'new RootlabMokaHomeUidSelector(app).recover()' in session
assert session.index('new RootlabMokaHomeUidSelector(app).recover()') < session.index('new RootlabMokaIpv4OutputTest(app).recover()')
assert 'RootlabMokaHomeUidSelector.pendingOrUnknown(app)' in session
assert 'RootlabMokaHomeUidSelector.pendingOrUnknown(app)' in (
    repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabTwoPeerSafetyGate.java'
).read_text()
assert 'RootMokaHomeUidRuleEvidenceTest.java' in (repo / '.github/workflows/build.yml').read_text()
assert 'RootIsolatedUidPolicyTransaction.start(' not in session

assert 'String auditMokaHomeFallback()' in session
assert 'session::stageMokaHomeFallback' in two_peer
assert 'session::auditMokaHomeFallback' in two_peer
assert 'Stage Home /32 fallback blocker' in two_peer
home_terminal = (repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabMokaHomeTerminalRoute.java').read_text()
assert 'commitIntent(plan);' in home_terminal
assert home_terminal.index('commitIntent(plan);') < home_terminal.index('shell.run(null, plan.candidateTerminal)')
assert 'new RootlabMokaIpv4OutputTest(app).exactAttached(uid, device)' in home_terminal
assert 'new RootlabMokaIpv6OutputTest(app).exactAttached(uid, device)' in home_terminal
assert 'requireNoUidSelector(shell)' in home_terminal
assert 'plan.candidateTerminal.replace(' in home_terminal
assert 'boolean activationAllowed() { return false; }' in (repo / 'app/src/main/java/com/yooshastan/wonheeproxy/RootMokaHomeRouteSafetyPlan.java').read_text()
assert 'RootMokaHomeTerminalRouteEvidenceTest.java' in (repo / '.github/workflows/build.yml').read_text()
assert 'new RootlabMokaHomeTerminalRoute(app).recover()' in session
assert session.index('new RootlabMokaIpv4OutputTest(app).recover()') < session.index('new RootlabMokaHomeTerminalRoute(app).recover()')
assert session.index('new RootlabMokaHomeTerminalRoute(app).recover()') < session.index('RootIsolatedWireGuardTransaction.recover(')
assert 'RootlabMokaHomeTerminalRoute.pendingOrUnknown(app)' in session
assert 'RootlabMokaHomeTerminalRoute.pendingOrUnknown(app)' in (
    repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabTwoPeerSafetyGate.java'
).read_text()
assert 'RootIsolatedUidPolicyTransaction.start(' not in session

assert 'String readMokaIpv4Counters()' in session
assert 'session::attachMokaIpv4Hook' in two_peer
assert 'session::readMokaIpv4Counters' in two_peer
assert 'Attach Moka IPv4 OUTPUT guard' in two_peer
ipv4_hook = (repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabMokaIpv4OutputTest.java').read_text()
assert 'exactAttached(uid, device)' in ipv4_hook
assert 'exactStagingPresentWithVerifiedIpv6Hook(uid, device)' in ipv4_hook
assert 'exactStagingPresentWithVerifiedDualHooks(uid, device)' in ipv4_hook
assert 'recordIntent(plan);' in ipv4_hook
assert ipv4_hook.index('recordIntent(plan);') < ipv4_hook.index('shell.run(null, step.install)')
assert 'canonicalHook(plan).inverse' in ipv4_hook
assert 'RootMokaIpv6CounterParser.target(' in ipv4_hook
assert 'String recover() throws Exception' in ipv4_hook
assert 'exactStagingPresentWithVerifiedDualHooks' in (repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabDetachedMokaFirewall.java').read_text()
assert 'new RootlabMokaIpv4OutputTest(app).recover()' in session
assert session.index('new RootlabMokaIpv4OutputTest(app).recover()') < session.index('new RootlabMokaIpv6OutputTest(app).recover()')
assert session.index('new RootlabMokaIpv6OutputTest(app).recover()') < session.index('new RootlabDetachedMokaFirewall(app).recover()')
assert 'RootlabMokaIpv4OutputTest.pendingOrUnknown(app)' in session
assert 'RootlabMokaIpv4OutputTest.pendingOrUnknown(app)' in (
    repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabTwoPeerSafetyGate.java'
).read_text()
assert 'RootIsolatedUidPolicyTransaction.start(' not in session

assert 'String readMokaIpv6Counters()' in session
assert 'String previewMokaIpv4Order()' in session
assert 'String auditMokaHomeRouteSelection()' in session
assert 'session::auditMokaHomeRouteSelection' in two_peer
assert 'Audit cellular Moka' in two_peer
assert 'ip -4 route get 10.0.0.169 uid ' in session
assert 'ip -4 route show table 51002' in session
assert 'ACTIVATION LOCKED: synthetic route get' in session
route_plan = (repo / 'app/src/main/java/com/yooshastan/wonheeproxy/RootMokaHomeRouteSafetyPlan.java').read_text()
assert 'boolean activationAllowed() { return false; }' in route_plan
assert 'REFUSE_CELLULAR_FALLTHROUGH' in route_plan
assert 'RootMokaHomeRouteSafetyPlanTest.java' in (repo / '.github/workflows/build.yml').read_text()
assert 'session::readMokaIpv6Counters' in two_peer
assert 'session::previewMokaIpv4Order' in two_peer
assert 'Read Moka IPv6 REJECT counters' in two_peer
assert 'Audit proposed Moka IPv4 rule order' in two_peer
assert 'RootMokaIpv6CounterParser.target(' in (
    repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabMokaIpv6OutputTest.java'
).read_text()
parser = (repo / 'app/src/main/java/com/yooshastan/wonheeproxy/RootMokaIpv6CounterParser.java').read_text()
assert 'static Counts target(' in parser and 'static long delta(' in parser
assert 'RootMokaIpv6CounterParserTest.java' in (repo / '.github/workflows/build.yml').read_text()
assert 'shell.run(null, "ip6tables -w -t filter -Z' not in (
    repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabMokaIpv6OutputTest.java'
).read_text()

assert 'session::attachMokaIpv6Hook' in two_peer
assert 'Attach Moka IPv6 OUTPUT guard' in two_peer
hook = (repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabMokaIpv6OutputTest.java').read_text()
assert 'RootMokaHomeFirewallPilotPlan.compile(uid, device)' in hook
assert 'exactStagingPresent(uid, device)' in hook
assert 'intent(plan);' in hook
assert 'exactReferences(shell, plan)' in hook
assert 'hook(plan).inverse' in hook
assert 'String recover() throws Exception' in hook
detached = (repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabDetachedMokaFirewall.java').read_text()
assert 'exactStagingPresentWithVerifiedIpv6Hook(' in hook
assert 'exactStagingPresentWithVerifiedDualHooks(' in hook
assert 'exactStagingPresent(plan.uid, plan.homeDevice)' not in hook
assert 'requireDetached(shell, 4)' in detached
assert 'verifyChain(shell, plan, 4, 5)' in detached
assert 'verifyChain(shell, plan, 6, 5)' in detached
assert 'references != 1' in detached
assert 'new RootlabMokaIpv6OutputTest(app).recover()' in session
assert session.index('new RootlabMokaIpv6OutputTest(app).recover()') < session.index('new RootlabDetachedMokaFirewall(app).recover()')
assert 'RootlabMokaIpv6OutputTest.pendingOrUnknown(app)' in session
assert 'RootlabMokaIpv6OutputTest.pendingOrUnknown(app)' in (
    repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabTwoPeerSafetyGate.java'
).read_text()

assert 'session::stageDetachedMokaFirewall' in two_peer
assert 'Stage detached Moka firewall chains' in two_peer
assert 'RootlabDetachedMokaFirewall.pendingOrUnknown(app)' in session
detached = (repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabDetachedMokaFirewall.java').read_text()
assert 'No Android app traffic is routed or filtered' in detached
assert 'journal' in detached.lower() and 'persist(plan, n + 1)' in detached
assert 'if ("OWNER_ANCHOR".equals(step.kind)) continue' in detached
assert 'requireDetached(shell, 4)' in detached and 'requireDetached(shell, 6)' in detached
assert 'verifyPrefix(shell, plan, n + 1)' in detached
assert 'new RootlabDetachedMokaFirewall(app).recover()' in session
assert 'new RootlabDetachedMokaFirewall(app).stage(uid, device)' in session
assert 'RootlabDetachedMokaFirewall.pendingOrUnknown(app)' in (
    repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabTwoPeerSafetyGate.java'
).read_text()
assert '" -I OUTPUT' not in detached and '" -A OUTPUT' not in detached

assert 'RootMokaHomeFirewallPilotTransaction.validate(plan)' in session
assert 'iptables' in session and 'ip6tables' in session
assert 'No firewall/routing/DNS changes.' in session
assert 'RootMokaHomeFirewallPilotTransactionTest.java' in (repo / '.github/workflows/build.yml').read_text()
assert 'session::previewMokaHomeRouting' in two_peer
assert 'String previewMokaHomeRouting()' in session
assert 'RootMokaHomePolicySafetyCase.currentLabGate(' in session
assert 'FAIL-CLOSED POLICY GATE:' in session
assert 'RootMokaHomePolicySafetyCaseTest.java' in (repo / '.github/workflows/build.yml').read_text()
assert 'RootMokaHomePolicySafetyCaseTest.java' in (repo / '.github/workflows/build.yml').read_text()
assert 'pm list packages -U' in session
assert 'RootIsolatedUidPolicyPreferencesJournal.pendingOrUnknown(app)' in session
assert 'ACTIVATION LOCKED:' in session
assert 'RootIsolatedUidPolicyTransaction.start(' not in session
assert 'String probeTcp(String slot, String target)' in session
assert 'RootTcpProbeTarget.parse(target)' in session
assert 'command -v curl >/dev/null' in session
assert '--interface ' in session and '--connect-timeout 3' in session
assert "--write-out '%{http_code}\\\\n'" in session, (
    "curl must produce line-terminated status for persistent RootShell.run readLine"
)
assert "No TCP connection attempted." in session
assert 'RootIsolatedWireGuardKernelListing.privateRoute(' in session
assert 'RootIsolatedWireGuardPreferencesJournal(app, pair.plan)' in session
assert 'RootIsolatedUidPolicyTransaction.start(' not in session
assert 'Safe Stop ALL selected test links' in two_peer
third_link = (repo / "app/src/main/java/com/yooshastan/wonheeproxy/RootIsolatedThreePeerLinkPlan.java").read_text()
assert '"PRIVATE_ROUTE"' in third_link and 'HOME_TABLE' in third_link
assert 'new RootIsolatedWireGuardBootstrapPlan.Plan(' in third_link
assert '"ip rule add' not in third_link
assert '"iptables' not in third_link
assert 'RootIsolatedThreePeerLinkPlanTest.java' in (
    repo / ".github/workflows/build.yml").read_text()

assert 'RootlabTwoPeerSafetyGate(app, shell)' in session
assert 'Settings.Global.getString' in gate
assert '"off".equals(privateDns)' in gate
assert '5100[0-7]' in gate
assert 'RootIsolatedWireGuardPreferencesJournal.pendingOrUnknown' in gate
assert '"ip rule add' not in link_plan and '"iptables ' not in link_plan
assert 'connmark' not in session and 'set-mark' not in session
assert 'RootIsolatedUidPolicyTransaction.start(' not in two_peer + session
assert 'does NOT route phone apps' in two_peer
assert 'Check selected profiles (no root changes)' in two_peer
assert 'session::profileReadiness' in two_peer
assert 'RootTwoPeerProfileReadiness.assess(' in session
assert 'routes, differentEndpoints, differentClientKeys' in session
assert 'getEndpoint().map(Object::toString)' in session
assert 'getKeyPair()' in session
assert 'RootTwoPeerProfileReadiness.Reason.SAME_SERVER_PEER' not in session
assert 'catch (ProfileRejected invalid)' in session
assert 'invalid.reason.name()' in session
assert 'No kernel change has been attempted by this check.' in session
assert 'record("Two-peer Start refused at PROFILE_CHECK:' in session
assert 'NO JOURNALED TUNNEL STAGES' in session
assert 'PEER_SETCONF_FORMAT_UNSUPPORTED' in session
assert 'parsed.toWgQuickString()' in session
assert 'RootIsolatedWireGuardSetconfCodec.stripCanonicalQuick(' in session
assert 'PROBE SKIPPED: selected peer links are not active' in session
assert 'No probe packets were sent.' in session

assert 'result.failurePhase' in session and 'result.failureCode' in session
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
assert "output.versionCode.set(134)" in gradle
assert "output.versionName.set('0.15.80-native-socket-protection-lifecycle')" in gradle
assert "applicationIdSuffix '.rootlab01562triple1native080'" in gradle
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
print("RootLab debug-only preview separation and read-only checks PASS")

# Separate transport ownership must be recovered before the older UID/chain stages.
transport = (repo / 'app/src/debug/java/com/yooshastan/wonheeproxy/RootlabHomeTransportTrial.java').read_text()
assert 'RootlabHomeTransportTrial(app).recover()' in session
assert session.index('RootlabHomeTransportTrial(app).recover()') < session.index('RootlabMokaHomeUidSelector(app).recover()')
assert 'RootlabHomeTransportTrial.pendingOrUnknown(app)' in gate
assert 'session::activateHomeTransportTrial' in two_peer
assert 'exactActiveForTransport' in transport and 'plan.remove()' in transport
