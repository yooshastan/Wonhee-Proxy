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
for forbidden in ("RootShell", "RootDnsRelayRunner",
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
kernel_plan = (java / "RootMultiExitKernelPlan.java").read_text()
require('RootMultiExitKernelPlan.compile(plan)' in uid_readiness,
        "On-device draft readiness must check the proposed independent tables")
require('activationAllowed() { return false; }' in kernel_plan
        and 'private RootMultiExitKernelPlan()' in kernel_plan,
        "Multi-exit compiler must remain non-activating")
isolated_bootstrap = (java / "RootIsolatedWireGuardBootstrapPlan.java").read_text()
require('activationAllowed() { return false; }' in isolated_bootstrap
        and 'RootMultiTunnelPlan.validateIndependentInterfaceAddresses' in isolated_bootstrap
        and '"PEER_CONFIG", "", ""' in isolated_bootstrap,
        "Independent WireGuard bootstrap must be non-executing and keep secrets off shell")
require('RootIsolatedWireGuardBootstrapPlanTest.java' in
        (root / ".github/workflows/build.yml").read_text(),
        "Two-exit isolated link bootstrap tests must be executed by CI")
transaction = (java / "RootIsolatedWireGuardTransaction.java").read_text()
journal_codec = (java / "RootIsolatedWireGuardJournalCodec.java").read_text()
prefs_journal = (java / "RootIsolatedWireGuardPreferencesJournal.java").read_text()
root_kernel_adapter = (java / "RootIsolatedWireGuardKernelAdapter.java").read_text()
config_handoff = (java / "RootIsolatedWireGuardConfigHandoff.java").read_text()
kernel_listing = (java / "RootIsolatedWireGuardKernelListing.java").read_text()
require('interface SafetyGate' in root_kernel_adapter
        and 'proveIsolatedUnderlayDnsAndFailClosed' in root_kernel_adapter
        and 'createdIfindices' in root_kernel_adapter,
        "New kernel adapter must require external full protection proof and ifindex identity")
require('new ToolsInstaller(this.context, shell)' in root_kernel_adapter
        and 'tools.ensureToolsAvailable();' in root_kernel_adapter
        and root_kernel_adapter.index('tools.ensureToolsAvailable();')
            < root_kernel_adapter.index('wg --version')
        and 'tools.install()' not in root_kernel_adapter,
        "Android root PATH lacks wg: isolated adapter must extract app-bundled tools "
        "before probing binaries, without modifying system partitions")
require('RootIsolatedWireGuardTransaction.safeStep(step)' in root_kernel_adapter
        and 'RootIsolatedWireGuardConfigHandoff.apply(' in root_kernel_adapter,
        "Only prevalidated steps and secure peer-config handoff may be executed")
setconf_codec = (java / "RootIsolatedWireGuardSetconfCodec.java").read_text()
require('RootIsolatedWireGuardSetconfCodec.stripCanonicalQuick(' in config_handoff
        and 'wg setconf ' in config_handoff
        and '"wg-quick strip ' not in config_handoff
        and ' | wg setconf' not in config_handoff
        and ' /dev/stdin' not in config_handoff
        and 'wg-quick up' not in config_handoff
        and 'wg-quick down' not in config_handoff
        and "FileOutputStream" in config_handoff
        and "Arrays.fill(clear" in config_handoff,
        "Peer configuration must use strict app-generated wg setconf, never fragile shell pipes")
require('key.equals("Address")' in setconf_codec
        and 'key.equals("DNS")' in setconf_codec
        and 'key.equals("MTU")' in setconf_codec
        and 'key.equals("PrivateKey")' in setconf_codec
        and 'key.equals("PublicKey")' in setconf_codec
        and 'key.equals("AllowedIPs")' in setconf_codec
        and 'RootIsolatedWireGuardSetconfCodecTest.java' in
            (root / ".github/workflows/build.yml").read_text(),
        "The kernel peer serializer must strip DNS/addresses, preserve WG keys and run CI tests")
require('failurePhase' in transaction
        and 'failureCode' in transaction
        and 'class SafeFailure extends Exception' in transaction,
        "Transaction must report only sanitized connection failure codes")
require('RootIsolatedWireGuardKernelListingTest.java' in
        (root / ".github/workflows/build.yml").read_text()
        and 'interfaceKind' in kernel_listing,
        "Android CI must exercise exact-owned link/route readback")
kernel_session = (java / "RootMultiKernelSession.java").read_text()
uid_policy_tx = (java / "RootIsolatedUidPolicyTransaction.java").read_text()
uid_policy_codec = (java / "RootIsolatedUidPolicyJournalCodec.java").read_text()
uid_policy_prefs = (java / "RootIsolatedUidPolicyPreferencesJournal.java").read_text()
uid_policy_listing = (java / "RootIsolatedUidPolicyListing.java").read_text()
uid_policy_kernel_adapter = (java / "RootIsolatedUidPolicyKernelAdapter.java").read_text()
require('kernel.requireFailClosedPreflight();' in uid_policy_tx
        and 'journal.recordIntent(step);' in uid_policy_tx
        and uid_policy_tx.index('journal.recordIntent(step);')
            < uid_policy_tx.index('kernel.apply(step);')
        and 'Presence.FOREIGN_OR_CHANGED' in uid_policy_tx
        and 'RootIsolatedUidOnlyPolicyPlan.Step' in uid_policy_tx,
        "UID-only route mutation must require preflight, durable intent and ownership readback")
require('new RootIsolatedUidPolicyJournalCodec(plan)' in uid_policy_prefs
        and 'MODE_PRIVATE' in uid_policy_prefs
        and '.commit()' in uid_policy_prefs
        and 'pendingOrUnknown(Context context)' in uid_policy_prefs,
        "UID policy journal must be app-private, synchronous and block legacy lifecycles")
require('private final String fingerprint;' in uid_policy_codec
        and 'RootIsolatedUidPolicyTransaction.safeStep(step)' in uid_policy_codec
        and 'RootIsolatedUidPolicyListing' in uid_policy_listing,
        "Rule journal fingerprint and exact kernel rule readback are mandatory")
for required in ('RootIsolatedUidPolicyTransactionTest.java',
                 'RootIsolatedUidPolicyJournalCodecTest.java',
                 'RootIsolatedUidPolicyListingTest.java'):
    require(required in (root / ".github/workflows/build.yml").read_text(),
            "UID policy rollback and ownership tests must run: " + required)
require('interface SafetyGate' in uid_policy_kernel_adapter
        and 'proveConnectedExitsDnsAndFailClosed' in uid_policy_kernel_adapter
        and 'RootIsolatedUidPolicyTransaction.safeStep(step)' in uid_policy_kernel_adapter
        and 'RootIsolatedUidPolicyListing.selector(' in uid_policy_kernel_adapter
        and 'RootIsolatedUidPolicyListing.terminalDefault(' in uid_policy_kernel_adapter,
        "Root UID adapter requires external device proof and exact kernel readback")
require('new RootIsolatedUidPolicyKernelAdapter(' not in kernel_session,
        "Unverified UID policy kernel executor must not connect to production Start")
require('RootIsolatedUidPolicyTransaction.start(' not in kernel_session
        and 'new RootIsolatedUidPolicyPreferencesJournal(' not in kernel_session,
        "UID routing must stay disabled until real on-device DNS/fail-closed proof")
for forbidden in ('new RootShell(', 'shell.run(', 'ProcessBuilder(',
                  'Runtime.getRuntime().exec(', 'iptables -t mangle -A'):
    require(forbidden not in uid_policy_tx
            and forbidden not in uid_policy_codec
            and forbidden not in uid_policy_prefs
            and forbidden not in uid_policy_listing,
            "UID policy transaction model must not execute root commands: " + forbidden)
require('new RootIsolatedWireGuardKernelAdapter(' not in kernel_session
        and 'RootIsolatedWireGuardTransaction.start(' not in kernel_session,
        "Kernel adapter may NOT be integrated into live Start without device DNS/fail-closed proof")

require('kernel.requireActivationPreflight();' in transaction
        and 'journal.beforeMutation(step);' in transaction
        and transaction.index('journal.beforeMutation(step);')
            < transaction.index('kernel.apply(step);')
        and 'Presence.FOREIGN_OR_CHANGED' in transaction
        and 'activationAllowed()' not in transaction,
        "Isolated WireGuard kernel transaction requires preflight + write-ahead intent")
require('boolean activationAllowed() { return false; }' in isolated_bootstrap,
        "Isolated bootstrap planner may never authorize its own activation")
require('private final String fingerprint;' in journal_codec
        and 'STEP' not in journal_codec
        and 'step.install' in journal_codec
        and 'step.inverse' in journal_codec
        and 'step.kind' in journal_codec,
        "Durable journal fingerprint must bind the complete planned step identity")
require('MODE_PRIVATE' in prefs_journal
        and '.commit()' in prefs_journal
        and 'codec.decode(' in prefs_journal
        and 'new RootIsolatedWireGuardJournalCodec(plan)' in prefs_journal,
        "Persistent journal must use exact-plan-validated synchronous app-private writes")
require('RootIsolatedWireGuardTransactionTest.java' in
        (root / ".github/workflows/build.yml").read_text()
        and 'RootIsolatedWireGuardJournalCodecTest.java' in
        (root / ".github/workflows/build.yml").read_text(),
        "Start/rollback fault injection and crash journal tests must run in CI")
for forbidden in ('new RootShell(', 'shell.run(', 'Runtime.getRuntime().exec(',
                  'ProcessBuilder(', 'wg-quick up', 'backend.setState('):
    require(forbidden not in transaction and forbidden not in journal_codec
            and forbidden not in prefs_journal,
            "Isolated bootstrap recovery must have no live root adapter yet: " + forbidden)
require('RootIsolatedWireGuardBootstrapPlan' in uid_readiness
        and 'compile(effectiveRoutes, plan).summary()' in uid_readiness,
        "Home App Routing readiness must report isolated two-exit bootstrap blockers")
for forbidden in ('new RootShell(', 'shell.run(', 'ProcessBuilder(',
                  'Runtime.getRuntime().exec(', 'backend.setState(',
                  'wg-quick up', 'ip -4 rule add', 'ip -6 rule add'):
    require(forbidden not in isolated_bootstrap,
            "Independent bootstrap must never mutate live networking: " + forbidden)
netfilter_help = (java / "RootNetfilterHelpCapabilities.java").read_text()
require('activationAllowed() { return false; }' in netfilter_help,
        "Legacy netfilter help cannot activate live packet classification")
require('RootNetfilterHelpCapabilitiesTest.java' in
        (root / ".github/workflows/build.yml").read_text(),
        "Pixel 8a legacy netfilter help tests must run in CI")
kernel_inventory = (java / "RootNetfilterKernelInventory.java").read_text()
require('activationAllowed() { return false; }' in kernel_inventory
        and 'connmark_mangle_OUTPUT' in kernel_inventory
        and 'RootNetfilterKernelInventoryTest.java' in
        (root / ".github/workflows/build.yml").read_text(),
        "Registered kernel modules and foreign OUTPUT chains cannot activate routing")
mark_audit = (java / "RootAndroidMarkCollisionAudit.java").read_text()
require('candidateVerifiedFree(long mask) { return false; }' in mark_audit
        and 'activationAllowed() { return false; }' in mark_audit,
        "Observed Android netd masks cannot certify new fwmark ownership")
require('RootAndroidMarkCollisionAuditTest.java' in
        (root / ".github/workflows/build.yml").read_text(),
        "Device mark-mask collision regressions must run in CI")
for unsafe in ('new RootShell(', 'shell.run(', 'ProcessBuilder(',
               'Runtime.getRuntime().exec(', 'iptables -t mangle -A',
               'ip rule add'):
    require(unsafe not in mark_audit,
            "Mark-mask interpreter must remain non-executing: " + unsafe)
for dangerous in ('new RootShell(', 'shell.run(', 'ProcessBuilder(',
                  'Runtime.getRuntime().exec(', 'iptables -t mangle -A',
                  'iptables -t mangle -F'):
    require(dangerous not in kernel_inventory,
            "Kernel inventory must remain pure/read-only: " + dangerous)
for dangerous in ('new RootShell(', 'shell.run(', 'startManagedStack(',
                  'enableRootDns(', 'Runtime.getRuntime().exec(', 'ProcessBuilder('):
    require(dangerous not in kernel_plan,
            "Multi-exit model must never execute planned commands: " + dangerous)
for source in (protocol_ui, protocol_model, uid_plan, uid_readiness):
    for dangerous in ('new RootShell(', 'shell.run(', 'iptables -w',
                      'ip rule add', 'ip rule del', 'enableRootDns(',
                      'startManagedStack('):
        require(dangerous not in source,
                "Dry-run protocol planner must not alter networking: " + dangerous)

global_model = (java / "RootCategoryProtocolRule.java").read_text()
home_selection = (java / "RootTunnelStartSelection.java").read_text()
require('button(editor, "Save global rule · preview"' in app,
        "Global Protocols tab must support explicit saving")
require('RootCategoryProtocolRule.Rule' in app
        and 'showGlobalProtocols()' in app
        and 'switchTab(2)' in app,
        "Protocols & Ports must be visible and category-targeted")
require('drafts.putCategoryProtocolPresetAndTarget' in app
        and 'drafts.removeCategoryProtocolRule' in app,
        "Global selectors need atomic category + tunnel saving and removal")
require('prefs.edit().putString(CATEGORY_PROTOCOLS' in draft,
        "Global port-to-category overrides must persist only as local drafts")
require('RootCategoryProtocolRule.validateAndSort' in uid_plan
        and 'categoryExits.get(global.category)' in uid_plan,
        "Global port rules must resolve a category and never silently fall back")
require('RootMultiKernelSession.reviewMultiStartSelection' in dashboard
        and 'reviewed.parked' in dashboard
        and 'new ArrayList<>(active)' in dashboard,
        "Home must start only explicit primary and compatible private tunnels")
require('RootTunnelSelectionAdvisor.review(activeEntries)' in home_selection,
        "Multi-select may not bypass existing route conflict validator")
require('activationAllowed() { return false; }' in uid_plan,
        "No draft policy may activate live per-app/transport enforcement")
for source in (global_model, home_selection):
    for dangerous in ('new RootShell(', 'shell.run(', 'ip rule add',
                      'iptables -w', 'startManagedStack(', 'enableRootDns('):
        require(dangerous not in source,
                "Selection and port models must never mutate the kernel: " + dangerous)

presets = (java / "RootCommonProtocolPresets.java").read_text()
root_session = (java / "RootMultiKernelSession.java").read_text()
tunnel_editor = (java / "TunnelProfileSettingsActivity.java").read_text()
require('RootCommonProtocolPresets.labels()' in app
        and 'RootCommonProtocolPresets.get(' in app,
        "Global protocol editor must offer readable service presets")
require('drafts.putCategoryProtocolPresetAndTarget(newRules' in app
        and 'Existing port rule(s)' not in app,
        "Global port preset and chosen target must save in one atomic batch")
require('synchronized void putCategoryProtocolPreset(' in draft
        and 'saveCategoryProtocolRules(RootCategoryProtocolRule.validateAndSort(merged))'
            in draft,
        "Preset persistence must have validated atomic replacement semantics")
require('GPS' in app and 'Wi-Fi/cell data' in app,
        "Location must not be misrepresented as a universal network port")
require('static String effectiveRouteSummary(' in root_session
        and 'RootMultiKernelSession.effectiveRouteSummary(profile)' in dashboard
        and 'RootMultiKernelSession.effectiveRouteSummary(original)' in tunnel_editor,
        "Imported WireGuard profiles must truthfully disclose effective full exits")
require('ROOT_HOME_LAST_RESULT_KEY' in dashboard
        and 'rootHomeLastProblem = ui.getString(ROOT_HOME_LAST_RESULT_KEY' in dashboard,
        "Sanitized connection failure summary must survive restarting Home")
for source in (presets,):
    for dangerous in ('new RootShell(', 'shell.run(', 'iptables', 'ip rule add',
                      'startManagedStack(', 'enableRootDns('):
        require(dangerous not in source,
                "Protocol presets are metadata and cannot install rules: " + dangerous)

require('static boolean isFullInternetExit(' in root_session
        and 'RootMultiKernelSession.isFullInternetExit(profile)' in app,
        "Global TCP/UDP rules must refuse non-Internet WireGuard destinations")
require('private Spinner chooseProtocolTarget(' in app
        and 'private SecureTunnelProfileStore.Profile verifiedProtocolTarget(' in app,
        "Global protocol setup must choose category and actual tunnel together")
require('putString(CATEGORY_PROTOCOLS, encodedRules)' in draft
        and 'putString(TUNNELS, encodedTargets).commit()' in draft,
        "Category protocol and target must commit as one private transaction")
require('secondaryButton(hero, "Check setup · no connection changes"' in dashboard
        and 'session.preflightManagedStart(active,' in dashboard,
        "Root Home must expose a read-only check of the actual active subset")
readiness_guide = (java / "RootStartReadinessGuide.java").read_text()
require('No connection or routing change was requested' in readiness_guide
        and 'independent H.2a' in readiness_guide,
        "Root preflight guidance must preserve safe-stop and no-change contract")
for source in (readiness_guide,):
    for dangerous in ('new RootShell(', 'shell.run(', 'iptables',
                      'ip rule add', 'startManagedStack(', 'enableRootDns('):
        require(dangerous not in source,
                "Read-only root setup advice must never mutate networking")

print("PASS: eight app categories, scoped app discovery, private draft persistence, "
      "UI visibility and no route/DNS/kernel enforcement from planner")
