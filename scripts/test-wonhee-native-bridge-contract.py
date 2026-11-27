#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
bridge = (root / "native/cmd/wonhee-jni/jni_bridge.c").read_text()
go = (root / "native/cmd/wonhee-jni/main.go").read_text()
java = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlessNativeBridge.java").read_text()
service = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlessNativeTransportService.java").read_text()
tun_service = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlessNativeTunPumpService.java").read_text()
router = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlessTunTestPacketRouter.java").read_text()
rootlab = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlabTwoPeerActivity.java").read_text()
manifest = (root / "app/src/debug/AndroidManifest.xml").read_text()
gradle = (root / "app/build.gradle").read_text()

assert 'GetMethodID(env, cls, "protect", "(I)Z")' in bridge
assert 'CallBooleanMethod(env, g_service, method, (jint)fd)' in bridge
assert 'wn_protect_socket(C.int(fd)) == 1' in go
assert 'dualwg.NewProtectedSession' in go and 'session.Start()' in go
config = (root / "native/smoke_config.go").read_text()
assert 'dualwg.NewEphemeralSmokeConfigForAllowedIP' in go
assert 'crypto/ecdh' in config and 'private_key=%x' in config and 'public_key=%x' in config
assert 'endpoint=' not in config and 'encoding/base64' not in go
assert 'C.int64_t' in go and 'return -4' in go and 'return -5' in go
assert 'requireTestSession("home")' in service and 'protected-bind-activation' in service
assert 'System.loadLibrary("wonhee_native")' in java
assert 'VpnService.prepare(this)' in service
assert 'VpnService.protect' in service
assert '.establish()' not in service
assert 'ParcelFileDescriptor' not in service
assert 'FOREGROUND_SERVICE_TYPE_SPECIAL_USE' in service
assert 'foregroundServiceType="specialUse"' in manifest
assert 'PROPERTY_SPECIAL_USE_FGS_SUBTYPE' in manifest
assert '.addRoute(' not in service
assert 'stats[0] != 4L || stats[1] != 0L' in service
assert 'RootlessNativeTransportService' not in manifest
assert manifest.count('<action android:name="android.net.VpnService" />') == 2
assert 'tools:node="remove"' in manifest
assert 'versionCode.set(169)' in gradle
assert "applicationIdSuffix '.rootlab01562triple1native160'" in gradle
assert "versionName.set('0.26.5-dual-stack-validation')" in gradle
assert "mergeDebugJniLibFolders" in gradle and "buildWonheeNativeAndroidArm64" in gradle

assert 'WNCreatePacketTestSession' in go and 'WNInjectPacket' in go and 'WNPacketStats' in go
assert 'session.Tun.Inject(packet)' in go and 'session.Tun.Stats()' in go
assert 'nativeCreatePacketTestSession' in bridge and 'nativeInjectPacket' in bridge
assert 'nativePacketStats' in bridge and 'nativeInjectPacket' in java
assert 'NewEphemeralSmokeConfigForAllowedIP' in go
assert '198.18.1.0/24' in config and '0.0.0.0/0' in config
assert 'atomic.Uint64' in (root / "native/packet_tun.go").read_text()
assert 'Injected:' in (root / "native/packet_tun.go").read_text()
assert 'VpnService.prepare(this)' in tun_service
assert 'Builder builder' in tun_service and 'builder.establish()' in tun_service
assert 'builder.addAllowedApplication(getPackageName())' in tun_service
assert 'addRoute("198.18.0.0", 15)' in tun_service
assert 'addAddress("10.253.0.1", 32)' in tun_service
assert 'setBlocking(true)' in tun_service
assert 'RootlessTunTestPacketRouter.select(buffer, length)' in tun_service
assert 'RootlessNativeBridge.injectPacket(handle' in tun_service
assert 'No DNS, default route or root mutation' in tun_service
assert 'addRoute("0.0.0.0"' not in tun_service and 'addRoute("::"' not in tun_service
assert 'addDnsServer' not in tun_service
assert 'RootlessNativePeerActivity' in manifest
assert 'Native live peer handshake test' in rootlab
assert 'RootlessNativeTransportActivity' not in rootlab
assert 'RootlessNativePeerService' in manifest
assert 'Target.HOME' in router
assert 'Target.INTERNET' in router
assert 'Target.DROP' in router
assert 'No peer endpoints, handshakes, DNS or reply path' in tun_service
assert 'probeIndex(buffer, length, batch.port, batch.nonce)' in tun_service
assert 'batch.seen.get() == 63' in tun_service
assert 'hi == 3 && hr == 3 && ni == 3 && nr == 3' in tun_service
assert 'policyDrops.get() == 0' not in tun_service

print("Wonhee native Android socket + scoped TUN ingress contract passed")

live = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlessNativePeerService.java").read_text()
profiles = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/NativePeerProfiles.java").read_text()
assert 'WNCreatePeerSession' in go and 'WNPeerStats' in go and 'entry.handshakeOnly' in go
assert 'RootlessNativeTunPumpService' not in manifest
assert 'builder.establish()' in live and 'builder.addAllowedApplication(getPackageName())' in live and 'builder.addRoute(targets[i],32)' in live
assert 'vpn.bindSocket(socket)' in live and 'socket.connect' in live and 'getOutputStream' in live and 'setEndpointIdentificationAlgorithm("HTTPS")' in live
assert 'createProbeSession' in live and 'pollProbePacket' in live and 'rewrite[slot].toSession(p)' in live
assert 'addDnsServer' not in live and 'addRoute("0.0.0.0"' not in live
assert 'SecureTunnelProfileStore' in profiles and 'validatePeerProfile' in profiles
assert 'p[0]!=2L*count' in live and 's[0]>0&&s[1]>0&&s[2]>0' in live

assert 'PROFILE_MISSING' in profiles and 'DUPLICATE_PEER_IDENTITY_WITH_' in profiles
assert 'NATIVE_PROFILE_REJECTED' in profiles and 'ENCRYPTED_STORE_UNAVAILABLE' in profiles
assert 'failure.code' in live
activity = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlessNativePeerActivity.java").read_text()
assert 'Check selected profiles (no network)' in activity and 'if(!checkProfiles()) return;' in activity

assert 'PeerProfileStatus' in go and 'nativeValidatePeerProfile' in bridge
assert 'HOSTNAME_REQUIRES_NUMERIC_IP' in profiles and 'applyOverride' in profiles
assert 'getStringArrayExtra("overrides")' in live
assert 'getAllByName' not in profiles and 'getByName' not in profiles

assert 'WNCreateProbeSession' in go and 'WNPollProbePacket' in go and 'entry.probe.OwnedTCP(packet,false,entry.probePorts)' in go
assert 'PeerProbeConfig' in go and 'replace_allowed_ips=true' in (root / 'native/peer_probe.go').read_text()

assert 'WNRegisterProbePorts' in go and 'registerProbePorts' in live
assert 'FLOWS=4' in live and 'bindAttempts>=4' in live and 'now-vpnSeenAt>=500L' in live
assert 'responseBytes.get(f)>0' in live and 'sentPayload[f]>0' in live and 'receivedPayload[f]>0' in live
assert 'createSocket(socket,host,ports[slot],false)' in live and 'tls.startHandshake()' in live

assert 'MatchUDP(packet,false,entry.udpPort)' in go and 'MatchUDP(packet,true,entry.udpPort)' in go
assert 'vpn.bindSocket(udp)' in live and 'udpVerified.get(i)==UDP_COUNT' in live
assert 'UDP_COUNT=30' in live and 'bodyBytes.set(flow,read)' in live
assert 'udpSockets[i].close()' in live and 'rejectIpv6' in live

bootstrap = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/NativeEndpointBootstrap.java").read_text()
assert 'network.bindSocket(raw)' in bootstrap and 'service.protect(raw)' in bootstrap
assert 'setEndpointIdentificationAlgorithm("HTTPS")' in bootstrap and 'tls.startHandshake()' in bootstrap
assert 'getByName' not in bootstrap and 'getAllByName' not in bootstrap
assert 'resolver.close()' in live and 'bootstrap.close()' in live
assert 'if(offline) configs[i]=canonical' in profiles and 'resolver.resolve(host,i)' in profiles

assert bootstrap.index('raw.bind(new InetSocketAddress(0))') < bootstrap.index('service.protect(raw)') < bootstrap.index('network.bindSocket(raw)') < bootstrap.index('raw.connect(')
assert 'PROTECT_REFUSED' in bootstrap and 'stage+"/"+category(failure)' in bootstrap
assert 'SECURE_BOOTSTRAP_FAILED/"+failure.code' in profiles
assert 'failure.getMessage()' not in bootstrap

assert 'builder.addRoute(streamTarget,32)' in live
assert 'TRANSFER_BYTES=2*1024*1024' in live and 'NativeTransferBody.read' in live
assert 'probePorts [4]uint16' in go and 'entry.probe.OwnedTCP(packet,true,entry.probePorts)' in go
assert 'resolveTransferTarget()' in bootstrap and 'speed.cloudflare.com' in bootstrap

app_routing = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/NativeAppRoutingService.java").read_text()
app_policy = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/NativeAppRoutingPolicy.java").read_text()
native_route = (root / "native/route_scope.go").read_text()
assert 'WNCreateRouteSession' in go and 'WNPollRoutePacket' in go
assert 'entry.routing.Outgoing(packet)' in go and 'entry.routing.Incoming(packet)' in go
assert 'getConnectionOwnerUid' in app_routing and 'builder.addAllowedApplication(app)' in app_routing
assert '.addRoute("0.0.0.0",0)' in app_routing and '.addRoute("::",0)' in app_routing
assert 'ledger.reply(key,i,now)' in app_routing and 'ledger.admit' in app_routing
assert 'NativeAppRoutingService' in manifest and 'NativeAppRoutingService' not in (root / "app/src/main/AndroidManifest.xml").read_text()
assert 'routeMaxFlows=4096' in native_route and 'MAX_FLOWS=4096' in app_policy
assert 'routePublic(remote)' in native_route and 'if(!publicIp(key.remote))return DROP' in app_policy
assert 'captured apps held in TUN until Stop' in app_routing
assert 'allowBypass' not in app_routing and 'Settings.Global.put' not in app_routing

protected_dns = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/NativeProtectedDnsRelay.java").read_text()
assert 'network.bindSocket(raw)' in protected_dns and 'raw.bind(' in protected_dns
assert 'setEndpointIdentificationAlgorithm("HTTPS")' in protected_dns and 'tls.startHandshake()' in protected_dns
assert 'ports.putIfAbsent(port,raw)' in protected_dns and 'relayForSocket(key)' in app_routing
assert 'key.remotePort==53' in app_routing and 'dnsRelay.submit(p)' in app_routing
assert 'RootBlocklistStore.current(getFilesDir())' in app_routing
assert 'controlled-guard-test' in app_routing and 'old.close()' in app_routing

# Only protected routing may be launched from the app drawer.
import xml.etree.ElementTree as ET
ns="{http://schemas.android.com/apk/res/android}"
xml=ET.fromstring(manifest)
launchers=[]
for activity_node in xml.findall("./application/activity"):
    for filt in activity_node.findall("intent-filter"):
        if any(x.get(ns+"name")=="android.intent.action.MAIN" for x in filt.findall("action")) and any(x.get(ns+"name")=="android.intent.category.LAUNCHER" for x in filt.findall("category")):
            launchers.append(activity_node.get(ns+"name"))
assert launchers==[".NativeAppRoutingActivity"], launchers
for name in (".RootlabTwoPeerActivity",".RootlessNativePeerActivity",".RootlabReadinessActivity",".WonheeDashboardPreviewActivity"):
    node=next(x for x in xml.findall("./application/activity") if x.get(ns+"name")==name)
    assert node.get(ns+"exported")=="false"
    assert not node.findall("intent-filter")

ui_activity = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/NativeAppRoutingActivity.java").read_text()
assert 'SECTIONS={"Home","Tunnels","Routing","Protection","Activity"}' in ui_activity
assert 'NativeHomeRoutes.fromConfig' in ui_activity and 'NativeAppRoutingService.running()' in ui_activity
assert 'NativeRoutingMetrics.perSecond' in app_routing and 'manager.notify(8402,notification())' in app_routing
assert 'policy classification route=' in app_routing

assert 'NativeDnsPositiveCache' in protected_dns and 'cache.get(query,SystemClock.elapsedRealtime())' in protected_dns
assert 'tlsReuse.incrementAndGet()' in protected_dns and 'tlsRetries.incrementAndGet()' in protected_dns
assert 'idle.size()<4' in protected_dns and 'reaper.shutdownNow()' in protected_dns
assert 'cache.clear();replies.clear()' in protected_dns
assert 'TLS reused=' in app_routing and 'cache hits=' in app_routing

assert '@Override public boolean protect(int fd)' in app_routing
assert 'super.protect(fd)' in app_routing and 'n.bindSocket(copy.getFileDescriptor())' in app_routing
assert 'setUnderlyingNetworks(new Network[]{next})' in app_routing
assert 'MAX_RECOVERY_ATTEMPTS=5' in app_routing and 'NativeRecoveryPlan.delay(attempt)' in app_routing
assert 'sessionConfigs=configs.clone()' in app_routing and 'Arrays.fill(sessionConfigs,null)' in app_routing
assert 'retireDns();if(!closePeers())cleanupFailed=true;ledger.entries.clear()' in app_routing
assert 'if(!recover())throw new IllegalStateException' in app_routing
assert 'CAPTURE LOST' in app_routing and 'controlled-recovery-test' in app_routing
assert app_routing.count('builder.establish()')==1
assert 'SUPPORTS_ALWAYS_ON" android:value="false"' in manifest

assert 'registerNetworkCallback(request,physicalCallback)' in app_routing
assert 'registerBestMatchingNetworkCallback' in app_routing and 'unregisterNetworkCallback' in app_routing
assert 'NativeUnderlayPolicy.pick' in app_routing and 'migration.due' in app_routing
assert 'preferred-network-migration' in app_routing and 'physical-underlay-lost' in app_routing
assert 'network migrations=' in app_routing and 'last recovery ms=' in app_routing
assert 'NET_CAPABILITY_NOT_RESTRICTED' in app_routing and 'NET_CAPABILITY_NOT_SUSPENDED' in app_routing
assert 'retry EOF=' in app_routing and 'registered relay ports=' in app_routing

advanced = (root / "native/dns_quic.go").read_text()
tcp_dns = (root / "native/dns_tcp.go").read_text()
dns_jni = (root / "native/cmd/wonhee-jni/dns_jni.go").read_text()
assert 'network.bindSocket(raw)' in protected_dns and 'ParcelFileDescriptor.fromDatagramSocket(raw)' in protected_dns
assert 'quicPorts.putIfAbsent(port,raw)' in protected_dns and 'NativeDnsTransportPolicy.protocol(mode)' in protected_dns
assert 'NativeAdvancedDnsBridge.closeQuic(handle)' in protected_dns and 'NativeAdvancedDnsBridge.closeTcp(tcpHandle)' in protected_dns
assert 'for(QuicConnection q:quicConnections)q.close()' in protected_dns
assert 'quicIdle.pollFirst()' in protected_dns and 'quicIdle.size()<4' in protected_dns
assert 'quicPorts.remove(port,raw)' in protected_dns and 'raw.close()' in protected_dns
assert 'quicConnections.add(c)' in protected_dns and 'if(closed){c.close()' in protected_dns
assert 's.cancel();s.mu.Lock()' in dns_jni and 's.client.Close()' in dns_jni
assert 'net.FilePacketConn(file)' in dns_jni and 'unix.F_DUPFD_CLOEXEC' in dns_jni
assert 'quic.Dial(ctx,boundedPacketConn{c.pc},c.addr' in advanced and 'http3.Transport' in advanced
assert 'quic.DialEarly(ctx,boundedPacketConn{pc},c.addr' in advanced
assert 'unexpected HTTP/3 redial' in advanced and 'unexpected DoQ redial' in advanced
assert 'exchangeDoQStream(ctx,c.doq,q)' in advanced and 'c.httpClient' in advanced
assert 'NewQuicDNSClient(s.ctx' in dns_jni and 's.client.Exchange(' in dns_jni
assert 'RootCAs:roots' in advanced and 'InsecureSkipVerify' not in advanced
assert 'DisablePathMTUDiscovery:true' in advanced and 'q[0],q[1]=0,0' in advanced
assert 'netstack.CreateNetTUN' in tcp_dns and 'network.ListenTCP' in tcp_dns
assert 'tcpDNSPacket(p,false)' in tcp_dns and 'dnsRelay.feedTcp(p)' in app_routing and 'dnsRelay.drainTcpQueries()' in app_routing
assert 'NativeDnsTransportPolicy.supports' in app_routing and 'NativeDnsTransportPolicy.supports' in ui_activity
assert 'validateFull(q,answer)' in protected_dns

# 0.22.1: bounded retry and explicit same-provider alternate endpoint.
assert 'DNSProviderAddress(int(provider),int(mode),int(alternate))' in dns_jni
assert 'remote.IP.Equal(net.ParseIP(s.endpoint.IP))' in dns_jni
assert 'NativeAdvancedDnsBridge.createQuic(provider,mode,alternate,quicRoots)' in protected_dns
assert 'if(k.remote!=ip||k.remotePort!=NativeDnsTransportPolicy.port(mode)' in protected_dns
assert 'freshBackoff.begin' in protected_dns and 'freshBackoff.finish' in protected_dns
assert 'QUIC_IDLE_LIMIT=10000' in protected_dns and 'quicFreshRetries' in protected_dns
assert 'r.testProvider()' in app_routing and 'DNS_TEST' in ui_activity
assert 'dnsAlternate.getSelectedItemPosition()' in ui_activity
assert 'DNS probe attempts=' in app_routing and 'dnsHealth' in ui_activity

assert 'functionalOwns(key)' in app_routing and 'return UNKNOWN_DNS' in app_routing
assert 'network.bindSocket(socket)' in protected_dns and 'NativeAppRoutingPolicy.DNS),53)' in protected_dns
assert 'closeFunctional();functionalWorker.shutdownNow()' in protected_dns
assert 'DNS_FUNCTIONAL_TEST' in ui_activity and 'r.testFunctional()' in app_routing

# 0.23: strict fixed-address HTTPS bootstrap; no resolver fallback.
assert 'InetAddress.getByAddress(resolverIp),port)' in bootstrap and 'port=option%2==0?443:853' in bootstrap
assert 'NativeBootstrapHttp.request' in bootstrap and 'NativeBootstrapHttp.response' in bootstrap
assert 'authenticated-DoH' in bootstrap and 'authenticated-DoT' in bootstrap
assert 'tls.setSoTimeout(timeout())' in bootstrap

# 0.23.1: broad capture only when explicitly opted in; never route unknown owners.
assert 'if(!allApps)builder.addAllowedApplication(getPackageName())' in app_routing
assert 'if(!allApps)for(String app:apps)builder.addAllowedApplication(app)' in app_routing
assert 'if(resolveOwner(uid))return uid' in app_routing and 'common.same(a)' in app_routing
assert 'uid==android.os.Process.myUid()' in app_routing
assert 'NativeAppCategorySuggestions.suggest' in app_routing and 'NativeAppCategorySuggestions.suggest' in ui_activity
assert 'allApps.isChecked()' in ui_activity and 'draft.getBoolean("allApps",false)' in ui_activity
assert 'Port flows ' in app_routing and 'portFlows[selector][role]++' in app_routing
assert 'InvalidQuicResponse' in protected_dns and 'if(e instanceof InvalidQuicResponse)ok=true' in protected_dns
assert 'android.permission.QUERY_ALL_PACKAGES' in manifest and 'android.permission.QUERY_ALL_PACKAGES' not in (root / "app/src/main/AndroidManifest.xml").read_text()

# 0.24: bounded retry and hold tests; no provider fallback or bypass.
assert 'NativeRoutingSafety.retryBootstrap' in bootstrap and 'queryOnce(host,type)' in bootstrap
assert 'BOOTSTRAP RETRY' in bootstrap and 'stopped()' in bootstrap
assert 'SHARED_UID_REQUIRES_ALL_MEMBERS_SAME_RULE_OR_ALL_APP_MODE' in app_routing
assert 'SHARED_UID_REQUIRES_ALL_MEMBERS_SAME_RULE_OR_ALL_APP_MODE' in ui_activity
assert 'r.category.getSelectedItemPosition()!=r.suggested' in ui_activity
assert 'NativeRoutingSafety.isolationAllowed(request,count,dnsRole,dnsStrategy!=NativeAppRoutingPolicy.DNS_GLOBAL)' in app_routing
assert app_routing.index('NativeRoutingSafety.held(role,isolationRole,now,isolationUntil)') < app_routing.index('RootlessNativeBridge.injectPacket(handles[role],translated)')
assert 'NativeRoutingSafety.held(i,isolationRole,now,isolationUntil)' in app_routing
assert 'Category flows ' in app_routing and 'ISOLATION_TEST' in ui_activity
assert 'protection unconfirmed' in ui_activity
assert 'Check configuration (offline)' in ui_activity

# Configuration retention contract: same draft namespace and package, autosaved routes and endpoint overrides, bounded route-only backup.
assert 'native_app_route_draft_v1' in ui_activity
assert 'wireDraftAutosave()' in ui_activity and 'autoSave();super.onPause()' in ui_activity
assert 'draft.getString("endpointOverride"+i,"")' in ui_activity and 'e.putString("endpointOverride"+i' in ui_activity
assert 'EXPORT_RULES' in ui_activity and 'IMPORT_RULES' in ui_activity and 'if(routingKey(key))e.remove(key)' in ui_activity
assert '1048576' in ui_activity and 'putRoutingValue(e,k,values.get(k))' in ui_activity

# 0.25.1: strict routing for attributable DNS; explicit policy for unknown owner.
assert 'NativeProtectedDnsRelay[] dnsRelays=new NativeProtectedDnsRelay[2]' in app_routing
assert 'dnsRelays[role]=new NativeProtectedDnsRelay(vpn,dnsProvider,role,dnsMode,dnsAlternate,blocklist)' in app_routing
assert 'policy.dnsExit(key,owners.get(owner),owner==UNKNOWN_DNS,dnsStrategy,dnsRole)' in app_routing
assert 'dnsLedger.admit(key,syn,owner,route,now)' in app_routing and 'dnsLedger.reply(reply,dnsRelay.role,now)' in app_routing
assert 'dnsLedger.entries.clear()' in app_routing
assert 'if(held){dnsIsolationDropped++;continue;}' in app_routing
assert 'NativeRoutingSafety.held(route,isolationRole,now,isolationUntil)' in app_routing
assert 'owner==RELAY_UID?(dnsRelay==null?-1:dnsRelay.role)' in app_routing
assert 'if(found!=null)return null' in app_routing
assert 'dnsStrategy' in ui_activity and 'Strict · deny unattributed DNS' in ui_activity
assert 'isolationUntil' in ui_activity and 'isolationUntil' in app_routing

# 0.26.0: isolated root egress trial, not legacy root guard reactivation.
egress = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/NativeEgressGuard.java").read_text()
egress_plan = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/NativeEgressGuardPlan.java").read_text()
egress_runtime = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/NativeEgressGuardRuntime.java").read_text()
assert 'getBooleanExtra("rootEgressGuard",false)' in app_routing
assert app_routing.index('tun=builder.establish()') < app_routing.index('egressGuard.install(') < app_routing.index('stage="dns-relay";')
assert 'egressGuard.failed()' in app_routing and 'egressGuard.retain()' in app_routing and 'egressGuard.remove()' in app_routing
assert 'EGRESS_JOURNAL_PENDING_RECOVER_OFFLINE' in app_routing
assert 'rootEgressGuard' in ui_activity and 'Recover owned root guard (offline)' in ui_activity
assert 'putString(KEY,plan.encode()).commit()' in egress and 'runtime.remove(plan)' in egress
assert 'scheduleWithFixedDelay(this::audit,5,5,TimeUnit.SECONDS)' in egress
assert 'EGRESS_STRICT_IPV4_NOT_ENABLED' in egress_runtime
assert ' -F ' not in egress_runtime and ' -P ' not in egress_runtime and '-j ACCEPT' not in egress_plan
assert 'RootGuardSafetyGate' not in egress_runtime
assert 'static boolean activationPaused() { return true; }' in (root / "app/src/main/java/com/yooshastan/wonheeproxy/RootGuardSafetyGate.java").read_text()

# 0.26.1: validation loss alone is not a physical failure under the root guard.
assert 'private Network preferredNetwork(){return pickNetwork(false,false);}' in app_routing
assert 'NativeUnderlayPolicy.sessionCandidate(eligibleLink(n),usable(n),guardedSession())' in app_routing
assert 'NET_CAPABILITY_CAPTIVE_PORTAL' in app_routing
assert 'if(!sessionUsable(underlay))reason="physical-underlay-lost"' in app_routing
assert 'else if(!peerReady)reason="peer-health"' in app_routing
assert 'NativeUnderlayPolicy.retainUnvalidated' in app_routing and 'Network next=recoveryCandidate(attempt)' in app_routing
assert 'FAILED_TRIAL_COOLDOWN_MS' in app_routing and 'UNDERLAY TRIAL — ' in app_routing
assert 'if(!captureIntact()||!dnsOff()||!sessionUsable(next)||!protectedSockets()' in app_routing
assert 'isolationRole=-1;isolationUntil=0;' not in app_routing[app_routing.index('if(recoveryTest||reason!=null)'):app_routing.index('if(dnsTest.getAndSet(false))')]
assert 'retained "+NativePeerProfiles.SLOTS[isolationRole]+" through recovery; original deadline unchanged' in app_routing
assert 'UNDERLAY PROBE — encrypted DNS through non-held exits; diagnostic only' in app_routing
assert 'nextValidationProbe=now+30000' in app_routing
assert 'egressGuard!=null&&egressGuard.failed()' in app_routing
assert 'peerEvidence' in ui_activity and 'validationLosses' in ui_activity
assert 'per-rule counters unavailable' in egress_runtime and 'DNS53=' in egress_runtime

# 0.26.2: pinned guarded recovery and local-only diagnostics.
assert 'recoveryRequested=stage.equals("preferred-network-migration")?requestedMigration:recoveryFrom' in app_routing
assert 'NativeUnderlayPolicy.recoveryTarget(attempt,id(recoveryRequested),id(recoveryFrom),eligible)' in app_routing
assert 'NativeUnderlayPolicy.handshakeBudget(speculative)' in app_routing and 'SystemClock.elapsedRealtime()+budget' in app_routing
assert 'startupProbePending=true' in app_routing and 'if(startupProbePending){startupProbePending=false;runDnsTests(false,now);}' in app_routing
assert 'if(!quicEstablished)synchronized(coldQuicGate)' in protected_dns
assert 'quicEstablished=true' in protected_dns and 'exchangeQuicInternal(query)' in protected_dns
assert 'peerDetails' in ui_activity and 'Inspect active routing' in ui_activity
assert 'uidEvidence=Collections.unmodifiableMap(result)' in app_routing and 'uidEvidenceAt=0;uidEvidence=Collections.emptyMap()' in app_routing
assert 'NativeAppRoutingService.inspectUid' in ui_activity
assert 'publishUidEvidence(state,now)' in app_routing

# 0.26.3: narrow validation bridge; no direct resolver exception.
validation_policy = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/NativeValidationDnsPolicy.java").read_text()
validation_plan = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/NativeValidationDnsPlan.java").read_text()
validation_bridge = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/NativeValidationDnsBridge.java").read_text()
assert 'VALIDATION_REQUIRES_ROOT_GUARD_AND_STRICT_DNS' in app_routing and 'VALIDATION_REQUIRES_ROOT_GUARD_AND_STRICT_DNS' in ui_activity
assert 'NETWORK_STACK_UID=1073' in validation_policy and 'new int[]{4}' in validation_plan
assert '-o wlan0 -p ' in validation_plan and '--dport 53 -m owner --uid-owner ' in validation_plan and '-j REDIRECT --to-ports ' in validation_plan
assert '-j ACCEPT' not in validation_plan and '-j ACCEPT' not in egress_plan
assert 'new byte[]{127,0,0,1}' in validation_bridge and 'active.resolveValidation(canonical,result::complete)' in validation_bridge
assert 'result.get(3500,TimeUnit.MILLISECONDS)' in validation_bridge and 'relay!=active' in validation_bridge
assert 'validationBridge.setRelay(null)' in app_routing and 'validationWifi&&!NativeRoutingSafety.held(0,isolationRole,now,isolationUntil)' in app_routing
assert 'runtime.installValidation(plan.validationPlan())' in egress and 'runtime.verify(plan.validationPlan())' in egress and 'runtime.remove(plan.validationPlan())' in egress
assert 'runtime.remove(p.validationPlan())' in egress
assert 'validationPort==0?null:new NativeValidationDnsPlan' in egress_plan
assert 'validationCompat' in ui_activity and 'validationStatus' in app_routing

# 0.26.4: partition existing terminal drops, never add a DNS bypass.
assert 'for(int owner:new int[]{1051,1073,0,1000})' in egress_plan
assert 'base.add("-o wlan0 -p "+proto+" --dport 53 -m owner --uid-owner "+owner+" -j DROP")' in egress_plan
assert 'diagnostics=1' in egress_plan and 'validationPort,true,validationPort!=0)' in egress
assert 'DNS53 Wi-Fi owner 1051=' in egress_runtime and 'other/unmatched=' in egress_runtime
assert 'append("NAT IPv").append(f).append(" redirect UDP=")' in egress_runtime and 'IPv6 redirect not installed' in egress_runtime
assert 'runtime.validationCounters(plan.validationPlan())' in egress

# 0.26.5: dual-stack opt-in loopback validation, actual observed owner.
assert 'return dual?0:NativeValidationDnsPolicy.NETWORK_STACK_UID' in validation_plan
assert 'dual?new int[]{4,6}:new int[]{4}' in validation_plan
assert 'validationDual=1' in egress_plan and 'validationPlan().owner()' in egress_plan
assert 'family==4?"127.0.0.1":"::1"' in egress_plan
assert 'new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}' in validation_bridge
assert 'u6.bind(new InetSocketAddress(loop6,t.getLocalPort()))' in validation_bridge
assert 'udpWorker6,tcpWorker6' in validation_bridge
