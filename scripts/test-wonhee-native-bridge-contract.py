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
assert 'versionCode.set(147)' in gradle
assert "applicationIdSuffix '.rootlab01562triple1native160'" in gradle
assert "versionName.set('0.16.0-native-app-routing')" in gradle
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
