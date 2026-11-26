#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
bridge = (root / "native/cmd/wonhee-jni/jni_bridge.c").read_text()
go = (root / "native/cmd/wonhee-jni/main.go").read_text()
java = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlessNativeBridge.java").read_text()
service = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlessNativeTransportService.java").read_text()
tun_service = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlessNativeTunPumpService.java").read_text()
router = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlessTunTestPacketRouter.java").read_text()\nrootlab = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlabTwoPeerActivity.java").read_text()
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
assert manifest.count('<action android:name="android.net.VpnService" />') == 1
assert 'tools:node="remove"' in manifest
assert 'versionCode.set(136)' in gradle
assert "applicationIdSuffix '.rootlab01562triple1native082'" in gradle
assert "versionName.set('0.15.82-native-tun-ingress')" in gradle
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
assert 'RootlessNativeTunPumpActivity' in manifest\nassert 'Native TUN packet pump test' in rootlab\nassert 'RootlessNativeTransportActivity' not in rootlab
assert 'RootlessNativeTunPumpService' in manifest
assert 'Target.HOME' in router
assert 'Target.INTERNET' in router
assert 'Target.DROP' in router
assert 'No peer endpoints, handshakes, DNS or reply path' in tun_service

print("Wonhee native Android socket + scoped TUN ingress contract passed")
