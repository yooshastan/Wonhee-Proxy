#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
bridge = (root / "native/cmd/wonhee-jni/jni_bridge.c").read_text()
go = (root / "native/cmd/wonhee-jni/main.go").read_text()
java = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlessNativeBridge.java").read_text()
service = (root / "app/src/debug/java/com/yooshastan/wonheeproxy/RootlessNativeTransportService.java").read_text()
manifest = (root / "app/src/debug/AndroidManifest.xml").read_text()
gradle = (root / "app/build.gradle").read_text()

assert 'GetMethodID(env, cls, "protect", "(I)Z")' in bridge
assert 'CallBooleanMethod(env, g_service, method, (jint)fd)' in bridge
assert 'wn_protect_socket(C.int(fd)) == 1' in go
assert 'dualwg.NewProtectedSession' in go and 'session.Start()' in go
config = (root / "native/smoke_config.go").read_text()
assert 'dualwg.NewEphemeralSmokeConfig()' in go
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
assert 'RootlessNativeTransportService' in manifest
assert 'tools:node="remove"' in manifest
assert 'versionCode.set(135)' in gradle
assert "versionName.set('0.15.81-native-smoke-ipc')" in gradle
assert "mergeDebugJniLibFolders" in gradle and "buildWonheeNativeAndroidArm64" in gradle
print("Wonhee native Android bridge contract passed")
