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
assert 'crypto/ecdh' in go and 'endpoint=' not in go
assert 'System.loadLibrary("wonhee_native")' in java
assert 'Builder()' in service and '.addAddress("10.255.255.1", 32)' in service
assert '.addRoute(' not in service
assert 'stats[0] != 4L || stats[1] != 0L' in service
assert 'RootlessNativeTransportService' in manifest
assert 'tools:node="remove"' in manifest
assert 'versionCode.set(133)' in gradle
assert "versionName.set('0.15.79-native-socket-protection')" in gradle
assert "mergeDebugJniLibFolders" in gradle and "buildWonheeNativeAndroidArm64" in gradle
print("Wonhee native Android bridge contract passed")
