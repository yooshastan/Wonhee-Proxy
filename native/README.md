# Dual WireGuard native transport experiment

This module introduces **two independent wireguard-go device instances** fed
by separate bounded in-memory packet interfaces. It does not use or alter the
Android `GoBackend` or its single working VpnService.

Build/test: `cd native && go test ./...` with Go >= 1.23.1.

Security gate: the modules are created **down** and do not open UDP sockets.
Never call `Device.Up` from Android until a protected UDP bind is implemented
and verified for both instances. The existing WireGuard Android entry point
uses a kernel TUN file descriptor and cannot receive a userspace packet queue.

Before enabling a dual-connect UI, add: Android JNI bridge; protected sockets
and endpoint migration; one Android TUN read/write pump; independent session
keys/configuration; validated IPv4 source translation; IPv6/DNS/MTU policy;
atomic teardown, reconnect and test coverage. No live dual tunnel is claimed.

Implementation is based on WireGuard's public Go APIs and must retain the
appropriate upstream licensing and notices when distributed.

## Protected UDP bind foundation
The protected-bind adapter requires both IPv4 and IPv6 sockets and synchronously invokes the supplied platform protection callback for each before exposing receive functions or permitting send. Failed protection closes the underlying sockets; reopening repeats protection; arbitrary profile fwmarks are rejected. The native protected session has an explicit guarded Start method, while legacy inactive sessions cannot activate. The callback is not yet connected to Android: the actual VpnService, JNI/mobile binding, TUN packet pump and independent multi-exit flow classifier remain required. Mock tests are not device proof.
