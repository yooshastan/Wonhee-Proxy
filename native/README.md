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
