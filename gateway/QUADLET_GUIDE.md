# Optional persistent Fedora server: Podman Quadlet

Wonhee Android Alpha 0.3 **does not modify your Fedora host**. The sample
Quadlet at quadlet/wonhee-mtproxy.container.example is an operator-reviewed
deployment option for a future maintenance window.

Your existing rootful Podman container already binds host TCP port 8443 to
container port 443 and stores its generated MTProxy secret in the named volume
wonhee-mtproxy-data. Do not accidentally start two containers on that port or
replace the persistent volume.

1. Before making any change, inspect the existing setup and record recovery
   details privately. **Do not paste generated MTProxy secrets into issues.**
   
       sudo podman inspect wonhee-mtproxy
       sudo podman port wonhee-mtproxy
       sudo podman volume inspect wonhee-mtproxy-data

2. Review and pin the container image to a known digest for reproducible
   deployments. The template uses latest only to mirror the existing
   proof-of-concept and should be hardened before production.
3. Decide when to retire the existing container, preserving the named volume.
   The template is not safe to enable while the original container is still
   present with the same name and port binding.
4. After authorizing a maintenance window, place a reviewed copy of the unit
   in /etc/containers/systemd/wonhee-mtproxy.container, reload systemd and
   enable wonhee-mtproxy.service. Confirm that the existing volume has been
   reused, not replaced. Prepare a rollback plan before switching.
5. Test reachability from cellular and verify **actual Ultgram connection**,
   not just a TCP socket. Keep the Fedora firewall's TCP 8443 rule restricted
   to the intended interface/zone and watch for unsolicited scans.

Do not use this Telegram-only service to expose Navidrome. A future
Tailscale replacement for Navidrome requires its own authenticated TLS tunnel,
access control and independent threat-model review.
