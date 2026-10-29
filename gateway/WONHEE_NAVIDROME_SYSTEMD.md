# Persistent Navidrome listener for Wonhee WireGuard

The Fedora Navidrome Podman container deliberately publishes `127.0.0.1:4533`. Moka Beta 6.1 connects to `http://10.77.0.1:4533` **only through the Wonhee VPN**. A manually launched `socat` process is lost on reboot. This systemd unit forwards only the VPN interface address to localhost and restarts after process failure.

**Do not reconfigure Podman to listen on `0.0.0.0` or forward TCP 4533 through your router.** Keep the router's existing *WireGuard UDP 51820* rule and the `wonheevpn` zone with the authorized phone peer only.

## Install on Fedora

From your Wonhee-Proxy checkout, install dependencies and check the exact intended endpoints:

```bash
sudo dnf install -y socat
ip -br addr show wg0
sudo podman port moka-navidrome
sudo ss -lntp | grep ':4533'
```

Expected: `wg0` owns `10.77.0.1/24`, and Navidrome listens on `127.0.0.1:4533`. Stop any **old manually launched** `socat` listener occupying `10.77.0.1:4533` before starting the service. First identify its exact PID using `sudo ss -lntp 'sport = :4533'`; avoid broad `pkill` commands.

```bash
sudo install -m 0644 gateway/systemd/wonhee-navidrome-forward.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wonhee-navidrome-forward.service
sudo systemctl status wonhee-navidrome-forward.service
```

If `wg0` starts later than systemd, the service retries every ten seconds until `10.77.0.1` becomes available. In a Fedora system with a different `socat` path, update the unit's `ExecStart` after checking `command -v socat`.

### Make the existing narrow firewalld rule persistent

The *runtime* rule from troubleshooting is lost after reload/reboot. Preserve it permanently only for the single trusted WireGuard peer:

```bash
sudo firewall-cmd --get-zone-of-interface=wg0
sudo firewall-cmd --permanent --zone=wonheevpn --add-rich-rule='rule family="ipv4" source address="10.77.0.2/32" destination address="10.77.0.1/32" port port="4533" protocol="tcp" accept'
sudo firewall-cmd --reload
sudo firewall-cmd --zone=wonheevpn --list-rich-rules
```

**Caution:** A firewalld reload applies the entire permanent ruleset, not just this rule. Review any other runtime-only changes before reloading.

## Verify

```bash
sudo ss -lntp 'sport = :4533'
curl --max-time 5 -I http://127.0.0.1:4533/
curl --max-time 5 -I http://10.77.0.1:4533/
sudo journalctl -u wonhee-navidrome-forward.service -n 40 --no-pager
```

Connect Wonhee on the phone, then open `http://10.77.0.1:4533` in a browser and stream from Moka. Test again after Fedora reboot and a WireGuard reconnect. TCP connectivity alone does not prove full-tunnel VPN internet routing or leak protection.

To disable this optional forwarder:

```bash
sudo systemctl disable --now wonhee-navidrome-forward.service
```

Keep the Podman mapping `127.0.0.1:4533`; Tailscale Serve and Wonhee can coexist server-side. Only Android's **active VPN app** changes.
