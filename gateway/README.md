# Optional remote MTProxy node

**Use a Linux VPS** for IP separation. Hosting this at home on Fedora or a
Raspberry Pi generally exposes the home connection's public IP to Telegram
because the outgoing proxy connection still originates at home.

With Docker Engine and Compose installed on the VPS, and inbound TCP/443 allowed:

```bash
docker compose -f gateway/compose.mtproxy.yml up -d
docker compose -f gateway/compose.mtproxy.yml ps
docker compose -f gateway/compose.mtproxy.yml logs --no-color mtproxy
```

The upstream container prints a `tg://proxy` import link on first
startup. **It contains your client secret.** Keep logs and link private;
never commit either. Persistent volume data preserves the generated secret
through ordinary restarts. Validate updates before deploying; this starter
uses a floating upstream `latest` tag and should be pinned to a
reviewed immutable digest for production.

The port check in Wonhee Proxy proves only a TCP listener is reachable. Test
connection authentication, actual Telegram messages, media, reconnects and
failure behavior separately on Pixel 8a and A36.

## Navidrome and private Fedora services

MTProxy forwards Telegram traffic only. It cannot replace Tailscale for
Navidrome or a private Flask dashboard. In a later phase, plan a separate
authenticated HTTPS gateway backed by an outbound-only Fedora-to-VPS tunnel,
or another narrowly authorized private access mechanism. Keep the existing
Navidrome Podman mapping bound to `127.0.0.1:4533` and do not
expose it directly to the public internet.

References: https://core.telegram.org/proxy and
https://github.com/TelegramMessenger/MTProxy.
