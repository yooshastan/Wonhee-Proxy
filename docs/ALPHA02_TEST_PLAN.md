# Wonhee Proxy Alpha 0.2 manual verification

Test on Pixel 8a and Samsung A36 if available. Do not paste actual MTProto
secrets, SOCKS5 passwords, decrypted profile stores or credential-bearing
deep links into bug reports.

## Encrypted profile storage

- [ ] Enter a named MTProto profile with public host, LAN host, port and a valid
      test secret. Save. Quit and relaunch; load it again.
- [ ] Enter a separate SOCKS5 profile, including optional username/password,
      and save it. Verify both entries appear in the profile picker.
- [ ] Update an existing profile using the same name; confirm no duplicate
      appears. Switch between profiles and verify masked credentials reload.
- [ ] Delete one with confirmation; confirm the other remains.
- [ ] Refuse invalid empty name, invalid port and malformed secret.
- [ ] Confirm ordinary SharedPreferences data contains only base64-encrypted
      payload (not the server address or secret). Avoid logging sensitive data.
- [ ] If Keystore is unavailable, saving must fail closed without plaintext.

## Endpoint selection and diagnostics

- [ ] Home Wi-Fi subnet containing LAN IPv4: Auto uses LAN endpoint.
- [ ] Cellular with Wi-Fi off: Auto uses public endpoint.
- [ ] Different Wi-Fi subnet: Auto uses public endpoint.
- [ ] Device VPN active: Auto should prefer public, with no claim of verification.
- [ ] Explicit Public and LAN selections override Auto, even on cellular.
- [ ] Verify consent dialog names the selected address and port.
- [ ] TCP reachable reports latency; timeout/refusal/DNS failure show separate
      results. None claims authenticated MTProto/SOCKS5 handshake.

## Ultgram handoff

- [ ] From a saved MTProto profile, import into Ultgram FOSS debug build.
- [ ] From a saved SOCKS5 profile, confirm the right values arrive.
- [ ] Verify no Android system chooser exposes proxy secrets.
- [ ] Send messages/download media in Ultgram and check its native proxy status.
- [ ] After switching networks, deliberately re-import as needed; no background
      route switching is promised or implemented.

Known limitations: No VPN, encrypted DNS, ad blocking, fail-closed routing,
protocol handshake test or Navidrome replacement in this alpha.
