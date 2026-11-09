#!/usr/bin/env python3
"""One-time 0.15.28 Wonhee root ledger rescue. Default is READ-ONLY.

DO NOT use on another package, unknown ledger, other route plan, or with a
running DNS firewall/relay. This is a *process-stop + metadata-only* rescue,
NOT a replacement for Wonhee's own identity-verified Safe Stop.
"""
import argparse
import datetime
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

PKG = "com.yooshastan.wonheeproxy"
BASE = Path("/data_mirror/data_ce/null/0") / PKG / "shared_prefs"
FILE = BASE / "wonhee_owned_split_routes.xml"
DNS_FILE = BASE / "wonhee_owned_dns_policy.xml"
GUARD_FILE = BASE / "wonhee_owned_guard_policy.xml"
KEY = "pending_or_installed_rules_v1"
TRAILER = b"\n    "
HOME = "wnma292ddb4b6da"
AIR = "wnm68fe81200daa"
EXPECTED = [
    ("12500", "10.0.0.0/24", "10.0.0.1"),
    ("12501", "10.6.0.0/24", "10.6.0.1"),
    ("12502", "10.77.0.0/24", "10.77.0.1"),
]


class Refuse(RuntimeError):
    pass


def require(condition, msg):
    if not condition:
        raise Refuse(msg)


def command(*args, allow_missing=False):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        if allow_missing:
            return ""
        raise Refuse("Required read-only command unavailable: " + " ".join(args[:3]))
    return result.stdout


def xml_key(path, key):
    try:
        root = ET.fromstring(path.read_bytes())
    except (OSError, ET.ParseError) as e:
        raise Refuse("Cannot parse expected app preferences " + path.name) from e
    found = [node for node in root.findall("string") if node.get("name") == key]
    require(len(found) == 1, "Expected unique key missing: " + key)
    return found[0].text or ""


def inspect_ledger():
    require(FILE.is_file(), "Wonhee routing preferences not readable via data mirror")
    raw = FILE.read_bytes()
    matches = list(re.finditer(
        rb'<string name="pending_or_installed_rules_v1">(.*?)</string>',
        raw, re.DOTALL))
    require(len(matches) == 1, "Expected exactly one plain routing string in XML")
    match = matches[0]
    body = match.group(1)
    require(body.endswith(TRAILER), "Exact 4-space trailing padding not present; refusing")
    require(xml_key(FILE, KEY).encode("utf-8") == body,
            "Raw XML and parsed value disagree; no repair")
    lines = body[:-4].decode("utf-8").splitlines()
    require(len(lines) == 3, "Expected precisely three nonempty saved routes")
    for idx, (line, expected) in enumerate(zip(lines, EXPECTED)):
        fields = line.split("|")
        priority, cidr, probe = expected
        require(len(fields) == 6, "Invalid saved route field count")
        require(fields == ["4", priority, cidr, HOME, probe, "0x0/0x20000"],
                "Saved route differs from pinned validated route at index " + str(idx + 1))
        net = ipaddress.ip_network(cidr)
        require(str(net.network_address + 1) == probe,
                "Saved routing probe mismatch")
    new_body = body[:-4]
    patched = raw[:match.start(1)] + new_body + raw[match.end(1):]
    try:
        root = ET.fromstring(patched)
        node = root.find("./string[@name='pending_or_installed_rules_v1']")
        require(node is not None and (node.text or "").encode("utf-8") == new_body,
                "Patched XML failed readback verification")
    except ET.ParseError as e:
        raise Refuse("Patched XML would not be valid") from e
    return raw, patched


def check_kernel():
    require(os.geteuid() == 0, "Root is required for independent audit.")
    version = command("dumpsys", "package", PKG)
    m = re.search(r"\bversionCode=(\d+)\b", version)
    require(m is not None and m.group(1) == "75", "Official package must be versionCode 75")

    links = command("ip", "-o", "link", "show")
    visible = re.findall(r"^\s*\d+:\s+(wnm[0-9a-z_-]+|wnhome0|wnair0)(?:@[^:]*)?:",
                         links, re.MULTILINE)
    require(sorted(visible) == sorted([HOME, AIR]),
            "Expected exactly the two known Wonhee kernel tunnel interfaces")
    for name in (HOME, AIR):
        line = next((line for line in links.splitlines() if re.search(
            r"^\s*\d+:\s+" + re.escape(name) + r":", line)), "")
        require("UP" in line and "LOWER_UP" in line,
                "A known tunnel is not in the expected connected state")

    ipv4 = command("ip", "-4", "rule", "show").splitlines()
    ipv6 = command("ip", "-6", "rule", "show").splitlines()
    reserved = [
        (family, line)
        for family, listing in ((4, ipv4), (6, ipv6))
        for line in listing
        if (lambda m: m and 12500 <= int(m.group(1)) <= 12799)(
            re.match(r"^\s*(\d+):", line))
    ]
    require(len(reserved) == 3 and all(family == 4 for family, _ in reserved),
            "Reserved IPv4/IPv6 routing inventory differs from the three owned routes")
    for line, (priority, cidr, probe) in zip(
            [line for _, line in sorted(reserved, key=lambda x: int(
                re.match(r"^\s*(\d+):", x[1]).group(1)))], EXPECTED):
        exact = (rf"^\s*{priority}:\s+from all to {re.escape(cidr)} "
                 rf"fwmark 0x0/0x20000 iif lo uidrange 0-99999 "
                 rf"lookup {HOME}\s*$")
        require(bool(re.match(exact, line)),
                "Exact live rule mismatch at priority " + priority)

    require(DNS_FILE.is_file(), "Expected DNS ledger file unavailable")
    require(xml_key(DNS_FILE, "pending_dns_policy_v1") == "",
            "DNS still has ownership intent; do not stop app or touch ledger")
    if GUARD_FILE.exists():
        require(xml_key(GUARD_FILE, "pending_guard_v1") == "",
                "Batch F guard ledger not empty/unknown; refuse")

    for args in [
        ("iptables", "-w", "-t", "nat", "-S", "OUTPUT"),
        ("iptables", "-w", "-S", "OUTPUT"),
        ("ip6tables", "-w", "-S", "OUTPUT"),
    ]:
        require("WN_" not in command(*args) and "WN_MULTI" not in command(*args),
                "Wonhee firewall markers remain or changed")
    for family in ("udp", "udp6", "tcp", "tcp6"):
        try:
            sockets = Path("/proc/net/" + family).read_text()
        except OSError as e:
            raise Refuse("Cannot inspect DNS listener sockets") from e
        for line in sockets.splitlines()[1:]:
            fields = line.split()
            if len(fields) > 1:
                require(fields[1].split(":")[-1].upper() != "D11F",
                        "DNS port 53535 bound; refuse")
    return True


def process_ids():
    out = command("pidof", PKG, allow_missing=True)
    return out.strip().split()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="Explicitly stop app process then repair exactly four spaces")
    args = parser.parse_args()
    raw, patched = inspect_ledger()
    check_kernel()
    print("PASS: 0.15.28, three exact saved/live Home routes, two known tunnels.")
    print("PASS: no active Wonhee DNS or guard ownership/firewall/relay.")
    print("PASS: only four trailing whitespace bytes need removal from routing XML.")
    if not args.apply:
        print("READ-ONLY CHECK COMPLETED. No files, processes, rules or tunnels changed.")
        print("Applying repair requires an explicit --apply, and will force-stop the app.")
        return 0

    require(sys.stdin.isatty(), "Applying rescue requires an interactive terminal")
    print("WARNING: --apply FORCE-STOPS the Wonhee application process.")
    print("This can interrupt notifications and app-managed networking; NO kill switch is active.")
    print("The script does NOT disconnect either kernel tunnel. Keep USB ADB ready.")
    confirmation = input("Type REPAIR to stop Wonhee and patch the exact four spaces: ")
    require(confirmation == "REPAIR", "User declined the repair")

    # Android may update SharedPreferences in memory. Quiesce only this package
    # before the file mutation, then reverify every condition. This intentionally
    # does not call pm clear/uninstall or any network operation.
    command("am", "force-stop", PKG)
    require(not process_ids(), "Wonhee process restarted; do not patch live preferences")
    before, after = inspect_ledger()
    require(before == raw, "Saved ledger changed since initial inspection")
    check_kernel()

    backup_dir = Path("/data/local/tmp/wonhee-ledger-recovery")
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    backup = backup_dir / (
        "wonhee_owned_split_routes-" +
        datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".xml")
    fd = os.open(str(backup), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(before)
        handle.flush()
        os.fsync(handle.fileno())
    require(backup.read_bytes() == before, "Backup verification failed; no changes made")

    # Preserve original inode, owner and SELinux label. This is a root metadata
    # rescue, never a generic SharedPreferences editor.
    with FILE.open("r+b") as handle:
        require(handle.read() == before, "Ledger changed during backup; aborting")
        handle.seek(0)
        handle.write(after)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())
    require(FILE.read_bytes() == after, "Post-write verification failed. Preserve backup.")
    print("PATCH APPLIED: exactly four spaces removed, all three route records preserved.")
    print("Backup (root-only): " + str(backup))
    print("Do NOT update yet. Reopen official Wonhee, select BOTH profiles,")
    print("and run its existing Safe Stop. Report any refusal before taking other action.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Refuse, OSError, UnicodeDecodeError) as err:
        print("RESCUE REFUSED: " + str(err), file=sys.stderr)
        raise SystemExit(1)
