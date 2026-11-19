#!/usr/bin/env python3
"""Read-only offline validation of Wonhee isolated start ownership XML.

Accept ONLY an empty/absent exact ownership record as upgrade-safe. A
corrupted, unexpected, or nonempty record means the installer must refuse.
Never delete, repair, or print an application's other SharedPreferences.
"""
import sys
import xml.etree.ElementTree as ET

ALLOWED_KEYS = ("pending_or_installed_steps_v1",
                "pending_or_installed_uid_rules_v1")

def check(path: str, key: str = ALLOWED_KEYS[0]) -> bool:
    if key not in ALLOWED_KEYS:
        print("ISOLATED JOURNAL UNKNOWN: invalid ownership selector", file=sys.stderr)
        return False
    try:
        root = ET.parse(path).getroot()
        if root.tag != "map":
            raise ValueError("Unexpected prefs document.")
        fields = [item for item in root if item.get("name") == key]
        if len(fields) != 1 or fields[0].tag != "string":
            raise ValueError("Missing or duplicated ownership field.")
        if fields[0].text:
            print("ISOLATED JOURNAL PENDING: exact-owned recovery required", file=sys.stderr)
            return False
        print("ISOLATED JOURNAL CLEAN")
        return True
    except (OSError, ET.ParseError, ValueError) as invalid:
        print("ISOLATED JOURNAL UNKNOWN: refuse update", file=sys.stderr)
        return False

if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print("Usage: check-wonhee-isolated-ledger.py <xml-file> [ownership-key]", file=sys.stderr)
        sys.exit(2)
    key = sys.argv[2] if len(sys.argv) == 3 else ALLOWED_KEYS[0]
    sys.exit(0 if check(sys.argv[1], key) else 1)
