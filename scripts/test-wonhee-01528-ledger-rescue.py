#!/usr/bin/env python3
"""Synthetic fixture tests for the opt-in 0.15.28 root metadata rescue."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).parent / "wonhee-01528-ledger-rescue.py"
spec = importlib.util.spec_from_file_location("wonhee_01528_rescue", SCRIPT)
rescue = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rescue)


class RescueLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.file = Path(self.tmp.name) / "wonhee_owned_split_routes.xml"
        self.old_path = rescue.FILE
        rescue.FILE = self.file
        self.addCleanup(setattr, rescue, "FILE", self.old_path)
        self.lines = [
            "4|12500|10.0.0.0/24|wnma292ddb4b6da|10.0.0.1|0x0/0x20000",
            "4|12501|10.6.0.0/24|wnma292ddb4b6da|10.6.0.1|0x0/0x20000",
            "4|12502|10.77.0.0/24|wnma292ddb4b6da|10.77.0.1|0x0/0x20000",
        ]

    def write(self, lines=None, padding="\n    ", lf_entity=None):
        lines = self.lines if lines is None else lines
        payload = "\n".join(lines) + padding
        if lf_entity is not None:
            payload = payload.replace("\n", lf_entity)
        text = ('<?xml version="1.0" encoding="utf-8"?>\n<map>\n'
                '<string name="pending_or_installed_rules_v1">'
                + payload + '</string>\n</map>')
        self.file.write_bytes(text.encode("utf-8"))
        return self.file.read_bytes()

    def test_exact_4_space_padding_is_removable_and_no_other_bytes_change(self):
        before = self.write()
        actual, after = rescue.inspect_ledger()
        self.assertEqual(actual, before)
        self.assertEqual(len(before) - len(after), 4)
        self.assertEqual(after, before.replace(
            b"\n    </string>", b"\n</string>"))
        self.assertEqual(self.file.read_bytes(), before,
                         "Read-only parser must not write live data")

    def test_android_xml_numeric_newline_escaped_representation(self):
        # Android XmlSerializer commonly serializes LF as &#10;. The decoded
        # SharedPreferences value still contains real newlines, whereas the
        # original rescue tool mistakenly compared the literal XML bytes.
        before = self.write(lf_entity="&#10;")
        actual, after = rescue.inspect_ledger()
        self.assertEqual(actual, before)
        self.assertEqual(len(before) - len(after), 4)
        self.assertEqual(after, before.replace(
            b"&#10;    </string>", b"&#10;</string>"))
        self.assertEqual(self.file.read_bytes(), before,
                         "Preflight must never modify preferences")

    def test_hex_numeric_newline_representation(self):
        before = self.write(lf_entity="&#xA;")
        actual, after = rescue.inspect_ledger()
        self.assertEqual(actual, before)
        self.assertEqual(len(before) - len(after), 4)

    def test_alternate_hex_numeric_lf_escaped_representation(self):
        before = self.write(lf_entity="&#x0A;")
        actual, after = rescue.inspect_ledger()
        self.assertEqual(actual, before)
        self.assertEqual(len(before) - len(after), 4)

    def test_entity_with_no_padding_refuses(self):
        self.write(padding="\n", lf_entity="&#10;")
        with self.assertRaises(rescue.Refuse):
            rescue.inspect_ledger()

    def test_no_whitespace_padding_refuses(self):
        self.write(padding="\n")
        with self.assertRaises(rescue.Refuse):
            rescue.inspect_ledger()

    def test_unexpected_padding_refuses(self):
        self.write(padding="\n   ")
        with self.assertRaises(rescue.Refuse):
            rescue.inspect_ledger()

    def test_unknown_route_refuses(self):
        lines = list(self.lines)
        lines[2] = lines[2].replace("10.77.0.0/24", "10.99.0.0/24")
        self.write(lines=lines)
        with self.assertRaises(rescue.Refuse):
            rescue.inspect_ledger()

    def test_unknown_table_refuses(self):
        lines = list(self.lines)
        lines[0] = lines[0].replace("wnma292ddb4b6da", "wlan0")
        self.write(lines=lines)
        with self.assertRaises(rescue.Refuse):
            rescue.inspect_ledger()

    def test_extra_record_refuses(self):
        lines = list(self.lines)
        lines.append(lines[-1])
        self.write(lines=lines)
        with self.assertRaises(rescue.Refuse):
            rescue.inspect_ledger()

    def test_unexpected_probe_refuses(self):
        lines = list(self.lines)
        lines[0] = lines[0].replace("10.0.0.1", "10.0.0.0")
        self.write(lines=lines)
        with self.assertRaises(rescue.Refuse):
            rescue.inspect_ledger()

    def test_malformed_xml_refuses(self):
        self.file.write_text('<map><string name="pending_or_installed_rules_v1">broken')
        with self.assertRaises(rescue.Refuse):
            rescue.inspect_ledger()


if __name__ == "__main__":
    unittest.main()
