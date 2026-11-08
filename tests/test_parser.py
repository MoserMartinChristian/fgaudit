import unittest

import helpers  # noqa: F401  (sets sys.path)

from fgaudit.model import InputError, load_config
from fgaudit.parser import parse


class ParserTests(unittest.TestCase):
    def test_nested_blocks_quotes_escapes(self):
        text = (
            'config firewall address\n'
            '    edit "web \\"A\\""\n'
            '        set comment "a \\\\ backslash and \'single\' quote"\n'
            '        set subnet 10.0.0.1 255.255.255.255\n'
            '    next\n'
            'end\n'
            'config system sdwan\n'
            '    set status enable\n'
            '    config members\n'
            '        edit 1\n'
            '            set interface "port1"\n'
            '        next\n'
            '    end\n'
            'end\n'
        )
        pr = parse(text)
        self.assertEqual(pr.warnings, [])
        e = pr.root.children["firewall address"].entries['web "A"']
        self.assertEqual(e.get("comment"), "a \\ backslash and 'single' quote")
        self.assertEqual(e.get_list("subnet"), ["10.0.0.1", "255.255.255.255"])
        sd = pr.root.children["system sdwan"]
        self.assertEqual(sd.get("status"), "enable")
        self.assertEqual(sd.children["members"].entries["1"].get("interface"), "port1")

    def test_multiline_certificate_and_unset(self):
        text = (
            "config vpn certificate local\n"
            '    edit "c1"\n'
            '        set certificate "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----"\n'
            '        set comments "x"\n'
            "        unset comments\n"
            "    next\n"
            "end\n"
        )
        pr = parse(text)
        e = pr.root.children["vpn certificate local"].entries["c1"]
        self.assertIn("\nBBBB\n", e.get("certificate"))
        self.assertIsNone(e.get("comments"))
        self.assertEqual(pr.warnings, [])

    def test_crlf_bom_tabs(self):
        data = "﻿#config-version=FGVM64-7.6.4-FW-build1-260101:opmode=0:vdom=0:user=admin\r\nconfig system global\r\n\tset hostname \"fw\"\r\nend\r\n".encode("utf-8")
        fc = load_config(data, "x.conf")
        self.assertEqual(fc.version, (7, 6, 4))
        self.assertEqual(fc.global_root.children["system global"].get("hostname"), "fw")

    def test_unknown_sections_kept(self):
        pr = parse("config system brand-new-thing\n    set foo bar baz\nend\n")
        self.assertEqual(pr.root.children["system brand-new-thing"].get_list("foo"), ["bar", "baz"])

    def test_vdom_sections_end_without_next(self):
        text = (
            "#config-version=FGVM64-8.0.2-FW-build1-260101:opmode=0:vdom=1:user=admin\n"
            "config vdom\nedit root\nnext\nedit second\nnext\nend\n"
            "config global\nconfig system interface\n    edit \"port1\"\n        set vdom \"root\"\n    next\nend\nend\n"
            "config vdom\nedit root\nconfig firewall policy\n    edit 1\n        set action accept\n    next\nend\nend\n"
            "config vdom\nedit second\nconfig firewall policy\n    edit 7\n    next\nend\nend\n"
        )
        fc = load_config(text.encode(), "v.conf")
        self.assertTrue(fc.vdom_mode)
        self.assertEqual(sorted(fc.vdoms), ["root", "second"])
        self.assertIn("1", fc.vdoms["root"].table("firewall policy").entries)
        self.assertIn("7", fc.vdoms["second"].table("firewall policy").entries)
        self.assertEqual(fc.warnings, [])

    def test_truncated_and_garbage(self):
        pr = parse("config firewall policy\n    edit 1\n        set srcintf \"port1\n")
        codes = {w.code for w in pr.warnings}
        self.assertIn("unterminated-quote", codes)
        self.assertIn("unclosed-blocks", codes)
        pr = parse("end\nnext\nset x y\nfoo bar\n")
        self.assertTrue(pr.warnings)

    def test_warnings_never_contain_content(self):
        pr = parse("config system admin\n    edit admin\n        set password ENC SECRETSECRET\n    bogus ENC SECRETSECRET\nend\nend\n")
        for w in pr.warnings:
            self.assertNotIn("SECRET", str(w.detail) + w.code)
        self.assertIn("SECRETSECRET", " ".join(pr.secret_values))

    def test_encrypted_and_binary(self):
        with self.assertRaises(InputError) as cm:
            load_config(b"#config-version=FGT60F-7.4.4-FW-build1-1:opmode=0:vdom=0:user=admin\n" + bytes(range(256)) * 20, "e.conf")
        self.assertEqual(cm.exception.code, "encrypted-backup")
        with self.assertRaises(InputError) as cm:
            load_config(b"#config-version=FGT60F-7.4.4-FW-build1-1:opmode=0:vdom=0:user=admin\nU2FsdGVkX19hYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==\n", "e2.conf")
        self.assertEqual(cm.exception.code, "encrypted-backup")
        with self.assertRaises(InputError) as cm:
            load_config(b"\x89PNG\r\n\x1a\n\x00\x00", "x.png")
        self.assertEqual(cm.exception.code, "binary-file")

    def test_version_detection(self):
        for v in ("7.4.8", "7.6.4", "8.0.2", "7.2.9", "9.1.0"):
            fc = load_config(f"#config-version=FGVM64-{v}-FW-build1-260101:opmode=0:vdom=0:user=a\nconfig system global\nend\n".encode(), "x")
            self.assertEqual(fc.version_str, v)
            self.assertEqual(fc.supported, v.startswith(("7.4", "7.6", "8.0")))


if __name__ == "__main__":
    unittest.main()
