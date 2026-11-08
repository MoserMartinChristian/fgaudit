import json
import os
import random
import re
import unittest

import helpers
from helpers import run_cli, run_json

from fgaudit import synth
from fgaudit.synth import FAKE_KEY, clean_config, faulty_config, policy

ENC_RE = re.compile(r"ENC [A-Za-z0-9+/=]+")
IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!\.?\d)")


def secrets_in(text):
    out = set(ENC_RE.findall(text))
    out |= {m.split(" ", 1)[1] for m in out}
    for line in FAKE_KEY.splitlines()[1:-1]:
        out.add(line)
    out.add("PlainTextSecret123")
    out.add("AnotherPlainSecret9")
    return out


def all_outputs(*args, files):
    """text (en+de), json, html, with and without --anonymize"""
    outs = []
    for extra in ([], ["--anonymize"]):
        for lang in ("en", "de"):
            rc, out, err, tmp = run_cli(*args, "--lang", lang, "--html", "{tmp}/r.html", *extra, files=files)
            outs.append(out + err)
            with open(os.path.join(tmp, "r.html"), encoding="utf-8") as fh:
                outs.append(fh.read())
            rc, out, err, tmp = run_cli(*args, "--json", "--lang", lang, *extra, files=files)
            outs.append(out + err)
    return outs


def with_plain_secrets(c):
    c.t("vpn ipsec phase1-interface").edit("to-hub").set("psksecret", "PlainTextSecret123")
    c.t("user local").edit("alice").set("passwd", "AnotherPlainSecret9")
    return c


class SecretTests(unittest.TestCase):
    def test_no_secret_in_any_output(self):
        c, _, _ = faulty_config("7.6")
        text = with_plain_secrets(c).render()
        secrets = secrets_in(text)
        self.assertGreater(len(secrets), 5)
        for out in all_outputs("a.conf", files={"a.conf": text}):
            for s in secrets:
                self.assertNotIn(s, out)
            self.assertNotIn("PRIVATE KEY", out)
            self.assertIsNone(ENC_RE.search(out))

    def test_no_secret_in_change_output(self):
        b = with_plain_secrets(clean_config("8.0", salt="x"))
        a = clean_config("8.0", salt="y")
        a.t("vpn ipsec phase1-interface").edit("to-hub").set("psksecret", "ChangedPlainSecret77")
        before, after = b.render(), a.render()
        secrets = secrets_in(before) | secrets_in(after) | {"ChangedPlainSecret77"}
        for out in all_outputs("b.conf", "a.conf", files={"b.conf": before, "a.conf": after}):
            for s in secrets:
                self.assertNotIn(s, out)

    def test_no_secret_in_error_messages(self):
        text = "#config-version=FGVM64-7.4.8-FW-build1-260101:opmode=0:vdom=0:user=admin\n" + "set psksecret ENC c2VjcmV0c2VjcmV0c2VjcmV0\n" * 3
        rc, out, err, _ = run_cli("x.conf", files={"x.conf": text})
        self.assertNotIn("c2VjcmV0", out + err)
        enc = b"#config-version=FGVM64-7.4.8-FW-build1-260101:opmode=0:vdom=0:user=admin\n" + os.urandom(2048)
        rc, out, err, _ = run_cli("enc.conf", files={"enc.conf": enc})
        self.assertEqual(rc, 2)
        self.assertIn("unencrypted", err)


class AnonymizeTests(unittest.TestCase):
    def _names(self, c):
        names = set()
        for vd in c.vd.values():
            for path, t in vd.children:
                if path in ("firewall address", "firewall addrgrp", "firewall vip", "firewall ippool", "vpn ipsec phase1-interface",
                            "vpn ipsec phase2-interface", "user local", "user group", "system zone", "firewall service custom"):
                    for k, _ in t.entries:
                        if k not in ("all", "none") and not str(k).isupper():
                            names.add(str(k))
            for k, n in vd.sub("firewall policy").entries:
                if n.get("name"):
                    names.add(str(n.get("name")))
        names |= {"fw-demo-01", "netops", "alice"}
        return names

    def test_anonymize_removes_ips_and_names(self):
        c, _, _ = faulty_config("8.0")
        text = c.render()
        ips = {ip for ip in IP_RE.findall(text) if not ip.startswith(("255.", "0.0.0.0"))}
        names = self._names(c)
        self.assertGreater(len(ips), 20)
        outs = []
        for lang in ("en", "de"):
            rc, out, err, tmp = run_cli("customer-site.conf", "--anonymize", "--lang", lang, "--html", "{tmp}/r.html", files={"customer-site.conf": text})
            outs.append(out)
            outs.append(helpers.read_text(os.path.join(tmp, "r.html")))
            rc, out, err, tmp = run_cli("customer-site.conf", "--anonymize", "--json", "--lang", lang, files={"customer-site.conf": text})
            outs.append(out)
            self.assertTrue(json.loads(out)["anonymized"])
        for out in outs:
            found_ips = {ip for ip in IP_RE.findall(out)} & ips
            self.assertEqual(found_ips, set())
            for n in names:
                self.assertIsNone(re.search(r"(?<![\w-])" + re.escape(n) + r"(?![\w-])", out), f"name {n!r} leaked")
            self.assertNotIn("customer-site", out)

    def test_anonymize_logs(self):
        files, _ = synth.incident_logs("7.6")
        allt = "".join(files.values())
        ips = {ip for ip in IP_RE.findall(allt)}
        names = {"fw-branch-01", "fw-hub-01", "fw-lab-01", "netops", "to-hub", "branch-01", "FGVMDEMO00000001", "internet"}
        rc, out, err, tmp = run_cli(*files.keys(), "--anonymize", "--json", files=files)
        rc2, out2, err2, tmp2 = run_cli(*files.keys(), "--anonymize", "--html", "{tmp}/r.html", files=files)
        html = helpers.read_text(os.path.join(tmp2, "r.html"))
        for o in (out, out2, html):
            self.assertEqual(set(IP_RE.findall(o)) & ips, set())
            for n in names:
                self.assertIsNone(re.search(r"(?<![\w-])" + re.escape(n) + r"(?![\w-])", o), n)

    def test_anonymize_is_consistent(self):
        c, _, _ = faulty_config("7.4")
        rc, rep, err = run_json("a.conf", "--anonymize", files={"a.conf": c.render()})
        f = [x for x in rep["findings"] if x["code"] == "overlap.interface"][0]
        # same object -> same replacement in params and detail
        self.assertIn(f["params"]["a_name"], f["detail"])
        self.assertIn(f["params"]["overlap"].split("/")[0], f["detail"])


class RobustnessTests(unittest.TestCase):
    def test_mutated_inputs_never_crash(self):
        rnd = random.Random(42)
        c, _, _ = faulty_config("7.6", vdom_mode=True)
        base = c.render()
        logs, _ = synth.incident_logs("8.0")
        samples = [base, logs["branch-01.log"]]
        n = 0
        for s in samples:
            lines = s.split("\n")
            for i in range(40):
                kind = i % 8
                if kind == 0:
                    m = s[: rnd.randint(0, len(s))]
                elif kind == 1:
                    ls = list(lines)
                    for _ in range(rnd.randint(1, 30)):
                        if ls:
                            ls.pop(rnd.randrange(len(ls)))
                    m = "\n".join(ls)
                elif kind == 2:
                    b = bytearray(s.encode())
                    for _ in range(rnd.randint(1, 50)):
                        b[rnd.randrange(len(b))] = rnd.randrange(256)
                    m = bytes(b)
                elif kind == 3:
                    m = s.replace('"', "", rnd.randint(1, 20))
                elif kind == 4:
                    m = s.replace("end\n", "end\nend\n", rnd.randint(1, 5)).replace("next\n", "", rnd.randint(1, 5))
                elif kind == 5:
                    m = "﻿" + s.replace("\n", "\r", rnd.randint(1, 100))
                elif kind == 6:
                    m = s + "\n" + "x" * 200000 + "\nconfig\nedit\nset\n" + "\x00" * 10
                else:
                    m = "".join(rnd.choice(' "\\\nabc=edit set config end next 10.0.0.1/24') for _ in range(3000))
                rc, out, err, _ = run_cli("m.conf", files={"m.conf": m})
                self.assertIn(rc, (0, 1, 2))
                if rc == 2:
                    self.assertTrue(err.startswith("fgaudit: "))
                n += 1
        self.assertEqual(n, 80)

    def test_special_inputs(self):
        cases = {"empty.conf": b"", "bom.conf": b"\xef\xbb\xbf", "nul.conf": b"\x00" * 100, "text.txt": b"hello world\n", "utf16.conf": "config system global\nend\n".encode("utf-16")}
        for name, data in cases.items():
            rc, out, err, _ = run_cli(name, files={name: data})
            self.assertIn(rc, (0, 1, 2), name)
        rc, out, err, _ = run_cli("does-not-exist.conf")
        self.assertEqual(rc, 2)


class OutputTests(unittest.TestCase):
    def test_html_escaping(self):
        c = clean_config("7.6")
        c.t("firewall address").edit('<script>alert("x")</script>').set("subnet", ["10.10.0.5", "255.255.255.255"])
        policy(c, 99, name='evil"&<b>', srcintf=["port2"], dstintf=["port1"], srcaddr=['<script>alert("x")</script>'], dstaddr=["all"], service=["HTTPS"], action="deny")
        rc, out, err, tmp = run_cli("x.conf", "--html", "{tmp}/r.html", files={"x.conf": c.render()})
        html = helpers.read_text(os.path.join(tmp, "r.html"))
        self.assertNotIn("<script>alert", html)
        self.assertNotIn('evil"&<b>', html)
        self.assertIn("evil&quot;&amp;&lt;b&gt;", html)
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("prefers-color-scheme:dark", html)
        self.assertNotIn("<script", html)
        self.assertNotRegex(html, r'(src|href)="https?:')

    def test_json_schema_stable(self):
        c, _, _ = faulty_config("8.0")
        rc, rep, err = run_json("a.conf", files={"a.conf": c.render()})
        self.assertEqual(rep["schema"], "fgaudit/report@1")
        for k in ("tool", "mode", "lang", "anonymized", "inputs", "summary", "findings", "notices", "stats", "timeline"):
            self.assertIn(k, rep)
        self.assertEqual(rep["summary"]["exit_code"], rc)
        for f in rep["findings"]:
            self.assertEqual(set(f), {"id", "check", "code", "severity", "vdom", "title", "detail", "next_step", "objects", "params"})
            self.assertIn(f["severity"], ("high", "medium", "low", "info"))
            self.assertTrue(f["next_step"])
        sev = [f["severity"] for f in rep["findings"]]
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        self.assertEqual(sev, sorted(sev, key=order.get))

    def test_exit_codes_and_modes(self):
        good = clean_config("7.4").render()
        bad, _, _ = faulty_config("7.4")
        self.assertEqual(run_cli("a.conf", files={"a.conf": good})[0], 0)
        self.assertEqual(run_cli("a.conf", files={"a.conf": bad.render()})[0], 1)
        self.assertEqual(run_cli("a.conf", "b.conf", "c.conf", files={"a.conf": good, "b.conf": good, "c.conf": good})[0], 2)
        logs, _ = synth.incident_logs("7.4")
        self.assertEqual(run_cli("a.conf", "l.log", files={"a.conf": good, "l.log": logs["branch-01.log"]})[0], 2)
        self.assertEqual(run_cli("a.conf", "--vdom", "nope", files={"a.conf": good})[0], 2)
        self.assertEqual(run_cli()[0], 2)
        rc, out, err, _ = run_cli("--demo")
        self.assertEqual(rc, 0)
        for word in ("Configuration audit", "Change review", "Incident timeline"):
            self.assertIn(word, out)

    def test_vdom_filter(self):
        c = clean_config("8.0", vdom_mode=True)
        policy(c, 2, "dmz-vd", name="dup", srcintf=["port4"], dstintf=["port5"], srcaddr=["dmz2-net"], dstaddr=["lab-net"], service=["HTTPS"])
        text = c.render()
        rc, rep, err = run_json("a.conf", "--vdom", "root", files={"a.conf": text})
        self.assertEqual(rc, 0)
        rc, rep, err = run_json("a.conf", "--vdom", "dmz-vd", files={"a.conf": text})
        self.assertEqual(rc, 1)
        self.assertEqual({f["vdom"] for f in rep["findings"]}, {"dmz-vd"})

    def test_german(self):
        rc, out, err, _ = run_cli("--demo", "--lang", "de")
        for word in ("ZUSAMMENFASSUNG", "BEFUNDE", "Nächster Schritt", "Vermutung, kein Beweis"):
            self.assertIn(word, out)

    def test_unknown_version_warns_and_continues(self):
        text = clean_config("7.6").render().replace("7.6.4-FW", "7.2.10-FW", 1)
        rc, out, err, _ = run_cli("a.conf", files={"a.conf": text})
        self.assertEqual(rc, 0)
        self.assertIn("WARNING", out)
        text = "\n".join(l for l in clean_config("7.6").render().split("\n") if not l.startswith("#"))
        rc, out, err, _ = run_cli("a.conf", files={"a.conf": text})
        self.assertEqual(rc, 0)
        self.assertIn("version not found", out)

    def test_never_overwrites_inputs(self):
        good = clean_config("7.4").render()
        rc, out, err, tmp = run_cli("a.conf", "--html", "a.conf", files={"a.conf": good})
        self.assertEqual(rc, 2)
        self.assertEqual(helpers.read_text(os.path.join(tmp, "a.conf")), good)
        rc, out, err, tmp = run_cli("a.conf", "--html", "b.conf", files={"a.conf": good, "b.conf": "keep me"})
        self.assertEqual(rc, 2)
        self.assertEqual(helpers.read_text(os.path.join(tmp, "b.conf")), "keep me")
        rc, out, err, tmp = run_cli("a.conf", "--html", "{tmp}/r.html", files={"a.conf": good})
        self.assertEqual(rc, 0)

    def test_wildcards_expanded(self):
        files, _ = synth.incident_logs("7.6")
        rc, out, err, tmp = run_cli("*.log", files={})
        self.assertEqual(rc, 2)
        rc, out, err, tmp = run_cli(files=files)
        rc, rep, err = run_json(os.path.join(tmp, "*.log"))
        self.assertEqual(len(rep["inputs"]), 3)

    def test_no_color_without_tty(self):
        rc, out, err, _ = run_cli("--demo")
        self.assertNotIn("\033[", out)


if __name__ == "__main__":
    unittest.main()
