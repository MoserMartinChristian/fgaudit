"""Tests for the window. The logic tests need no display; the window smoke test
runs only where tkinter and a display are available (e.g. xvfb-run)."""

import os
import tempfile
import unittest

import helpers  # noqa: F401  (sets sys.path)
from test_safety import ENC_RE, secrets_in, with_plain_secrets

from fgaudit import synth
from fgaudit.cli import build_report, exit_code_for
from fgaudit.gui import detect_mode, finding_detail, timeline_rows, tr, T
from fgaudit.model import InputError


def _write(tmp, name, text):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return p


def _have_display():
    try:
        import tkinter as tk

        r = tk.Tk()
        r.destroy()
        return True
    except Exception:
        return False


class GuiLogicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="fgaudit-gui-")
        d = synth.demo_inputs()
        cls.conf = _write(cls.tmp, "fw.conf", d["audit"][1])
        cls.before = _write(cls.tmp, "before.conf", d["before"][1])
        cls.after = _write(cls.tmp, "after.conf", d["after"][1])
        cls.logs = [_write(cls.tmp, n, t) for n, t in d["logs"].items()]
        cls.other = _write(cls.tmp, "notes.txt", "just some notes\n")

    def test_mode_hint(self):
        self.assertEqual(detect_mode([]), "none")
        self.assertEqual(detect_mode([self.conf]), "audit")
        self.assertEqual(detect_mode([self.before, self.after]), "change")
        self.assertEqual(detect_mode([self.conf, self.before, self.after]), "toomany")
        self.assertEqual(detect_mode(self.logs), "timeline")
        self.assertEqual(detect_mode([self.conf] + self.logs), "mixed")
        self.assertEqual(detect_mode([self.other]), "unknown:notes.txt")
        self.assertEqual(detect_mode([os.path.join(self.tmp, "missing.conf")]), "unknown:missing.conf")

    def test_same_result_as_cli(self):
        rc, rep_json, _ = helpers.run_json(self.conf)
        rep = build_report([self.conf])
        self.assertEqual([f.code for f in rep.sorted_findings()], [f["code"] for f in rep_json["findings"]])
        self.assertEqual(exit_code_for(rep), rc)

    def test_errors_are_input_errors(self):
        with self.assertRaises(InputError) as cm:
            build_report([self.other])
        self.assertEqual(cm.exception.code, "not-a-config")
        with self.assertRaises(InputError) as cm:
            build_report([self.conf] + self.logs)
        self.assertEqual(cm.exception.code, "mixed-inputs")
        with self.assertRaises(InputError) as cm:
            build_report([])
        self.assertEqual(cm.exception.code, "no-input")

    def test_detail_and_timeline_texts(self):
        rep = build_report(self.logs, lang="de")
        rows = timeline_rows(rep, "de")
        self.assertTrue(any("401" in r["count"] for r in rows))
        f = rep.sorted_findings()[0]
        self.assertIn("Nächster Schritt", finding_detail(f, "de"))

    def test_no_secrets_in_window_texts(self):
        c, _, _ = synth.faulty_config("7.6")
        text = with_plain_secrets(c).render()
        p = _write(self.tmp, "secret.conf", text)
        secrets = secrets_in(text)
        for anon in (False, True):
            rep = build_report([p], anonymize=anon)
            shown = "\n".join(finding_detail(f, "en") for f in rep.all_findings())
            for s in secrets:
                self.assertNotIn(s, shown)
            self.assertIsNone(ENC_RE.search(shown))

    def test_all_window_texts_translated(self):
        self.assertEqual(set(T["en"]), set(T["de"]))
        self.assertIn("{file}", tr("de", "hint.unknown"))


@unittest.skipUnless(_have_display(), "tkinter or display not available")
class GuiWindowTests(unittest.TestCase):
    def test_window_runs_demo_and_check(self):
        import time
        import tkinter as tk

        from fgaudit.gui import App

        d = synth.demo_inputs()
        tmp = tempfile.mkdtemp(prefix="fgaudit-gui-")
        conf = _write(tmp, "fw.conf", d["audit"][1])
        root = tk.Tk()
        try:
            app = App(root, lang="en", files=[conf])
            self.assertIn("audit", app.hint.cget("text"))
            for demo in (False, True):
                app.report = None
                app.run(demo=demo)
                end = time.time() + 60
                while app.report is None and time.time() < end:
                    root.update()
                    time.sleep(0.02)
                self.assertIsNotNone(app.report)
                self.assertTrue(app.findings_by_iid)
                self.assertEqual(str(app.html_btn.cget("state")), "normal")
            app.set_lang("de")  # re-runs in German
            end = time.time() + 60
            while str(app.run_btn.cget("state")) == "disabled" and time.time() < end:
                root.update()
                time.sleep(0.02)
            while app.results.qsize():
                root.update()
            self.assertEqual(app.report_lang, "de")
            self.assertIn("Prüfen", app.run_btn.cget("text"))
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
