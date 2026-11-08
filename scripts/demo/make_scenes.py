"""Build the scenes for the demo GIF from the built-in made-up demo data.

Writes the synthetic demo inputs to a temporary folder, runs fgaudit on them
with colour forced on, and stores each scene (command + output as HTML) in
scenes.json. render_frames.js then turns the scenes into PNG frames.
No real data is involved."""

import html
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fgaudit import synth  # noqa: E402

SGR = {"1": "b", "2": "dim", "31": "red", "32": "green", "33": "yellow", "36": "cyan", "37": "white", "44": "bgblue"}


def ansi_to_html(text):
    out, cls = [], []
    for part in re.split(r"(\x1b\[[0-9;]*m)", text):
        m = re.fullmatch(r"\x1b\[([0-9;]*)m", part)
        if m:
            codes = [c for c in m.group(1).split(";") if c]
            if not codes or "0" in codes:
                cls = []
            cls += [SGR[c] for c in codes if c in SGR]
            continue
        if part:
            esc = html.escape(part)
            out.append(f'<span class="{" ".join(cls)}">{esc}</span>' if cls else esc)
    return "".join(out)


def run(args, cwd):
    env = dict(os.environ, FORCE_COLOR="1", COLUMNS="100", PYTHONPATH=os.path.join(ROOT, "src"))
    env.pop("NO_COLOR", None)
    p = subprocess.run([sys.executable, "-m", "fgaudit", *args], cwd=cwd, env=env, capture_output=True, text=True)
    return [ansi_to_html(line) for line in p.stdout.splitlines()]


def main():
    d = synth.demo_inputs()
    with tempfile.TemporaryDirectory() as tmp:
        files = {"fw-branch.conf": d["audit"][1], "before.conf": d["before"][1], "after.conf": d["after"][1]}
        files.update(d["logs"])
        for name, text in files.items():
            with open(os.path.join(tmp, name), "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
        logs = sorted(d["logs"])
        scenes = [
            {"cmd": "fgaudit fw-branch.conf", "lines": run(["fw-branch.conf"], tmp), "show": "top", "hold": 65},
            {"cmd": "fgaudit before.conf after.conf", "lines": run(["before.conf", "after.conf"], tmp), "show": "top", "hold": 65},
            {"cmd": "fgaudit " + " ".join(logs), "lines": run(logs, tmp), "show": "timeline", "hold": 90},
        ]
    with open(os.path.join(HERE, "scenes.json"), "w", encoding="utf-8") as fh:
        json.dump(scenes, fh)
    print("scenes.json written")


if __name__ == "__main__":
    main()
