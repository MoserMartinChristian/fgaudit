import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

if not os.environ.get("FGAUDIT_TEST_INSTALLED"):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
os.environ["FGAUDIT_DEBUG"] = "1"  # crashes must fail the tests, not be hidden
os.environ.pop("FORCE_COLOR", None)

from fgaudit.cli import main  # noqa: E402


def run_cli(*args, files=None):
    """Run fgaudit in-process. files: {name: str|bytes}. Returns (rc, stdout, stderr, paths)."""
    tmp = tempfile.mkdtemp(prefix="fgaudit-test-")
    paths = {}
    for name, content in (files or {}).items():
        p = os.path.join(tmp, name)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(p, mode, **({} if isinstance(content, bytes) else {"encoding": "utf-8", "newline": ""})) as fh:
            fh.write(content)
        paths[name] = p
    argv = [paths.get(a, a) if isinstance(a, str) else a for a in args]
    argv = [a.replace("{tmp}", tmp) for a in argv]
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue(), tmp


def run_json(*args, files=None):
    rc, out, err, tmp = run_cli(*args, "--json", files=files)
    return rc, json.loads(out) if out.strip() else None, err


def finding_keys(report):
    out = set()
    for f in report["findings"]:
        out.add((f["code"], tuple(o.get("id") or o["name"] for o in f["objects"])))
    return out


def read_text(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()
