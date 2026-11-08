"""Command line entry point. One command; the mode follows from the inputs:

    fgaudit backup.conf                 audit (shadowed policies, IP overlaps)
    fgaudit before.conf after.conf      change review
    fgaudit logs.txt [more.log ...]     incident timeline
    fgaudit --demo                      everything with built-in made-up data
    fgaudit --gui                       the same checks in a window (also: fgaudit-gui)

Exit codes: 0 no findings, 1 findings, 2 error.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, Sequence, Tuple

from . import __version__
from .checks import change as change_check
from .checks import overlap as overlap_check
from .checks import shadow as shadow_check
from .checks import timeline as timeline_check
from .findings import SEV_RANK, Notice, Report
from .i18n import error_text, localize, localize_notice, ui
from .logs import parse_lines
from .model import FortiConfig, InputError, is_config_text, is_log_text, load_config, looks_binary
from .parser import decode_bytes
from .privacy import Anonymizer, Redactor, collect_config_names, collect_log_names, transform
from .render import render_html, render_json, render_text, use_color

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _max_bytes() -> int:
    try:
        return int(float(os.environ.get("FGAUDIT_MAX_MB", "512")) * 1024 * 1024)
    except ValueError:
        return 512 * 1024 * 1024


class Ctx:
    def __init__(self, lang: str):
        self.lang = lang
        self.secrets: List[str] = []
        self.configs: List[FortiConfig] = []
        self.log_events: list = []
        self.log_sources: List[str] = []


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fgaudit",
        description="Offline, read-only audit of FortiOS config backups and logs. Unofficial, not affiliated with or endorsed by Fortinet.",
        epilog="Examples: fgaudit backup.conf | fgaudit before.conf after.conf | fgaudit fw1.log fw2.log | fgaudit --demo | fgaudit --gui",
    )
    p.add_argument("files", nargs="*", help="one config, two configs (before after), or log files")
    p.add_argument("--demo", action="store_true", help="run all checks on built-in made-up data")
    p.add_argument("--vdom", metavar="NAME", help="check only this VDOM")
    p.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report")
    p.add_argument("--json", action="store_true", help="print JSON instead of text (redirect with > report.json)")
    p.add_argument("--anonymize", action="store_true", help="replace IPs, host, user and object names consistently")
    p.add_argument("--gui", action="store_true", help="open the graphical window instead (same checks)")
    p.add_argument("--lang", choices=("en", "de"), default=os.environ.get("FGAUDIT_LANG", "en"), help="output language (default: en)")
    p.add_argument("--version", action="version", version=f"fgaudit {__version__}")
    return p


def _err(lang: str, code: str, **params) -> int:
    sys.stderr.write("fgaudit: " + error_text(lang, code, **params) + "\n")
    return EXIT_ERROR


def read_input(path: str) -> bytes:
    """Read one input file. Raises InputError (never file content in the message)."""
    label = os.path.basename(path)
    try:
        size = os.path.getsize(path)
        if size > _max_bytes():
            raise InputError("too-large", file=label, limit=_max_bytes() // (1024 * 1024))
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as e:
        raise InputError("unreadable", file=label, reason=e.strerror or type(e).__name__)


def classify_input(data: bytes) -> str:
    text = decode_bytes(data[:200000])
    if is_log_text(text):
        return "log"  # logs may contain a few broken or binary lines
    if looks_binary(data):
        return "config"  # load_config produces the right error (encrypted/binary)
    if is_config_text(text):
        return "config"
    if "#config-version=" in text[:400]:
        return "config"
    return "unknown"


# --------------------------------------------------------------------------- #


def _config_input(fc: FortiConfig, vdoms: List[str]) -> dict:
    return {
        "kind": "config",
        "file": fc.filename,
        "model": fc.model,
        "version": fc.version_str,
        "supported": fc.supported,
        "vdom_mode": fc.vdom_mode,
        "vdoms": vdoms,
        "policies": sum(len(fc.vdoms[v].table("firewall policy")) for v in vdoms),
    }


def _version_notices(fc: FortiConfig) -> List[Notice]:
    out = []
    if fc.version is None:
        out.append(Notice("version-unknown", {"file": fc.filename}))
    elif not fc.supported:
        out.append(Notice("version-unsupported", {"file": fc.filename, "version": fc.version_str}))
    if fc.warnings:
        w = fc.warnings[0]
        out.append(Notice("parse-warnings", {"file": fc.filename, "count": len(fc.warnings), "line": w.line, "code": w.code}))
    return out


def _select_vdoms(fc: FortiConfig, vdom: Optional[str], lang: str) -> List[str]:
    if vdom:
        if vdom not in fc.vdoms:
            raise InputError("vdom-missing", vdom=vdom, available=", ".join(fc.vdoms))
        return [vdom]
    return list(fc.vdoms)


def audit(fc: FortiConfig, vdom: Optional[str], lang: str) -> Report:
    vds = _select_vdoms(fc, vdom, lang)
    rep = Report(mode="audit")
    rep.inputs.append(_config_input(fc, vds))
    rep.notices.extend(_version_notices(fc))
    if vdom:
        rep.notices.append(Notice("vdom-filter", {"vdom": vdom}))
    for v in vds:
        st = fc.vdoms[v].table("system settings")
        if st.get("ngfw-mode") == "policy-based" or len(fc.vdoms[v].table("firewall security-policy")):
            rep.notices.append(Notice("policy-mode", {"vdom": v}))
    rep.findings.extend(shadow_check.run(fc, vds))
    rep.findings.extend(overlap_check.run(fc, vds))
    if any(f.code == "unused.object" for f in rep.findings):
        rep.notices.append(Notice("unused-scope", {}))
    rep.stats = {"policies": rep.inputs[0]["policies"], "vdoms": len(vds)}
    return rep


def change(old: FortiConfig, new: FortiConfig, vdom: Optional[str], lang: str) -> Report:
    vds_old = list(old.vdoms)
    vds_new = list(new.vdoms)
    if vdom:
        if vdom not in old.vdoms and vdom not in new.vdoms:
            raise InputError("vdom-missing", vdom=vdom, available=", ".join(dict.fromkeys(vds_old + vds_new)))
        vds = [vdom]
    else:
        vds = list(dict.fromkeys(vds_old + vds_new))
    rep = Report(mode="change")
    rep.inputs.append(_config_input(old, [v for v in vds if v in old.vdoms]))
    rep.inputs.append(_config_input(new, [v for v in vds if v in new.vdoms]))
    rep.notices.extend(_version_notices(old))
    rep.notices.extend(_version_notices(new))
    if old.version and new.version and old.version[:2] != new.version[:2]:
        rep.notices.append(Notice("version-mismatch", {"a": old.version_str, "b": new.version_str}))
    findings, stats = change_check.run(old, new, vds)
    rep.findings.extend(findings)
    if stats.get("ignored_uuid"):
        rep.notices.append(Notice("uuid-ignored", {"count": stats["ignored_uuid"]}))
    risky = [f.severity for f in findings if f.severity != "info"]
    stats["risk"] = min(risky, key=lambda s: SEV_RANK[s]) if risky else None
    rep.stats = stats
    return rep


def timeline(sources: List[Tuple[str, bytes]], lang: str, ctx: Ctx) -> Report:
    rep = Report(mode="timeline")
    events = []
    totals = {"lines": 0, "unparseable": 0}
    for label, data in sources:
        text = decode_bytes(data)
        res = parse_lines(text.split("\n"), label)
        ctx.secrets.extend(res.secret_values)
        events.extend(res.events)
        totals["lines"] += res.lines
        totals["unparseable"] += res.unparseable
        rep.inputs.append({"kind": "log", "file": label, "lines": res.lines})
    ctx.log_events = events
    ctx.log_sources = [s for s, _ in sources]
    tl = timeline_check.build(events)
    rows = tl["rows"]
    rep.findings.extend(timeline_check.findings_from(tl))
    unknown_count = sum(int(u["count"]) for u in tl["unknown"])
    rep.timeline = {
        "events": [timeline_check.row_dict(r) for r in rows],
        "unknown": tl["unknown"],
        "stats": {
            "lines": totals["lines"], "unparseable": totals["unparseable"], "classified": tl["classified"],
            "rows": len(rows), "unknown": unknown_count, "traffic": tl["traffic"], "no_time": tl["no_time"],
            "devices": tl["devices"], "tz_missing": tl["tz_missing"],
        },
    }
    if tl["tz_missing"]:
        rep.notices.append(Notice("no-tz", {"devices": ", ".join(tl["tz_missing"])}))
    if tl["no_time"]:
        rep.notices.append(Notice("no-time", {"count": tl["no_time"]}))
    rep.notices.append(Notice("eventtime-utc", {}))
    rep.stats = {"events": tl["classified"], "devices": len(tl["devices"])}
    return rep


# --------------------------------------------------------------------------- #


def _finish(rep: Report, ctx: Ctx, anonymize: bool) -> Report:
    lang = ctx.lang
    for r in [rep] + rep.sections:
        for f in r.findings:
            localize(f, lang)
        for n in r.notices:
            localize_notice(n, lang)
    for fc in ctx.configs:
        ctx.secrets.extend(fc.parsed.secret_values)
    red = Redactor(ctx.secrets)
    transform(rep, red)
    if anonymize:
        an = Anonymizer()
        for fc in ctx.configs:
            collect_config_names(an, fc)
        collect_log_names(an, ctx.log_events, ctx.log_sources)
        transform(rep, an)
    return rep


def build_report(files: Sequence[str], *, demo_mode: bool = False, vdom: Optional[str] = None,
                 lang: str = "en", anonymize: bool = False) -> Report:
    """Run the matching checks and return the finished (localized, redacted and
    optionally anonymized) report. Shared by the command line and the GUI.

    Raises InputError for inputs that cannot be checked."""
    ctx = Ctx(lang)
    if demo_mode:
        rep = demo(ctx, vdom)
    else:
        if not files:
            raise InputError("no-input")
        items = [(os.path.basename(p), read_input(p)) for p in files]
        kinds = [classify_input(d) for _, d in items]
        for (label, _), k in zip(items, kinds):
            if k == "unknown":
                raise InputError("not-a-config", file=label)
        if all(k == "log" for k in kinds):
            rep = timeline(items, lang, ctx)
        elif all(k == "config" for k in kinds):
            if len(items) > 2:
                raise InputError("too-many-configs")
            fcs = [load_config(data, label) for label, data in items]
            ctx.configs = fcs
            rep = audit(fcs[0], vdom, lang) if len(fcs) == 1 else change(fcs[0], fcs[1], vdom, lang)
        else:
            raise InputError("mixed-inputs")
    return _finish(rep, ctx, anonymize)


def exit_code_for(rep: Report, demo_mode: bool = False) -> int:
    return EXIT_FINDINGS if (rep.has_findings and not demo_mode) else EXIT_OK


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    lang = args.lang
    if args.gui:
        from .gui import main as gui_main

        return gui_main(lang=lang, files=_expand(args.files))
    files = _expand(args.files)
    try:
        rep = build_report(files, demo_mode=args.demo, vdom=args.vdom, lang=lang, anonymize=args.anonymize)
    except InputError as e:
        return _err(lang, e.code, **e.params)
    except Exception:  # never print file content in a traceback
        if os.environ.get("FGAUDIT_DEBUG"):
            raise
        return _err(lang, "internal", file=", ".join(os.path.basename(f) for f in files) or "demo")
    code = exit_code_for(rep, args.demo)
    if args.html:
        if not _safe_output(args.html, files):
            return _err(lang, "refuse-overwrite", file=args.html)
        try:
            with open(args.html, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(render_html(rep, lang, args.anonymize))
        except OSError as e:
            return _err(lang, "write-failed", file=args.html, reason=e.strerror or type(e).__name__)
    if args.json:
        _write(render_json(rep, lang, args.anonymize, code))
    else:
        _write(render_text(rep, lang, use_color(sys.stdout), args.anonymize))
    return code


def _expand(paths: List[str]) -> List[str]:
    """Expand wildcards ourselves (cmd.exe and PowerShell pass them literally)."""
    import glob

    out: List[str] = []
    for p in paths:
        if any(ch in p for ch in "*?[") and not os.path.exists(p):
            hits = sorted(glob.glob(p))
            out.extend(hits or [p])
        else:
            out.append(p)
    return out


def _safe_output(path: str, inputs: List[str]) -> bool:
    """Never overwrite an input file or anything that is not an earlier report."""
    try:
        target = os.path.realpath(path)
        if any(os.path.realpath(i) == target for i in inputs):
            return False
        if os.path.exists(path):
            with open(path, "rb") as fh:
                head = fh.read(64).lstrip().lower()
            return head.startswith(b"<!doctype html")
    except OSError:
        return False
    return True


def _write(s: str) -> None:
    try:
        sys.stdout.write(s)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "ascii"
        sys.stdout.write(s.encode(enc, errors="replace").decode(enc, errors="replace"))
    sys.stdout.flush()


def demo(ctx: Ctx, vdom: Optional[str]) -> Report:
    from .synth import demo_inputs

    lang = ctx.lang
    d = demo_inputs()
    name, text = d["audit"]  # type: ignore[misc]
    fc = load_config(text.encode(), name)
    bname, btext = d["before"]  # type: ignore[misc]
    aname, atext = d["after"]  # type: ignore[misc]
    b = load_config(btext.encode(), bname)
    a = load_config(atext.encode(), aname)
    ctx.configs = [fc, b, a]
    r1 = audit(fc, vdom, lang)
    r1.title = ui(lang, "mode.audit") + " (FortiOS 7.4)"
    r2 = change(b, a, vdom, lang)
    r2.title = ui(lang, "mode.change") + " (FortiOS 7.6)"
    logs = [(k, v.encode()) for k, v in d["logs"].items()]  # type: ignore[union-attr]
    r3 = timeline(logs, lang, ctx)
    r3.title = ui(lang, "mode.timeline") + " (FortiOS 8.0)"
    rep = Report(mode="demo", sections=[r1, r2, r3])
    rep.notices.append(Notice("demo-data", {}))
    rep.inputs = []
    return rep


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        return run(argv)
    except KeyboardInterrupt:
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_OK
