"""Terminal, JSON and HTML output."""

from __future__ import annotations

import html
import json
import os
import shutil
import textwrap
from typing import Any, Dict, List, Optional, TextIO

from . import __version__
from .findings import SEVERITIES, Finding, Report
from .i18n import CAT, event_text, ui

JSON_SCHEMA = "fgaudit/report@1"

# --------------------------------------------------------------------------- #
# terminal

_COL = {
    "high": "\033[1;31m", "medium": "\033[1;33m", "low": "\033[36m", "info": "\033[2m",
    "bold": "\033[1m", "dim": "\033[2m", "head": "\033[1;37;44m", "ok": "\033[1;32m", "reset": "\033[0m",
}


def use_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":
        return _enable_windows_vt()
    return os.environ.get("TERM") != "dumb"


def _enable_windows_vt() -> bool:  # pragma: no cover - Windows only
    try:
        import ctypes

        k = ctypes.windll.kernel32  # type: ignore[attr-defined]
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        return bool(k.SetConsoleMode(h, mode.value | 0x0004))
    except Exception:
        return False


class Term:
    def __init__(self, color: bool, width: Optional[int] = None):
        self.color = color
        self.width = max(60, min(width or shutil.get_terminal_size((100, 24)).columns, 110))

    def c(self, key: str, s: str) -> str:
        return f"{_COL[key]}{s}{_COL['reset']}" if self.color else s

    def wrap(self, s: str, indent: int) -> List[str]:
        return textwrap.wrap(s, width=self.width - indent, break_long_words=True, break_on_hyphens=False) or [""]


def _tag(lang: str, sev: str) -> str:
    return f"[{ui(lang, sev)}]"


def render_text(rep: Report, lang: str, color: bool, anonymized: bool = False, width: Optional[int] = None) -> str:
    t = Term(color, width)
    out: List[str] = []
    title = ui(lang, "mode." + rep.mode)
    out.append(t.c("bold", f"fgaudit {__version__}") + "  " + title)
    for inp in rep.inputs:
        out.append(t.c("dim", "  " + _input_line(lang, inp)))
    out.append(t.c("dim", "  " + ui(lang, "readonly")))
    if anonymized:
        out.append(t.c("dim", "  " + ui(lang, "anonymized")))
    out.append("")
    if rep.sections:
        out.extend(_summary_lines(t, rep, lang))
        for sec in rep.sections:
            out.append("")
            out.append(t.c("head", f" {sec.title} "))
            for inp in sec.inputs:
                out.append(t.c("dim", "  " + _input_line(lang, inp)))
            out.extend(_body_lines(t, sec, lang, summary=True))
    else:
        out.extend(_body_lines(t, rep, lang, summary=True))
    return "\n".join(out) + "\n"


def _input_line(lang: str, inp: Dict[str, Any]) -> str:
    if inp.get("kind") == "config":
        parts = [f"{ui(lang, 'input')}: {inp['file']}", f"FortiOS {inp.get('version', '?')}" + (f" ({inp['model']})" if inp.get("model") else "")]
        if inp.get("vdoms"):
            parts.append(f"{ui(lang, 'vdoms')}: {', '.join(inp['vdoms'])}")
        if inp.get("policies") is not None:
            parts.append(f"{inp['policies']} {ui(lang, 'policies')}")
        return "  |  ".join(parts)
    return f"{ui(lang, 'input')}: {inp['file']}  |  {inp.get('lines', 0)} {ui(lang, 'lines')}"


def _summary_lines(t: Term, rep: Report, lang: str) -> List[str]:
    out = [t.c("bold", ui(lang, "summary").upper())]
    counts = {s: 0 for s in SEVERITIES}
    for f in (rep.all_findings() if rep.sections else rep.findings):
        counts[f.severity] += 1
    chips = "  ".join(t.c(s, f"{_tag(lang, s)} {counts[s]}") for s in SEVERITIES)
    out.append("  " + chips)
    for line in t.wrap(verdict(rep, lang, counts), 2):
        out.append("  " + line)
    return out


def verdict(rep: Report, lang: str, counts: Optional[Dict[str, int]] = None) -> str:
    if counts is None:
        counts = {s: 0 for s in SEVERITIES}
        for f in rep.all_findings():
            counts[f.severity] += 1
    n = sum(v for k, v in counts.items() if k != "info")
    if rep.mode == "change" and rep.stats.get("risk"):
        pass
    if n == 0:
        return ui(lang, "verdict.clean", what=_what(rep, lang)) + (
            f" ({counts['info']} {ui(lang, 'info')})" if counts["info"] else "")
    from .i18n import SEV_WORD

    parts = ", ".join(f"{counts[s]} {SEV_WORD[lang][s]}" for s in SEVERITIES if counts[s] and s != "info")
    v = ui(lang, "verdict.found", n=n, parts=parts)
    if counts["info"]:
        v += f" + {counts['info']} {ui(lang, 'info')}."
    if rep.mode == "change" and rep.stats.get("risk"):
        v = f"{ui(lang, 'risk')}: {SEV_WORD[lang][rep.stats['risk']].upper()}. " + v
    return v


def _what(rep: Report, lang: str) -> str:
    s = rep.stats
    if rep.mode == "audit":
        return ui(lang, "what.audit", policies=s.get("policies", 0), vdoms=s.get("vdoms", 1))
    if rep.mode == "change":
        return ui(lang, "what.change", changes=s.get("changes", 0))
    if rep.mode == "timeline":
        return ui(lang, "what.timeline", events=s.get("events", 0), devices=s.get("devices", 0))
    return rep.mode


def _body_lines(t: Term, rep: Report, lang: str, summary: bool) -> List[str]:
    out: List[str] = []
    if summary:
        out.extend(_summary_lines(t, rep, lang))
    if rep.notices:
        out.append("")
        out.append(t.c("bold", ui(lang, "notes").upper()))
        for n in rep.notices:
            lines = t.wrap(n.text, 4)
            out.append("  - " + (t.c("medium", lines[0]) if n.text.startswith(("WARNING", "WARNUNG")) else lines[0]))
            out.extend("    " + l for l in lines[1:])
    fs = rep.sorted_findings()
    out.append("")
    out.append(t.c("bold", ui(lang, "findings").upper()))
    if not fs:
        out.append("  " + t.c("ok", ui(lang, "no_findings")))
    for f in fs:
        out.extend(_finding_lines(t, f, lang))
    if rep.timeline:
        out.extend(_timeline_lines(t, rep.timeline, lang))
    return out


def _finding_lines(t: Term, f: Finding, lang: str) -> List[str]:
    out = [""]
    tag = _tag(lang, f.severity)
    pad = " " * (len(tag) + 1)
    first, *rest = t.wrap(f.title, len(tag) + 3)
    out.append("  " + t.c(f.severity, tag) + " " + t.c("bold", first))
    out.extend("  " + pad + t.c("bold", l) for l in rest)
    meta = [f.check]
    if f.vdom:
        meta.insert(0, f"VDOM {f.vdom}")
    out.append("  " + pad + t.c("dim", " | ".join(meta)))
    for l in t.wrap(f.detail, len(pad) + 2):
        out.append("  " + pad + l)
    if f.next_step:
        nl = t.wrap(f"{ui(lang, 'next')}: {f.next_step}", len(pad) + 2)
        out.append("  " + pad + t.c("bold", "-> ") + nl[0])
        out.extend("  " + pad + "   " + l for l in nl[1:])
    return out


def _timeline_lines(t: Term, tl: Dict[str, Any], lang: str) -> List[str]:
    out = ["", t.c("bold", ui(lang, "timeline").upper())]
    events = tl.get("events", [])
    shown = events[:60]
    for e in shown:
        sev = e["severity"]
        mark = {"high": "!!", "medium": "! ", "low": ". ", "info": "  "}[sev]
        txt = event_text(lang, e)
        rep = ""
        if e["count"] > 1:
            rep = "  " + ui(lang, "repeated", n=e["count"], last=e["last"])
        if e.get("flapping"):
            rep += f"  ({ui(lang, 'flapping')})"
        line = f"  {mark} {e['time']}  {e['device']:<12} {txt}{rep}"
        out.append(t.c(sev, line) if sev in ("high", "medium") else line)
    if len(events) > len(shown):
        out.append(t.c("dim", f"  ... +{len(events) - len(shown)} (--html / --json)"))
    st = tl.get("stats", {})
    out.append("")
    out.append(t.c("dim", "  " + ui(lang, "stats.timeline", lines=st.get("lines", 0), events=st.get("classified", 0),
                                     unknown=st.get("unknown", 0), traffic=st.get("traffic", 0), bad=st.get("unparseable", 0))))
    unk = tl.get("unknown", [])
    if unk:
        out.append("")
        out.append(t.c("bold", ui(lang, "unknown_entries")))
        for u in unk[:10]:
            out.append(f"  {u['count']:>6}x  logid={u['logid']}  {u.get('subtype', '')}  {u.get('logdesc', '')}")
        if len(unk) > 10:
            out.append(t.c("dim", f"  ... +{len(unk) - 10}"))
    return out


# --------------------------------------------------------------------------- #
# JSON


def report_dict(rep: Report, lang: str, anonymized: bool, exit_code: Optional[int] = None) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "schema": JSON_SCHEMA,
        "tool": {"name": "fgaudit", "version": __version__},
        "mode": rep.mode,
        "lang": lang,
        "anonymized": anonymized,
        "inputs": rep.inputs,
        "summary": {
            "counts": rep.severity_counts(),
            "has_findings": rep.has_findings,
            "verdict": verdict(rep, lang),
        },
        "findings": [],
        "notices": [{"code": n.code, "text": n.text} for n in rep.notices],
        "stats": rep.stats,
        "timeline": rep.timeline,
    }
    if exit_code is not None:
        d["summary"]["exit_code"] = exit_code
    for i, f in enumerate(rep.sorted_findings(), 1):
        d["findings"].append({
            "id": f"F{i:03d}",
            "check": f.check,
            "code": f.code,
            "severity": f.severity,
            "vdom": f.vdom,
            "title": f.title,
            "detail": f.detail,
            "next_step": f.next_step,
            "objects": [o.to_dict() for o in f.objects],
            "params": f.params,
        })
    if rep.sections:
        d["sections"] = [dict(report_dict(s, lang, anonymized), title=s.title) for s in rep.sections]
        for s in d["sections"]:
            s.pop("tool", None)
            s.pop("schema", None)
    return d


def render_json(rep: Report, lang: str, anonymized: bool, exit_code: Optional[int] = None) -> str:
    return json.dumps(report_dict(rep, lang, anonymized, exit_code), indent=2, ensure_ascii=False, default=str) + "\n"


# --------------------------------------------------------------------------- #
# HTML

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2330;--muted:#5d6878;--line:#dde2e8;--accent:#2457c5;
--high:#c62828;--high-bg:#fdecec;--medium:#a85d00;--medium-bg:#fff4e0;--low:#1f6f8b;--low-bg:#e6f4f8;--info:#5d6878;--info-bg:#eef0f3;--ok:#1b7a3d;--ok-bg:#e7f6ec;
color-scheme:light}
@media (prefers-color-scheme:dark){:root:not(:has(#theme:checked)){--bg:#0f141b;--card:#171e28;--fg:#e4e9f0;--muted:#97a3b4;--line:#2a3442;--accent:#7aa2ff;
--high:#ff6b6b;--high-bg:#3a1c1f;--medium:#f4b24a;--medium-bg:#3a2c14;--low:#5cc4e0;--low-bg:#132e38;--info:#97a3b4;--info-bg:#222a35;--ok:#5fd28a;--ok-bg:#15301f;color-scheme:dark}}
@media (prefers-color-scheme:light){:root:has(#theme:checked){--bg:#0f141b;--card:#171e28;--fg:#e4e9f0;--muted:#97a3b4;--line:#2a3442;--accent:#7aa2ff;
--high:#ff6b6b;--high-bg:#3a1c1f;--medium:#f4b24a;--medium-bg:#3a2c14;--low:#5cc4e0;--low-bg:#132e38;--info:#97a3b4;--info-bg:#222a35;--ok:#5fd28a;--ok-bg:#15301f;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:28px 16px 60px}
header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:18px;margin:34px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:0 0 4px}
.muted{color:var(--muted)}
.small{font-size:13px}
code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
.chip{border-radius:999px;padding:3px 12px;font-weight:600;font-size:13px}
.sev-high{color:var(--high);background:var(--high-bg)}.sev-medium{color:var(--medium);background:var(--medium-bg)}
.sev-low{color:var(--low);background:var(--low-bg)}.sev-info{color:var(--info);background:var(--info-bg)}
.ok{color:var(--ok);background:var(--ok-bg)}
.finding{border-left:4px solid var(--line)}
.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--medium)}.finding.low{border-left-color:var(--low)}.finding.info{border-left-color:var(--info)}
.finding .meta{font-size:12px;color:var(--muted);margin:2px 0 8px}
.badge{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;border-radius:4px;padding:1px 7px;margin-right:6px;vertical-align:2px}
.next{margin-top:8px;padding:8px 10px;border-radius:6px;background:var(--bg)}
.next b{color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
.tl-high td:first-child{box-shadow:inset 3px 0 var(--high)}.tl-medium td:first-child{box-shadow:inset 3px 0 var(--medium)}
.tbl{overflow-x:auto}
.toggle{cursor:pointer;user-select:none;border:1px solid var(--line);border-radius:999px;padding:4px 12px;font-size:13px;background:var(--card);color:var(--fg)}
#theme{position:absolute;opacity:0;pointer-events:none}
footer{margin-top:40px;font-size:12px;color:var(--muted)}
ul.notes{margin:6px 0;padding-left:20px}
"""


def _e(s: Any) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def render_html(rep: Report, lang: str, anonymized: bool) -> str:
    title = ui(lang, "report_title")
    parts: List[str] = []
    parts.append("<!doctype html>")
    parts.append(f'<html lang="{_e(lang)}"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    parts.append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">")
    parts.append('<meta name="referrer" content="no-referrer">')
    parts.append(f"<title>{_e(title)}</title><style>{CSS}</style></head><body>")
    parts.append('<input type="checkbox" id="theme" aria-label="theme">')
    parts.append('<div class="wrap"><header><div>')
    parts.append(f"<h1>{_e(title)}: {_e(ui(lang, 'mode.' + rep.mode))}</h1>")
    for inp in rep.inputs:
        parts.append(f'<div class="muted small">{_e(_input_line(lang, inp))}</div>')
    parts.append(f'<div class="muted small">{_e(ui(lang, "readonly"))}</div>')
    if anonymized:
        parts.append(f'<div class="muted small">{_e(ui(lang, "anonymized"))}</div>')
    parts.append(f'</div><label class="toggle" for="theme">{_e(ui(lang, "theme"))}</label></header>')
    parts.append(_html_summary(rep, lang))
    if rep.sections:
        for sec in rep.sections:
            parts.append(f"<h2>{_e(sec.title)}</h2>")
            for inp in sec.inputs:
                parts.append(f'<div class="muted small">{_e(_input_line(lang, inp))}</div>')
            parts.append(_html_body(sec, lang))
    else:
        parts.append(_html_body(rep, lang))
    parts.append(f"<footer>{_e(ui(lang, 'generated', version=__version__))}</footer></div></body></html>")
    return "\n".join(parts) + "\n"


def _html_summary(rep: Report, lang: str) -> str:
    c = rep.severity_counts()
    chips = "".join(f'<span class="chip sev-{s}">{_e(ui(lang, s))} {c[s]}</span>' for s in SEVERITIES)
    v = verdict(rep, lang)
    cls = "ok" if not rep.has_findings else ""
    return f'<div class="card"><h3>{_e(ui(lang, "summary"))}</h3><div class="chips">{chips}</div><div class="chip {cls}" style="display:inline-block;font-weight:500">{_e(v)}</div></div>'


def _html_body(rep: Report, lang: str) -> str:
    out: List[str] = []
    if rep.sections == [] and rep.mode != "demo" and False:
        pass
    if rep.notices:
        out.append(f'<div class="card"><h3>{_e(ui(lang, "notes"))}</h3><ul class="notes">')
        for n in rep.notices:
            out.append(f"<li>{_e(n.text)}</li>")
        out.append("</ul></div>")
    fs = rep.sorted_findings()
    out.append(f"<h2>{_e(ui(lang, 'findings'))} ({len(fs)})</h2>")
    if not fs:
        out.append(f'<div class="card"><span class="chip ok">{_e(ui(lang, "no_findings"))}</span></div>')
    for f in fs:
        meta = " | ".join(x for x in [f"VDOM {f.vdom}" if f.vdom else "", f.check] if x)
        out.append(f'<div class="card finding {f.severity}"><h3><span class="badge sev-{f.severity}">{_e(ui(lang, f.severity))}</span>{_e(f.title)}</h3>')
        out.append(f'<div class="meta">{_e(meta)}</div><div>{_e(f.detail)}</div>')
        if f.next_step:
            out.append(f'<div class="next"><b>{_e(ui(lang, "next"))}:</b> {_e(f.next_step)}</div>')
        out.append("</div>")
    if rep.timeline:
        tl = rep.timeline
        out.append(f"<h2>{_e(ui(lang, 'timeline'))}</h2>")
        out.append('<div class="card tbl"><table><thead><tr>')
        for h in ("time", "device", "event", "count"):
            out.append(f"<th>{_e(ui(lang, h))}</th>")
        out.append("</tr></thead><tbody>")
        for e in tl.get("events", []):
            cnt = str(e["count"]) if e["count"] == 1 else ui(lang, "repeated", n=e["count"], last=e["last"])
            if e.get("flapping"):
                cnt += f" ({ui(lang, 'flapping')})"
            out.append(f'<tr class="tl-{e["severity"]}"><td class="mono">{_e(e["time"])}</td><td>{_e(e["device"])}</td>'
                       f'<td><span class="badge sev-{e["severity"]}">{_e(CAT[lang].get(e["category"], e["category"]))}</span>{_e(event_text(lang, e))}</td><td>{_e(cnt)}</td></tr>')
        out.append("</tbody></table>")
        st = tl.get("stats", {})
        out.append(f'<p class="muted small">{_e(ui(lang, "stats.timeline", lines=st.get("lines", 0), events=st.get("classified", 0), unknown=st.get("unknown", 0), traffic=st.get("traffic", 0), bad=st.get("unparseable", 0)))}</p></div>')
        unk = tl.get("unknown", [])
        if unk:
            out.append(f'<div class="card tbl"><h3>{_e(ui(lang, "unknown_entries"))}</h3><table><thead><tr><th>{_e(ui(lang, "count"))}</th><th>logid</th><th>subtype</th><th>{_e(ui(lang, "description"))}</th></tr></thead><tbody>')
            for u in unk:
                out.append(f'<tr><td>{u["count"]}</td><td class="mono">{_e(u["logid"])}</td><td>{_e(u.get("subtype"))}</td><td>{_e(u.get("logdesc"))}</td></tr>')
            out.append("</tbody></table></div>")
    return "\n".join(out)
