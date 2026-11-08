"""Graphical window for fgaudit (tkinter, part of the Python standard library).

Same checks, same safety rules as the command line: the window calls
cli.build_report(), so redaction, anonymization and error handling are shared.
Nothing is sent anywhere; files are only read.

Start with ``fgaudit-gui``, ``fgaudit --gui`` or ``python -m fgaudit.gui``.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .findings import SEVERITIES, Finding, Report
from .i18n import error_text, event_text, ui
from .model import InputError

# Window texts. Report texts come from i18n like on the command line.
T: Dict[str, Dict[str, str]] = {
    "en": {
        "subtitle": "Offline and read-only. Unofficial, not affiliated with or endorsed by Fortinet.",
        "files": "Files",
        "add": "Add files…", "remove": "Remove", "clear": "Clear", "up": "Up", "down": "Down",
        "hint.none": "Add one config backup (audit), two backups (before, then after) or log files.",
        "hint.audit": "Mode: configuration audit (shadowed policies, unused objects, IP overlaps)",
        "hint.change": "Mode: change review. First file = before, second file = after. Use Up/Down to swap.",
        "hint.timeline": "Mode: incident timeline from logs",
        "hint.toomany": "More than two config backups: pick one (audit) or two (before/after).",
        "hint.mixed": "Configs and logs mixed: check them separately.",
        "hint.unknown": "Not recognised as a FortiGate config or log: {file}",
        "options": "Options", "vdom": "Only VDOM (optional):", "lang": "Language:", "anon": "Anonymize names and IPs",
        "run": "Run check", "demo": "Demo with made-up data", "running": "Checking…",
        "save_html": "Save HTML report…", "save_json": "Save JSON…",
        "tab.findings": "Findings", "tab.timeline": "Timeline", "tab.text": "Full text",
        "col.sev": "Severity", "col.vdom": "VDOM", "col.check": "Check", "col.title": "Finding",
        "col.time": "Time", "col.device": "Device", "col.event": "Event", "col.count": "Count",
        "next": "Next step", "objects": "Objects", "notes": "Notes",
        "select": "Select a finding to see the details.",
        "nofindings": "No findings.",
        "notimeline": "The timeline is shown for log files.",
        "error": "fgaudit", "internal": "Internal error while checking. Nothing was changed. Please report it without attaching real data.",
        "saved": "Saved: {path}", "open_now": "Open the report in the browser now?",
        "refuse": "Not saved: {file} is an input file or an existing file that is not an fgaudit report.",
        "filetypes.all": "All files", "filetypes.cfg": "Config backups", "filetypes.log": "Logs",
        "ready": "Ready. Files are only read, never changed or sent.",
    },
    "de": {
        "subtitle": "Offline und nur lesend. Inoffiziell, nicht mit Fortinet verbunden oder von Fortinet unterstützt.",
        "files": "Dateien",
        "add": "Dateien hinzufügen…", "remove": "Entfernen", "clear": "Leeren", "up": "Hoch", "down": "Runter",
        "hint.none": "Füg ein Config-Backup (Prüfung), zwei Backups (erst vorher, dann nachher) oder Logdateien hinzu.",
        "hint.audit": "Modus: Konfigurationsprüfung (verdeckte Policies, ungenutzte Objekte, IP-Überschneidungen)",
        "hint.change": "Modus: Change-Bewertung. Erste Datei = vorher, zweite = nachher. Mit Hoch/Runter tauschen.",
        "hint.timeline": "Modus: Incident-Timeline aus Logs",
        "hint.toomany": "Mehr als zwei Config-Backups: Nimm eins (Prüfung) oder zwei (vorher/nachher).",
        "hint.mixed": "Configs und Logs gemischt: Bitte getrennt prüfen.",
        "hint.unknown": "Nicht als FortiGate-Config oder -Log erkannt: {file}",
        "options": "Optionen", "vdom": "Nur VDOM (optional):", "lang": "Sprache:", "anon": "Namen und IPs anonymisieren",
        "run": "Prüfen", "demo": "Demo mit erfundenen Daten", "running": "Prüfe…",
        "save_html": "HTML-Bericht speichern…", "save_json": "JSON speichern…",
        "tab.findings": "Befunde", "tab.timeline": "Timeline", "tab.text": "Volltext",
        "col.sev": "Schwere", "col.vdom": "VDOM", "col.check": "Prüfung", "col.title": "Befund",
        "col.time": "Zeit", "col.device": "Gerät", "col.event": "Ereignis", "col.count": "Anzahl",
        "next": "Nächster Schritt", "objects": "Objekte", "notes": "Hinweise",
        "select": "Wähl einen Befund aus, um die Details zu sehen.",
        "nofindings": "Keine Befunde.",
        "notimeline": "Die Timeline erscheint bei Logdateien.",
        "error": "fgaudit", "internal": "Interner Fehler bei der Prüfung. Es wurde nichts verändert. Bitte melden, ohne echte Daten anzuhängen.",
        "saved": "Gespeichert: {path}", "open_now": "Den Bericht jetzt im Browser öffnen?",
        "refuse": "Nicht gespeichert: {file} ist eine Eingabedatei oder eine vorhandene Datei, die kein fgaudit-Bericht ist.",
        "filetypes.all": "Alle Dateien", "filetypes.cfg": "Config-Backups", "filetypes.log": "Logs",
        "ready": "Bereit. Dateien werden nur gelesen, nie verändert oder verschickt.",
    },
}

SEV_COLORS = {"high": "#c62828", "medium": "#a85d00", "low": "#1f6f8b", "info": "#5d6878"}


def tr(lang: str, key: str, **kw: Any) -> str:
    s = T.get(lang, T["en"]).get(key) or T["en"][key]
    return s.format(**kw) if kw else s


def detect_mode(paths: Sequence[str]) -> str:
    """Predict the mode for the hint line. Reads at most 200 kB per file."""
    from .cli import classify_input

    if not paths:
        return "none"
    kinds = []
    for p in paths:
        try:
            with open(p, "rb") as fh:
                kinds.append(classify_input(fh.read(200_000)))
        except OSError:
            kinds.append("unknown")
    if "unknown" in kinds:
        return "unknown:" + os.path.basename(paths[kinds.index("unknown")])
    if all(k == "log" for k in kinds):
        return "timeline"
    if all(k == "config" for k in kinds):
        return {1: "audit", 2: "change"}.get(len(kinds), "toomany")
    return "mixed"


def finding_detail(f: Finding, lang: str) -> str:
    lines = [f.title, "", f.detail]
    if f.next_step:
        lines += ["", f"{tr(lang, 'next')}: {f.next_step}"]
    if f.objects:
        objs = ", ".join(f"{o.type} {o.name}" + (f" (VDOM {o.vdom})" if o.vdom else "") for o in f.objects)
        lines += ["", f"{tr(lang, 'objects')}: {objs}"]
    return "\n".join(lines)


def timeline_rows(rep: Report, lang: str) -> List[Dict[str, Any]]:
    out = []
    for r in [rep] + list(rep.sections):
        tl = r.timeline or {}
        for e in tl.get("events", []):
            cnt = ""
            if e["count"] > 1:
                cnt = ui(lang, "repeated", n=e["count"], last=e["last"]).strip() if e.get("last") else str(e["count"])
            if e.get("flapping"):
                cnt += f" ({ui(lang, 'flapping')})"
            out.append({"time": e["time"], "device": e["device"], "severity": e["severity"],
                        "event": event_text(lang, e), "count": cnt.strip()})
    return out


class App:
    def __init__(self, root: Any, lang: str = "en", files: Optional[Sequence[str]] = None):
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk = tk, ttk
        self.root = root
        self.lang = lang if lang in T else "en"
        self.files: List[str] = []
        self.report: Optional[Report] = None
        self.report_demo = False
        self.report_lang = self.lang
        self.report_anon = False
        self.findings_by_iid: Dict[str, Finding] = {}
        self.results: "queue.Queue[tuple]" = queue.Queue()
        self.labels: List[tuple] = []  # (widget, key) to relabel on language change

        root.title(f"fgaudit {__version__}")
        root.minsize(820, 560)
        root.geometry("1100x800")
        style = ttk.Style(root)
        if "clam" in style.theme_names() and sys.platform.startswith("linux"):
            style.theme_use("clam")
        from tkinter import font as tkfont

        base = tkfont.nametofont("TkDefaultFont")
        size = abs(int(base.cget("size"))) or 10
        self.f_title = base.copy()
        self.f_title.configure(size=size + 5, weight="bold")
        self.f_bold = base.copy()
        self.f_bold.configure(weight="bold")
        style.configure("Title.TLabel", font=self.f_title)
        style.configure("Muted.TLabel", foreground="#5d6878")
        for sev, col in SEV_COLORS.items():
            style.configure(f"{sev}.TLabel", foreground=col, font=self.f_bold)

        outer = ttk.Frame(root, padding=12)
        outer.pack(fill="both", expand=True)

        head = ttk.Frame(outer)
        head.pack(fill="x")
        ttk.Label(head, text="fgaudit", style="Title.TLabel").pack(side="left")
        self._lbl(ttk.Label(head, style="Muted.TLabel"), "subtitle").pack(side="left", padx=12)

        # files
        ff = self._lbl(ttk.LabelFrame(outer, padding=8), "files")
        ff.pack(fill="x", pady=(10, 4))
        lb_frame = ttk.Frame(ff)
        lb_frame.pack(side="left", fill="both", expand=True)
        self.listbox = tk.Listbox(lb_frame, height=3, activestyle="none", selectmode="extended")
        self.listbox.pack(fill="both", expand=True)
        self.hint = ttk.Label(lb_frame, style="Muted.TLabel")
        self.hint.pack(fill="x", pady=(4, 0))
        btns = ttk.Frame(ff)
        btns.pack(side="left", padx=(8, 0), fill="y")
        for key, cmd in (("add", self.add_files), ("remove", self.remove_files), ("up", lambda: self.move(-1)),
                         ("down", lambda: self.move(1)), ("clear", self.clear_files)):
            self._lbl(ttk.Button(btns, command=cmd), key).pack(fill="x", pady=1)

        # options + actions
        of = self._lbl(ttk.LabelFrame(outer, padding=8), "options")
        of.pack(fill="x", pady=4)
        self._lbl(ttk.Label(of), "vdom").pack(side="left")
        self.vdom = tk.StringVar()
        ttk.Entry(of, textvariable=self.vdom, width=14).pack(side="left", padx=(4, 16))
        self._lbl(ttk.Label(of), "lang").pack(side="left")
        self.lang_var = tk.StringVar(value=self.lang)
        cb = ttk.Combobox(of, textvariable=self.lang_var, values=("en", "de"), width=4, state="readonly")
        cb.pack(side="left", padx=(4, 16))
        cb.bind("<<ComboboxSelected>>", lambda _e: self.set_lang(self.lang_var.get()))
        self.anon = tk.BooleanVar()
        self._lbl(ttk.Checkbutton(of, variable=self.anon), "anon").pack(side="left")

        act = ttk.Frame(outer)
        act.pack(fill="x", pady=(4, 6))
        self.run_btn = self._lbl(ttk.Button(act, command=self.run), "run")
        self.run_btn.pack(side="left")
        self.demo_btn = self._lbl(ttk.Button(act, command=lambda: self.run(demo=True)), "demo")
        self.demo_btn.pack(side="left", padx=6)
        self.json_btn = self._lbl(ttk.Button(act, command=self.save_json, state="disabled"), "save_json")
        self.json_btn.pack(side="right")
        self.html_btn = self._lbl(ttk.Button(act, command=self.save_html, state="disabled"), "save_html")
        self.html_btn.pack(side="right", padx=6)

        # summary
        sf = ttk.Frame(outer)
        sf.pack(fill="x", pady=(2, 6))
        self.chips = {}
        for sev in SEVERITIES:
            lab = ttk.Label(sf, style=f"{sev}.TLabel")
            lab.pack(side="left", padx=(0, 12))
            self.chips[sev] = lab
        self.verdict = ttk.Label(sf)
        self.verdict.pack(side="left", padx=8)

        # results
        self.nb = ttk.Notebook(outer)
        self.nb.pack(fill="both", expand=True)
        tab1 = ttk.Frame(self.nb)
        pane = ttk.PanedWindow(tab1, orient="vertical")
        pane.pack(fill="both", expand=True)
        tf = ttk.Frame(pane)
        self.tree = ttk.Treeview(tf, columns=("sev", "vdom", "check", "title"), show="tree headings", selectmode="browse")
        self.tree.column("#0", width=0, stretch=False)
        self.tree.column("sev", width=90, stretch=False)
        self.tree.column("vdom", width=90, stretch=False)
        self.tree.column("check", width=90, stretch=False)
        self.tree.column("title", width=600)
        for sev, col in SEV_COLORS.items():
            self.tree.tag_configure(sev, foreground=col)
        self.tree.tag_configure("section", font=self.f_bold)
        ysb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)
        pane.add(tf, weight=3)
        df = ttk.Frame(pane)
        self.detail = tk.Text(df, wrap="word", height=8, relief="flat", padx=10, pady=8, font=base)
        dsb = ttk.Scrollbar(df, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=dsb.set)
        self.detail.pack(side="left", fill="both", expand=True)
        dsb.pack(side="right", fill="y")
        pane.add(df, weight=2)
        self.nb.add(tab1)

        tab2 = ttk.Frame(self.nb)
        self.tl = ttk.Treeview(tab2, columns=("time", "device", "event", "count"), show="headings")
        self.tl.column("time", width=200, stretch=False)
        self.tl.column("device", width=130, stretch=False)
        self.tl.column("event", width=480)
        self.tl.column("count", width=260)
        for sev, col in SEV_COLORS.items():
            self.tl.tag_configure(sev, foreground=col)
        tsb = ttk.Scrollbar(tab2, orient="vertical", command=self.tl.yview)
        self.tl.configure(yscrollcommand=tsb.set)
        self.tl.pack(side="left", fill="both", expand=True)
        tsb.pack(side="right", fill="y")
        self.nb.add(tab2)

        tab3 = ttk.Frame(self.nb)
        self.text = tk.Text(tab3, wrap="none", font=tkfont.nametofont("TkFixedFont"), padx=8, pady=6)
        xsb = ttk.Scrollbar(tab3, orient="horizontal", command=self.text.xview)
        ysb3 = ttk.Scrollbar(tab3, orient="vertical", command=self.text.yview)
        self.text.configure(xscrollcommand=xsb.set, yscrollcommand=ysb3.set)
        ysb3.pack(side="right", fill="y")
        xsb.pack(side="bottom", fill="x")
        self.text.pack(fill="both", expand=True)
        self.nb.add(tab3)

        self.status = ttk.Label(outer, style="Muted.TLabel")
        self.status.pack(fill="x", pady=(6, 0))

        self.set_lang(self.lang)
        if files:
            self.files = [f for f in files]
            self.refresh_files()

    # helpers -------------------------------------------------------------
    def _lbl(self, widget: Any, key: str) -> Any:
        self.labels.append((widget, key))
        return widget

    def set_lang(self, lang: str) -> None:
        self.lang = lang if lang in T else "en"
        for w, key in self.labels:
            w.configure(text=tr(self.lang, key))
        for i, key in enumerate(("tab.findings", "tab.timeline", "tab.text")):
            self.nb.tab(i, text=tr(self.lang, key))
        for col, key in (("sev", "col.sev"), ("vdom", "col.vdom"), ("check", "col.check"), ("title", "col.title")):
            self.tree.heading(col, text=tr(self.lang, key))
        for col, key in (("time", "col.time"), ("device", "col.device"), ("event", "col.event"), ("count", "col.count")):
            self.tl.heading(col, text=tr(self.lang, key))
        self.refresh_files()
        self.status.configure(text=tr(self.lang, "ready"))
        if self.report is not None and str(self.run_btn.cget("state")) != "disabled":
            self.run(demo=self.report_demo)  # report texts follow the new language

    def refresh_files(self) -> None:
        self.listbox.delete(0, "end")
        for i, f in enumerate(self.files, 1):
            self.listbox.insert("end", f"{i}. {os.path.basename(f)}   —   {os.path.dirname(os.path.abspath(f))}")
        mode = detect_mode(self.files)
        if mode.startswith("unknown:"):
            self.hint.configure(text=tr(self.lang, "hint.unknown", file=mode.split(":", 1)[1]))
        else:
            self.hint.configure(text=tr(self.lang, "hint." + mode))

    def add_files(self) -> None:
        from tkinter import filedialog

        paths = filedialog.askopenfilenames(parent=self.root, filetypes=[
            (tr(self.lang, "filetypes.all"), "*"),
            (tr(self.lang, "filetypes.cfg"), "*.conf *.cfg *.txt"),
            (tr(self.lang, "filetypes.log"), "*.log *.txt"),
        ])
        for p in paths:
            if p not in self.files:
                self.files.append(p)
        self.refresh_files()

    def remove_files(self) -> None:
        for i in sorted(self.listbox.curselection(), reverse=True):
            del self.files[i]
        self.refresh_files()

    def clear_files(self) -> None:
        self.files = []
        self.refresh_files()

    def move(self, delta: int) -> None:
        sel = self.listbox.curselection()
        if len(sel) != 1:
            return
        i, j = sel[0], sel[0] + delta
        if 0 <= j < len(self.files):
            self.files[i], self.files[j] = self.files[j], self.files[i]
            self.refresh_files()
            self.listbox.selection_set(j)

    # running ---------------------------------------------------------------
    def run(self, demo: bool = False) -> None:
        files = list(self.files)
        vdom = self.vdom.get().strip() or None
        lang, anon = self.lang, bool(self.anon.get())
        for b in (self.run_btn, self.demo_btn, self.html_btn, self.json_btn):
            b.configure(state="disabled")
        self.status.configure(text=tr(lang, "running"))
        self.root.configure(cursor="watch")

        def work() -> None:
            from .cli import build_report

            try:
                rep = build_report(files, demo_mode=demo, vdom=vdom, lang=lang, anonymize=anon)
                self.results.put(("ok", rep, demo, anon, lang))
            except InputError as e:
                self.results.put(("error", error_text(lang, e.code, **e.params)))
            except Exception:  # never show file content or a traceback
                if os.environ.get("FGAUDIT_DEBUG"):
                    import traceback

                    traceback.print_exc()
                self.results.put(("error", tr(lang, "internal")))

        threading.Thread(target=work, daemon=True).start()
        self.root.after(100, self._poll)

    def _poll(self) -> None:
        try:
            res = self.results.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll)
            return
        self.root.configure(cursor="")
        self.run_btn.configure(state="normal")
        self.demo_btn.configure(state="normal")
        if res[0] == "error":
            from tkinter import messagebox

            self.status.configure(text=res[1])
            messagebox.showerror(tr(self.lang, "error"), res[1], parent=self.root)
            return
        _, rep, demo, anon, lang = res
        self.report, self.report_demo, self.report_anon, self.report_lang = rep, demo, anon, lang
        self.show_report(rep, lang)
        self.html_btn.configure(state="normal")
        self.json_btn.configure(state="normal")

    def show_report(self, rep: Report, lang: str) -> None:
        from .render import render_text, verdict

        counts = rep.severity_counts()
        for sev, lab in self.chips.items():
            lab.configure(text=f"{ui(lang, sev)} {counts.get(sev, 0)}")
        self.verdict.configure(text=verdict(rep, lang))

        self.tree.delete(*self.tree.get_children())
        self.findings_by_iid = {}
        sections = list(rep.sections) or [rep]
        self.tree.column("#0", width=240 if rep.sections else 0, stretch=False)
        for si, sec in enumerate(sections):
            parent = ""
            if rep.sections:
                parent = self.tree.insert("", "end", text=sec.title or ui(lang, "mode." + sec.mode), open=True, tags=("section",))
            for fi, f in enumerate(sec.sorted_findings()):
                iid = self.tree.insert(parent, "end", values=(ui(lang, f.severity), f.vdom or "", f.check, f.title), tags=(f.severity,))
                self.findings_by_iid[iid] = f
        notes = [n.text for s in [rep] + list(rep.sections) for n in s.notices if n.text]
        intro = tr(lang, "select") if self.findings_by_iid else tr(lang, "nofindings")
        if notes:
            intro += "\n\n" + tr(lang, "notes") + ":\n" + "\n".join("- " + n for n in notes)
        self._set_text(self.detail, intro)

        self.tl.delete(*self.tl.get_children())
        rows = timeline_rows(rep, lang)
        for r in rows:
            self.tl.insert("", "end", values=(r["time"], r["device"], r["event"], r["count"]), tags=(r["severity"],))
        if not rows:
            self.tl.insert("", "end", values=("", "", tr(lang, "notimeline"), ""))

        self._set_text(self.text, render_text(rep, lang, False, self.report_anon, width=110))
        self.status.configure(text=verdict(rep, lang))
        self.nb.select(1 if rep.mode == "timeline" else 0)

    def show_detail(self, _event: Any = None) -> None:
        sel = self.tree.selection()
        if sel and sel[0] in self.findings_by_iid:
            self._set_text(self.detail, finding_detail(self.findings_by_iid[sel[0]], self.report_lang))

    @staticmethod
    def _set_text(widget: Any, s: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", s)
        widget.configure(state="disabled")

    # export ------------------------------------------------------------------
    def _ask_save(self, ext: str, default: str) -> Optional[str]:
        from tkinter import filedialog, messagebox

        from .cli import _safe_output

        path = filedialog.asksaveasfilename(parent=self.root, defaultextension=ext, initialfile=default,
                                            filetypes=[(ext.upper().lstrip("."), "*" + ext)])
        if not path:
            return None
        if ext == ".html" and not _safe_output(path, self.files):
            messagebox.showerror(tr(self.lang, "error"), tr(self.lang, "refuse", file=os.path.basename(path)), parent=self.root)
            return None
        if ext == ".json" and any(os.path.realpath(path) == os.path.realpath(f) for f in self.files):
            messagebox.showerror(tr(self.lang, "error"), tr(self.lang, "refuse", file=os.path.basename(path)), parent=self.root)
            return None
        return path

    def _write(self, path: str, content: str) -> bool:
        from tkinter import messagebox

        try:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
        except OSError as e:
            messagebox.showerror(tr(self.lang, "error"),
                                 error_text(self.lang, "write-failed", file=os.path.basename(path), reason=e.strerror or type(e).__name__),
                                 parent=self.root)
            return False
        self.status.configure(text=tr(self.lang, "saved", path=path))
        return True

    def save_html(self) -> None:
        from tkinter import messagebox

        from .render import render_html

        if self.report is None:
            return
        path = self._ask_save(".html", "fgaudit-report.html")
        if path and self._write(path, render_html(self.report, self.report_lang, self.report_anon)):
            if messagebox.askyesno("fgaudit", tr(self.lang, "open_now"), parent=self.root):
                webbrowser.open(Path(path).resolve().as_uri())

    def save_json(self) -> None:
        from .cli import exit_code_for
        from .render import render_json

        if self.report is None:
            return
        path = self._ask_save(".json", "fgaudit-report.json")
        if path:
            self._write(path, render_json(self.report, self.report_lang, self.report_anon,
                                          exit_code_for(self.report, self.report_demo)))


def main(argv: Optional[Sequence[str]] = None, lang: Optional[str] = None, files: Optional[Sequence[str]] = None) -> int:
    if files is None:
        args = list(sys.argv[1:] if argv is None else argv)
        files = []
        while args:
            a = args.pop(0)
            if a == "--lang" and args:
                lang = args.pop(0)
            elif a.startswith("--lang="):
                lang = a.split("=", 1)[1]
            else:
                files.append(a)
        from .cli import _expand

        files = _expand(files)
    if lang is None:
        lang = os.environ.get("FGAUDIT_LANG", "en")
    try:
        import tkinter as tk
    except ImportError:
        sys.stderr.write(
            "fgaudit: the window needs tkinter, which is missing in this Python installation.\n"
            "  Windows/macOS: install Python from python.org (tkinter is included).\n"
            "  Debian/Ubuntu: sudo apt install python3-tk   Fedora: sudo dnf install python3-tkinter\n"
            "The command line works without it: fgaudit --help\n")
        return 2
    try:
        root = tk.Tk()
    except tk.TclError:
        sys.stderr.write("fgaudit: cannot open a window (no display). Use the command line: fgaudit --help\n")
        return 2
    App(root, lang=lang, files=files)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
