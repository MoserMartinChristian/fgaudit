"""Check 4: incident timeline from FortiGate event logs.

Message IDs are the last five digits of ``logid`` and were checked against
the FortiOS Log Message Reference 7.4.9, 7.6.4 and 8.0.0 (all IDs below exist
in all three with the same meaning)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..findings import Finding, Obj
from ..logs import LogEvent, fmt_time

# msgid -> (category, kind)
MSG: Dict[str, Tuple[str, str]] = {
    "20090": ("interface", "link"),
    "20099": ("interface", "status"),
    "20300": ("bgp", "neighbor"),
    "20302": ("ospf", "neighbor"),
    "20303": ("ospf", "neighbor"),
    "22011": ("conserve", "enter"),
    "22012": ("conserve", "leave"),
    "22802": ("conserve", "enter"),
    "22803": ("conserve", "leave"),
    "22921": ("routing", "route"),
    "22922": ("sdwan", "linkmon"),
    "22923": ("sdwan", "member"),
    "22925": ("sdwan", "sla"),
    "23101": ("ipsec", "up"),
    "23102": ("ipsec", "down"),
    "37120": ("ipsec", "negotiate"),
    "37121": ("ipsec", "negotiate"),
    "37122": ("ipsec", "negotiate"),
    "37123": ("ipsec", "negotiate"),
    "37124": ("ipsec", "negotiate"),
    "37125": ("ipsec", "negotiate"),
    "37127": ("ipsec", "negotiate"),
    "37128": ("ipsec", "negotiate"),
    "37129": ("ipsec", "negotiate"),
    "37130": ("ipsec", "negotiate"),
    "37137": ("ipsec", "connfail"),
    "37138": ("ipsec", "conn"),
    "35011": ("ha", "syncfail"),
    "35013": ("ha", "failover-fail"),
    "35016": ("ha", "failover"),
    "37892": ("ha", "state"),
    "37898": ("ha", "devfail"),
    "37901": ("ha", "hbdown"),
    "37902": ("ha", "hbup"),
    "37904": ("ha", "primary"),
    "37910": ("ha", "hblost"),
    "32001": ("admin", "login"),
    "32002": ("admin", "loginfail"),
    "32102": ("config", "change"),
    "32104": ("config", "change"),
    "44544": ("config", "change"),
    "44545": ("config", "change"),
    "44546": ("config", "change"),
    "44547": ("config", "change"),
    "44548": ("config", "change"),
    "32138": ("system", "reboot"),
    "32200": ("system", "shutdown"),
    "32545": ("system", "reboot"),
}

# severity per (category, state)
SEV = {
    ("interface", "down"): "high", ("bgp", "down"): "high", ("ospf", "down"): "high",
    ("conserve", "enter"): "high", ("system", "reboot"): "high", ("system", "shutdown"): "high",
    ("ha", "failover"): "high", ("ha", "state"): "high", ("ha", "hbdown"): "high", ("ha", "hblost"): "medium",
    ("ha", "devfail"): "high", ("ha", "primary"): "high", ("ha", "failover-fail"): "high", ("ha", "syncfail"): "medium",
    ("sdwan", "down"): "medium", ("ipsec", "down"): "medium", ("ipsec", "fail"): "medium",
    ("routing", "down"): "medium", ("admin", "loginfail"): "low",
}
PRECURSOR = {("config", "change"), ("admin", "login")}

_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


@dataclass
class Ev:
    ev: LogEvent
    cat: str
    kind: str
    state: str  # down/up/enter/leave/fail/ok/info/...
    obj: str
    intf: str = ""

    @property
    def sev(self) -> str:
        return SEV.get((self.cat, self.state)) or SEV.get((self.cat, self.kind)) or "info"


def _state_from_text(*texts: str) -> str:
    t = " ".join(x.lower() for x in texts if x)
    for word, st in (
        ("out-of-sla", "down"), ("dead", "down"), (" down", "down"), ("down", "down"), ("fail", "fail"),
        ("in-sla", "up"), ("alive", "up"), (" up", "up"), ("up", "up"), ("established", "up"),
    ):
        if word in t:
            return st
    return "info"


def classify(e: LogEvent) -> Optional[Ev]:
    mid = e.msgid
    entry = MSG.get(mid)
    f = e.fields
    if entry is None:
        return _fallback(e)
    cat, kind = entry
    msg = f.get("msg", "")
    if cat == "interface":
        obj = f.get("intf") or f.get("interface") or _first_word_after(msg, "interface") or "?"
        st = _state_from_text(f.get("status", ""), f.get("action", ""), msg)
        return Ev(e, cat, kind, st, obj, intf=obj)
    if cat in ("bgp", "ospf"):
        m = re.search(r"neighbou?r\s+(\S+)|nbr\s+(\S+)", msg, re.I)
        obj = (m.group(1) or m.group(2)) if m else (_IP.search(msg).group(1) if _IP.search(msg) else "?")
        low = msg.lower()
        if cat == "ospf":
            m2 = re.search(r"to\s+(\w+)", msg, re.I)
            to = (m2.group(1).lower() if m2 else "")
            st = "up" if to == "full" else ("down" if to in ("down", "init") or "down" in low else "info")
        else:
            st = "down" if " down" in low or "idle" in low else ("up" if " up" in low or "established" in low else "info")
        return Ev(e, cat, kind, st, obj.strip(",."))
    if cat == "conserve":
        return Ev(e, cat, kind, kind, "memory" if mid in ("22011", "22012") else "file descriptor")
    if cat == "routing":
        obj = f.get("name") or f.get("interface") or "route"
        return Ev(e, cat, kind, _state_from_text(f.get("status", ""), msg), obj, intf=f.get("interface", ""))
    if cat == "sdwan":
        intf = f.get("interface", "") or f.get("member", "")
        hc = f.get("healthcheck") or f.get("name") or ""
        obj = f"{hc}/{intf}" if hc and intf else (intf or hc or "?")
        if kind == "sla":
            st = "info"
            if f.get("status", "").lower() in ("down", "dead"):
                st = "down"
        else:
            st = _state_from_text(f.get("newvalue", ""), f.get("status", ""), msg)
        return Ev(e, cat, kind, st, obj, intf=intf)
    if cat == "ipsec":
        tun = f.get("vpntunnel") or f.get("tunnelip") or f.get("remip") or "?"
        intf = f.get("outintf", "")
        if kind == "up":
            st = "up"
        elif kind == "down":
            st = "down"
        elif kind == "conn":
            a = f.get("action", "").lower()
            st = "down" if "down" in a else ("up" if "up" in a else "info")
        elif kind == "connfail":
            st = "fail"
        else:  # negotiate
            stat = (f.get("status", "") + " " + f.get("result", "")).lower()
            st = "fail" if ("fail" in stat or "error" in stat or mid in ("37121", "37123", "37124", "37125", "37128", "37130")) else "info"
        return Ev(e, cat, kind, st, tun, intf=intf)
    if cat == "ha":
        obj = f.get("devintfname") or f.get("vcluster_member") or f.get("sn") or f.get("hostname") or e.device
        st = kind
        if kind == "hbup":
            st = "up"
        return Ev(e, cat, kind, st, obj, intf=f.get("devintfname", ""))
    if cat == "admin":
        return Ev(e, cat, kind, kind, f.get("user", "?") or "?")
    if cat == "config":
        obj = f.get("cfgpath") or "config"
        if f.get("cfgobj"):
            obj += f" [{f.get('cfgobj')}]"
        return Ev(e, cat, kind, "change", obj)
    if cat == "system":
        return Ev(e, cat, kind, kind, e.device)
    return None


def _fallback(e: LogEvent) -> Optional[Ev]:
    """Classify by subtype/logdesc for IDs not in the table."""
    f = e.fields
    desc = (f.get("logdesc", "") + " " + f.get("msg", "")).lower()
    sub = f.get("subtype", "").lower()
    if f.get("type", "").lower() != "event":
        return None
    if "bgp" in desc:
        return Ev(e, "bgp", "neighbor", _state_from_text(desc), _IP.search(desc).group(1) if _IP.search(desc) else "?")
    if "ospf" in desc:
        return Ev(e, "ospf", "neighbor", _state_from_text(desc), _IP.search(desc).group(1) if _IP.search(desc) else "?")
    if "conserve" in desc:
        return Ev(e, "conserve", "enter" if "enter" in desc else "leave", "enter" if "enter" in desc else "leave", "memory")
    if sub == "ha" and ("failover" in desc or "state" in desc):
        return Ev(e, "ha", "state", "state", e.device)
    return None


def _first_word_after(msg: str, word: str) -> str:
    m = re.search(word + r"\s+(\S+)", msg, re.I)
    return m.group(1).strip(",.") if m else ""


# --------------------------------------------------------------------------- #


@dataclass
class Row:
    first: Ev
    last_ts: float
    count: int = 1
    flapping: bool = False

    @property
    def sig(self) -> Tuple:
        e = self.first
        return (e.ev.device, e.cat, e.obj, e.state)


@dataclass
class Incident:
    trigger: int
    chain: List[Tuple[int, str, float]] = field(default_factory=list)  # (row idx, reason code, delay s)
    precursor: Optional[Tuple[int, float]] = None
    confidence: str = "low"
    reasons: List[str] = field(default_factory=list)


MERGE_WINDOW = 15 * 60
INCIDENT_GAP = 30 * 60


def build(events: List[LogEvent]) -> Dict[str, object]:
    classified: List[Ev] = []
    unknown: Dict[str, Dict[str, object]] = {}
    traffic = 0
    no_time = 0
    for e in events:
        if e.ts is None:
            no_time += 1
            continue
        t = e.fields.get("type", "").lower()
        if t in ("traffic", "utm", "anomaly") or t in ("virus", "webfilter", "ips", "app-ctrl", "dns", "ssl", "waf", "emailfilter", "dlp", "file-filter", "voip", "ssh", "icap", "casb", "videofilter", "virtual-patch"):
            traffic += 1
            continue
        ev = classify(e)
        if ev is None:
            lid = e.fields.get("logid", "?")
            u = unknown.setdefault(lid, {"logid": lid, "count": 0, "subtype": e.fields.get("subtype", ""), "logdesc": e.fields.get("logdesc", "")[:80]})
            u["count"] = int(u["count"]) + 1  # type: ignore[arg-type]
            continue
        classified.append(ev)
    classified.sort(key=lambda x: (x.ev.ts, x.ev.source, x.ev.line))
    rows: List[Row] = []
    open_rows: Dict[Tuple, Row] = {}
    for ev in classified:
        sig = (ev.ev.device, ev.cat, ev.obj, ev.state)
        r = open_rows.get(sig)
        if r is not None and ev.ev.ts - r.last_ts <= MERGE_WINDOW:
            r.count += 1
            r.last_ts = ev.ev.ts
            continue
        r = Row(ev, ev.ev.ts)
        rows.append(r)
        open_rows[sig] = r
    # flapping: same object has both down and up rows that overlap in time
    by_obj: Dict[Tuple, List[Row]] = {}
    for r in rows:
        by_obj.setdefault((r.first.ev.device, r.first.cat, r.first.obj), []).append(r)
    for lst in by_obj.values():
        downs = [r for r in lst if r.first.state in ("down", "fail")]
        ups = [r for r in lst if r.first.state == "up"]
        for d in downs:
            for u in ups:
                if d.count + u.count >= 6 and u.first.ev.ts <= d.last_ts and d.first.ev.ts <= u.last_ts:
                    d.flapping = True
                    u.flapping = True
    incidents = _incidents(rows)
    devices = sorted({e.device for e in events})
    tz_missing = sorted({e.device for e in events if e.ts is not None and not e.absolute})
    return {
        "rows": rows,
        "incidents": incidents,
        "unknown": sorted(unknown.values(), key=lambda u: -int(u["count"])),  # type: ignore[arg-type]
        "traffic": traffic,
        "no_time": no_time,
        "devices": devices,
        "tz_missing": tz_missing,
        "classified": len(classified),
    }


def _anomalous(r: Row) -> bool:
    return r.first.sev != "info"


# relation rules: (cause cat/state, effect cat/state, max delay s, reason code, strength)
def _relation(c: Row, e: Row) -> Optional[Tuple[str, str]]:
    cc, ec = c.first, e.first
    delay = ec.ev.ts - cc.ev.ts
    if delay < 0:
        return None
    if cc.cat == "system" and delay <= 900:
        return "after-reboot", "high"
    if cc.cat == "interface" and cc.state == "down":
        if ec.intf and ec.intf == cc.obj and delay <= 180:
            return "same-interface", "high"
        if ec.cat in ("sdwan", "ipsec", "bgp", "ospf", "ha", "routing") and delay <= 180 and ec.ev.device == cc.ev.device:
            return "same-device-soon", "medium"
    if cc.cat == "conserve" and delay <= 900 and ec.ev.device == cc.ev.device:
        return "conserve-effects", "medium"
    if cc.cat == "ha" and delay <= 300:
        return "ha-effects", "medium"
    if cc.cat == "sdwan" and cc.state == "down" and ec.cat in ("ipsec", "bgp", "ospf") and delay <= 180:
        if ec.intf and ec.intf == cc.intf:
            return "same-interface", "high"
        if ec.ev.device == cc.ev.device:
            return "same-device-soon", "medium"
    if cc.cat == "ipsec" and cc.state in ("down", "fail") and ec.cat in ("bgp", "ospf") and delay <= 180:
        return "routing-over-tunnel", "medium"
    if delay <= 120 and ec.ev.device != cc.ev.device:
        return "other-device-soon", "low"
    return None


def _incidents(rows: List[Row]) -> List[Incident]:
    idx = [i for i, r in enumerate(rows) if _anomalous(r)]
    clusters: List[List[int]] = []
    for i in idx:
        if clusters and rows[i].first.ev.ts - rows[clusters[-1][-1]].first.ev.ts <= INCIDENT_GAP:
            clusters[-1].append(i)
        else:
            clusters.append([i])
    out: List[Incident] = []
    for cl in clusters:
        trig = cl[0]
        inc = Incident(trigger=trig)
        strengths = []
        for j in cl[1:]:
            best = None
            for k in [trig] + [c for c, _, _ in inc.chain]:
                rel = _relation(rows[k], rows[j])
                if rel and (best is None or _rank(rel[1]) > _rank(best[1])):
                    best = (rel[0], rel[1], k)
            delay = rows[j].first.ev.ts - rows[trig].first.ev.ts
            if best:
                inc.chain.append((j, best[0], delay))
                strengths.append(best[1])
            else:
                inc.chain.append((j, "same-timeframe", delay))
                strengths.append("low")
        # precursor: config change / admin login up to 10 minutes before
        t0 = rows[trig].first.ev.ts
        for i in range(trig - 1, -1, -1):
            r = rows[i]
            if t0 - r.first.ev.ts > 600:
                break
            if (r.first.cat, r.first.state) in {("config", "change"), ("admin", "login")}:
                inc.precursor = (i, t0 - r.first.ev.ts)
                break
        # confidence
        if not inc.chain:
            inc.confidence = "low"
            inc.reasons.append("single-event")
        elif strengths.count("high") >= 1 and strengths.count("low") <= len(strengths) // 2:
            inc.confidence = "high"
            inc.reasons.append("object-link")
        elif "medium" in strengths or "high" in strengths:
            inc.confidence = "medium"
            inc.reasons.append("time-link")
        else:
            inc.confidence = "low"
            inc.reasons.append("time-only")
        # ambiguity: another anomaly within 5 s on a different device
        for j in cl[1:]:
            if rows[j].first.ev.ts - t0 <= 5 and rows[j].first.ev.device != rows[trig].first.ev.device:
                inc.reasons.append("near-simultaneous")
                if inc.confidence == "high":
                    inc.confidence = "medium"
                break
        if rows[trig].first.ev.absolute is False:
            inc.reasons.append("no-timezone")
            if inc.confidence == "high":
                inc.confidence = "medium"
        out.append(inc)
    return out


def _rank(s: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}[s]


def row_dict(r: Row) -> Dict[str, object]:
    e = r.first
    return {
        "time": fmt_time(e.ev.ts, e.ev.absolute, e.ev.tz),
        "last": fmt_time(r.last_ts, e.ev.absolute, e.ev.tz) if r.count > 1 else None,
        "ts": e.ev.ts,
        "absolute": e.ev.absolute,
        "device": e.ev.device,
        "category": e.cat,
        "kind": e.kind,
        "state": e.state,
        "object": e.obj,
        "severity": e.sev,
        "count": r.count,
        "flapping": r.flapping,
        "logid": e.ev.fields.get("logid", ""),
        "source": e.ev.source,
        "line": e.ev.line,
        "user": e.ev.fields.get("user", "") if e.cat in ("admin", "config") else "",
    }


def findings_from(tl: Dict[str, object]) -> List[Finding]:
    rows: List[Row] = tl["rows"]  # type: ignore[assignment]
    out: List[Finding] = []
    for n, inc in enumerate(tl["incidents"]):  # type: ignore[union-attr]
        trig = rows[inc.trigger]
        sevs = [trig.first.sev] + [rows[j].first.sev for j, _, _ in inc.chain]
        sev = "high" if "high" in sevs else "medium" if "medium" in sevs else "low"
        chain = []
        for j, reason, delay in inc.chain[:12]:
            chain.append({"row": j, "reason": reason, "delay": round(delay), **row_dict(rows[j])})
        params = {
            "n": n + 1,
            "trigger": row_dict(trig),
            "chain": chain,
            "more": max(0, len(inc.chain) - 12),
            "confidence": inc.confidence,
            "reasons": inc.reasons,
            "precursor": ({**row_dict(rows[inc.precursor[0]]), "before": round(inc.precursor[1])} if inc.precursor else None),
            "events": 1 + len(inc.chain),
        }
        out.append(Finding("timeline", "timeline.incident", sev, None,
                           [Obj("device", trig.first.ev.device), Obj(trig.first.cat, trig.first.obj)], params, n))
    return out
