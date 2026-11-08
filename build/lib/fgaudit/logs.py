"""Parser for FortiGate key=value log lines (disk/memory export, FortiAnalyzer
export, syslog with or without a syslog header).

Field names and message IDs follow the FortiOS Log Message Reference
(7.4, 7.6 and 8.0). See docs/SOURCES.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Tuple

_KV_START = re.compile(r'(?:^|[\s>])(?=(?:date|logver|itime|eventtime|logid|devname|devid|timestamp)=)')
_KV = re.compile(r'([A-Za-z_][\w.-]*)=("(?:[^"\\]|\\.)*"|[^\s]*)')
_TZ = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


@dataclass
class LogEvent:
    fields: Dict[str, str]
    source: str  # file label
    line: int
    ts: Optional[float]  # seconds since epoch (UTC) when absolute, else local seconds
    absolute: bool
    tz: Optional[str]
    device: str

    def get(self, k: str, d: str = "") -> str:
        return self.fields.get(k, d)

    @property
    def msgid(self) -> str:
        lid = self.fields.get("logid", "")
        return lid[-5:].lstrip("0") if lid.isdigit() and len(lid) >= 5 else lid


@dataclass
class LogParseResult:
    events: List[LogEvent] = field(default_factory=list)
    lines: int = 0
    unparseable: int = 0
    no_time: int = 0
    secret_values: List[str] = field(default_factory=list)


def parse_kv(line: str) -> Optional[Dict[str, str]]:
    m = _KV_START.search(line)
    if not m:
        return None
    body = line[m.end():]
    out: Dict[str, str] = {}
    for k, v in _KV.findall(body):
        if v.startswith('"') and v.endswith('"') and len(v) >= 2:
            v = re.sub(r"\\(.)", r"\1", v[1:-1])
        out[k] = v
    if "logid" not in out and "type" not in out:
        return None
    return out


def _tz_offset(tz: str) -> Optional[timedelta]:
    tz = tz.strip()
    if tz.upper() in ("UTC", "GMT", "Z"):
        return timedelta(0)
    m = _TZ.match(tz)
    if not m:
        return None
    sign = -1 if m.group(1) == "-" else 1
    return sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))


def event_time(f: Dict[str, str]) -> Tuple[Optional[float], bool, Optional[str]]:
    """Return (timestamp, absolute, tz).

    ``eventtime`` is an epoch value (the Log Message Reference documents it as
    "Epoch time the log was triggered"), so it is absolute. Its unit is
    detected by magnitude (s, ms, us, ns). Without it, date+time are used,
    and they are only absolute if ``tz`` is present."""
    tz = f.get("tz") or None
    et = f.get("eventtime", "")
    if et.isdigit():
        n = int(et)
        digits = len(et)
        if digits >= 18:
            sec = n / 1e9
        elif digits >= 15:
            sec = n / 1e6
        elif digits >= 12:
            sec = n / 1e3
        else:
            sec = float(n)
        if 946684800 <= sec <= 4102444800:  # 2000..2100 sanity check
            return sec, True, tz
    d, t = f.get("date", ""), f.get("time", "")
    if d and t:
        try:
            dt = datetime.strptime(f"{d} {t[:8]}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None, False, tz
        off = _tz_offset(tz) if tz else None
        if off is not None:
            return (dt - off).replace(tzinfo=timezone.utc).timestamp(), True, tz
        return dt.replace(tzinfo=timezone.utc).timestamp(), False, None
    return None, False, tz


_SECRETISH = re.compile(r"(pass|secret|psk|pwd|token|key)", re.I)


def parse_lines(lines: Iterable[str], source: str, start: int = 1) -> LogParseResult:
    res = LogParseResult()
    for i, line in enumerate(lines, start):
        if not line.strip():
            continue
        res.lines += 1
        f = parse_kv(line)
        if f is None:
            res.unparseable += 1
            continue
        for k, v in f.items():
            if _SECRETISH.search(k) and len(v) >= 4:
                res.secret_values.append(v)
        ts, absolute, tz = event_time(f)
        if ts is None:
            res.no_time += 1
        dev = f.get("devname") or f.get("devid") or source
        res.events.append(LogEvent(f, source, i, ts, absolute, tz, dev))
    return res


def fmt_time(ev_ts: float, absolute: bool, tz: Optional[str]) -> str:
    if absolute:
        off = _tz_offset(tz) if tz else None
        if off is not None:
            dt = datetime.fromtimestamp(ev_ts, timezone(off))
            return dt.strftime("%Y-%m-%d %H:%M:%S ") + dt.strftime("%z")
        return datetime.fromtimestamp(ev_ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return datetime.fromtimestamp(ev_ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S") + " (?)"
