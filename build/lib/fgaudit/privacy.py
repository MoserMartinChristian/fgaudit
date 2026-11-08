"""Secret redaction (always on) and consistent anonymization (--anonymize).

Both work on the finished report data: every string in the report passes
through them before anything is rendered, so terminal, HTML and JSON output
are covered alike."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
from dataclasses import fields, is_dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

REDACTED = "<redacted>"

_ENC_RE = re.compile(r"ENC\s+[A-Za-z0-9+/=]{8,}")
_PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)


class Redactor:
    def __init__(self, secrets: Iterable[str]):
        vals = {s for s in secrets if s and len(s) >= 4}
        # also redact the parts of multi-token secret values
        self.secrets: List[str] = sorted(vals, key=len, reverse=True)

    def __call__(self, s: str) -> str:
        if not s:
            return s
        s = _PEM_RE.sub(REDACTED, s)
        s = _ENC_RE.sub(REDACTED, s)
        for v in self.secrets:
            if v in s:
                s = s.replace(v, REDACTED)
        return s


# --------------------------------------------------------------------------- #

_V4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!\.?\d)")
_V6 = re.compile(r"(?<![\w:])((?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})(?![\w:])")

# Names that are generic and safe to keep.
SAFE_NAMES = {
    "all", "any", "none", "always", "root", "ALL", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "ALL_ICMP6",
    "virtual-wan-link", "default", "ssl.root", "accept", "deny", "enable", "disable", "admin",
}
_SAFE_RE = re.compile(r"^(port\d+|wan\d*|lan\d*|internal\d*|dmz\d*|mgmt\d*|ha\d*|x\d+|a|b|fortilink|loopback\d*|npu\d+_vlink\d+|agg\d+|ssl\.\w+)$", re.I)


class Anonymizer:
    """Replaces IPs (prefix-preserving, keyed per run) and known names."""

    def __init__(self, key: Optional[bytes] = None):
        self.key = key or os.urandom(32)
        self.names: Dict[str, str] = {}
        self.counters: Dict[str, int] = {}
        self._ipcache: Dict[str, str] = {}
        self._name_re: Optional[re.Pattern] = None

    # names -----------------------------------------------------------
    def add_name(self, name: str, kind: str) -> None:
        if not name or name in self.names or name in SAFE_NAMES or _SAFE_RE.match(name):
            return
        if _V4.fullmatch(name):
            return  # handled by IP replacement
        n = self.counters.get(kind, 0) + 1
        self.counters[kind] = n
        self.names[name] = f"{kind}-{n:03d}"
        self._name_re = None

    def _regex(self) -> Optional[re.Pattern]:
        if self._name_re is None and self.names:
            parts = sorted(self.names, key=len, reverse=True)
            self._name_re = re.compile(r"(?<![\w-])(" + "|".join(re.escape(p) for p in parts) + r")(?![\w-])")
        return self._name_re

    # ips ---------------------------------------------------------------
    def _bits(self, value: int, width: int) -> int:
        out = 0
        for i in range(width):
            prefix = value >> (width - i)
            bit = (value >> (width - 1 - i)) & 1
            mac = hmac.new(self.key, f"{width}:{i}:{prefix}".encode(), hashlib.sha256).digest()
            out = (out << 1) | (bit ^ (mac[0] & 1))
        return out

    def ip(self, s: str) -> str:
        if s in self._ipcache:
            return self._ipcache[s]
        try:
            a = ipaddress.ip_address(s)
        except ValueError:
            return s
        if a.version == 4:
            v = int(a)
            if v == 0 or s.startswith("255.") or v == 0xFFFFFFFF:
                r = s  # masks, 0.0.0.0 and broadcast carry no information
            else:
                r = str(ipaddress.IPv4Address(self._bits(v, 32)))
        else:
            v = int(a)
            r = s if v == 0 else str(ipaddress.IPv6Address(self._bits(v, 128)))
        self._ipcache[s] = r
        return r

    def __call__(self, s: str) -> str:
        if not s:
            return s
        s = _V4.sub(lambda m: self.ip(m.group(1)), s)
        s = _V6.sub(lambda m: self.ip(m.group(1)) if _is_v6(m.group(1)) else m.group(1), s)
        rx = self._regex()
        if rx is not None:
            s = rx.sub(lambda m: self.names[m.group(1)], s)
        return s


def _is_v6(s: str) -> bool:
    try:
        return ipaddress.ip_address(s).version == 6
    except ValueError:
        return False


# Field names whose values are names that must be anonymized
NAME_FIELDS_LOG = ("devname", "user", "srcname", "dstname", "hostname", "vpntunnel", "name", "healthcheck", "group", "xauthuser", "cfgobj", "remote_user")


def collect_config_names(anon: Anonymizer, fc) -> None:
    from .parser import Config

    anon.add_name(fc.filename, "file")
    if fc.header_user:
        anon.add_name(fc.header_user, "user")
    gl = fc.global_root.children.get("system global")
    if gl is not None:
        for k in ("hostname", "alias"):
            v = gl.get(k)
            if v:
                anon.add_name(v, "host")
    for name in fc.vdoms:
        anon.add_name(name, "vdom")

    kinds = {
        "firewall address": "addr", "firewall address6": "addr", "firewall addrgrp": "addrgrp", "firewall addrgrp6": "addrgrp",
        "firewall service custom": "svc", "firewall service group": "svcgrp", "firewall vip": "vip", "firewall vipgrp": "vip",
        "firewall ippool": "pool", "system interface": "intf", "system zone": "zone", "user local": "user", "user group": "group",
        "system admin": "user", "vpn ipsec phase1-interface": "vpn", "vpn ipsec phase2-interface": "vpn",
        "firewall schedule recurring": "sched", "firewall schedule onetime": "sched", "firewall schedule group": "sched",
        "router bgp": "bgp", "system dhcp server": "dhcp", "user ldap": "srv", "user radius": "srv",
    }

    def walk(c: Config, path: str) -> None:
        for p, ch in c.children.items():
            kind = kinds.get(p, "obj")
            for e in ch.entries.values():
                if not e.key.isdigit():
                    anon.add_name(e.key, kind)
                for k in ("name", "alias", "comments", "comment", "description", "hostname", "member", "interface", "users", "groups"):
                    for v in e.settings.get(k, []):
                        if not v.isdigit():
                            anon.add_name(v, "obj" if k not in ("users",) else "user")
                walk(e, p)  # type: ignore[arg-type]
            walk(ch, p)

    walk(fc.parsed.root, "")


def collect_log_names(anon: Anonymizer, events, sources: Iterable[str]) -> None:
    for s in sources:
        anon.add_name(s, "file")
    for e in events:
        for k in NAME_FIELDS_LOG:
            v = e.fields.get(k)
            if v and not v.isdigit():
                anon.add_name(v, "host" if k in ("devname", "hostname", "srcname", "dstname") else "user" if "user" in k else "obj")
        for k in ("devid", "sn"):
            v = e.fields.get(k)
            if v:
                anon.add_name(v, "serial")
        for k in ("intf", "interface", "devintfname", "outintf", "member"):
            v = e.fields.get(k)
            if v and not v.isdigit():
                anon.add_name(v, "intf")
        msg = e.fields.get("msg", "")
        # names quoted in msg text, e.g. name="xyz"
        for m in re.finditer(r'"([^"]{2,64})"', msg):
            anon.add_name(m.group(1), "obj")


def transform(obj: Any, fn: Callable[[str], str], _seen: Optional[Set[int]] = None) -> Any:
    """Apply fn to every string inside obj (dataclasses, dicts, lists)."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, dict):
        return {transform(k, fn) if isinstance(k, str) else k: transform(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [transform(v, fn) for v in obj]
    if isinstance(obj, tuple):
        return tuple(transform(v, fn) for v in obj)
    if is_dataclass(obj) and not isinstance(obj, type):
        for f in fields(obj):
            setattr(obj, f.name, transform(getattr(obj, f.name), fn))
        return obj
    return obj
