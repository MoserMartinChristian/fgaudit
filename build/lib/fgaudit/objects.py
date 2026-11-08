"""Resolution of FortiOS objects (addresses, services, interfaces, users) into
sets that can be compared. Anything that cannot be resolved statically is
kept as a named *dynamic* part, so the checks can report "not reliably
checkable" instead of guessing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .model import FortiConfig, Vdom
from .netsets import (
    EMPTY,
    V4_ALL,
    V4_MAX,
    V6_ALL,
    V6_MAX,
    IntervalSet,
    v4_int,
    v4_subnet,
    v6_int,
    v6_prefix,
)
from .parser import Entry

# --------------------------------------------------------------------------- #
# addresses


@dataclass(frozen=True)
class Dyn:
    name: str
    kind: str  # fqdn, geography, dynamic, vip, isdb, unknown, ...


@dataclass
class AddrSet:
    ip: IntervalSet = EMPTY
    dyn: Tuple[Dyn, ...] = ()

    def union(self, o: "AddrSet") -> "AddrSet":
        d = self.dyn + tuple(x for x in o.dyn if x not in self.dyn)
        return AddrSet(self.ip.union(o.ip), d)


_DYNAMIC_V4_TYPES = {
    "fqdn": "fqdn",
    "geography": "geography",
    "dynamic": "dynamic",
    "interface-subnet": "interface-subnet",
    "wildcard": "wildcard",
    "wildcard-fqdn": "fqdn",
    "mac": "mac",
    "route-tag": "route-tag",
    "ipam": "ipam",
}
_DYNAMIC_V6_TYPES = {
    "fqdn": "fqdn",
    "geography": "geography",
    "dynamic": "dynamic",
    "template": "template",
    "mac": "mac",
    "route-tag": "route-tag",
    "wildcard": "wildcard",
    "ipam": "ipam",
}


class AddressBook:
    """Resolves address names for one VDOM and one IP family."""

    def __init__(self, vd: Vdom, v6: bool = False):
        self.v6 = v6
        suffix = "6" if v6 else ""
        self.addr = vd.table("firewall address" + suffix)
        self.grp = vd.table("firewall addrgrp" + suffix)
        self.vip = vd.table("firewall vip" + suffix)
        self.vipgrp = vd.table("firewall vipgrp" + suffix)
        # IPv4 policies may also reference "vip46"/"vip64" etc.; they are
        # treated as VIPs when found in any of these tables.
        self.other_vips = [vd.table(t) for t in ("firewall vip46", "firewall vip64", "firewall vip6", "firewall vipgrp6", "firewall vip", "firewall vipgrp")]
        self.full = V6_ALL if v6 else V4_ALL
        self.max = V6_MAX if v6 else V4_MAX
        self._cache: Dict[str, AddrSet] = {}

    def resolve_many(self, names: List[str]) -> AddrSet:
        out = AddrSet()
        for n in names:
            out = out.union(self.resolve(n))
        return out

    def resolve(self, name: str, _stack: Optional[Set[str]] = None) -> AddrSet:
        if name in self._cache:
            return self._cache[name]
        stack = _stack or set()
        if name in stack:
            return AddrSet(dyn=(Dyn(name, "group-cycle"),))
        stack = stack | {name}
        res = self._resolve(name, stack)
        self._cache[name] = res
        return res

    def _resolve(self, name: str, stack: Set[str]) -> AddrSet:
        ent = self.addr.entries.get(name)
        if ent is not None:
            return self._addr_entry(ent)
        g = self.grp.entries.get(name)
        if g is not None:
            gtype = g.get("type", "default")
            if gtype not in ("default", "folder"):
                return AddrSet(dyn=(Dyn(name, "dynamic"),))
            members = AddrSet()
            for m in g.get_list("member"):
                members = members.union(self.resolve(m, stack))
            if g.get("exclude", "disable") == "enable":
                ex = AddrSet()
                for m in g.get_list("exclude-member"):
                    ex = ex.union(self.resolve(m, stack))
                if ex.dyn or members.dyn:
                    return AddrSet(dyn=(Dyn(name, "exclude-dynamic"),))
                return AddrSet(members.ip.difference(ex.ip))
            return members
        if name in self.vip.entries or name in self.vipgrp.entries or any(name in t.entries for t in self.other_vips):
            return AddrSet(dyn=(Dyn(name, "vip"),))
        if name == "all":
            return AddrSet(self.full)
        if name == "none":
            return AddrSet()
        return AddrSet(dyn=(Dyn(name, "unknown"),))

    def _addr_entry(self, ent: Entry) -> AddrSet:
        name = ent.key
        if self.v6:
            t = ent.get("type", "ipprefix")
            if t in _DYNAMIC_V6_TYPES:
                return AddrSet(dyn=(Dyn(name, _DYNAMIC_V6_TYPES[t]),))
            if ent.get("sdn") or ent.get("host-type", "any") != "any":
                return AddrSet(dyn=(Dyn(name, "dynamic"),))
            if t == "iprange":
                lo = v6_int(ent.get("start-ip", "::") or "::")
                hi = v6_int(ent.get("end-ip", "::") or "::")
                if lo is None or hi is None or lo > hi:
                    return AddrSet(dyn=(Dyn(name, "unparsable"),))
                return AddrSet(IntervalSet.single(lo, hi))
            if t == "ipprefix":
                p = v6_prefix(ent.get("ip6", "::/0") or "::/0")
                if p is None:
                    return AddrSet(dyn=(Dyn(name, "unparsable"),))
                return AddrSet(IntervalSet.single(p[0], p[1]))
            return AddrSet(dyn=(Dyn(name, "unknown-type"),))
        t = ent.get("type", "ipmask")
        if t in _DYNAMIC_V4_TYPES:
            return AddrSet(dyn=(Dyn(name, _DYNAMIC_V4_TYPES[t]),))
        if ent.get("sdn"):
            return AddrSet(dyn=(Dyn(name, "dynamic"),))
        if t == "iprange":
            lo = v4_int(ent.get("start-ip", "0.0.0.0") or "0.0.0.0")
            hi = v4_int(ent.get("end-ip", "0.0.0.0") or "0.0.0.0")
            if lo is None or hi is None or lo > hi:
                return AddrSet(dyn=(Dyn(name, "unparsable"),))
            return AddrSet(IntervalSet.single(lo, hi))
        if t == "ipmask":
            toks = ent.get_list("subnet") or ["0.0.0.0", "0.0.0.0"]
            s = v4_subnet(toks)
            if s is None:
                return AddrSet(dyn=(Dyn(name, "unparsable"),))
            return AddrSet(IntervalSet.single(s[0], s[1]))
        return AddrSet(dyn=(Dyn(name, "unknown-type"),))


# --------------------------------------------------------------------------- #
# services
#
# A service is a mapping protocol -> list of rectangles (dport_lo, dport_hi,
# sport_lo, sport_hi). For ICMP the "ports" are ICMP type and code.

Rect = Tuple[int, int, int, int]
FULL_RECT: Rect = (0, 65535, 0, 65535)
ICMP_FULL: Rect = (0, 255, 0, 255)


@dataclass
class SvcSet:
    all: bool = False
    protos: Dict[int, List[Rect]] = field(default_factory=dict)
    dyn: Tuple[Dyn, ...] = ()

    def add(self, proto: int, rect: Rect) -> None:
        self.protos.setdefault(proto, []).append(rect)

    def union(self, o: "SvcSet") -> "SvcSet":
        r = SvcSet(all=self.all or o.all)
        for p, rs in self.protos.items():
            r.protos[p] = list(rs)
        for p, rs in o.protos.items():
            r.protos.setdefault(p, []).extend(rs)
        r.dyn = self.dyn + tuple(x for x in o.dyn if x not in self.dyn)
        return r

    def is_empty(self) -> bool:
        return not self.all and not self.protos and not self.dyn


def _full_rect_for(proto: int) -> Rect:
    return ICMP_FULL if proto in (1, 58) else FULL_RECT


def parse_portrange(spec: str) -> Optional[Rect]:
    """``dst[-dst][:src[-src]]`` -> rect."""
    dst, _, src = spec.partition(":")

    def rng(s: str, default: Tuple[int, int]) -> Optional[Tuple[int, int]]:
        if not s:
            return default
        lo, _, hi = s.partition("-")
        try:
            a = int(lo)
            b = int(hi) if hi else a
        except ValueError:
            return None
        if a > b or a < 0 or b > 65535:
            return None
        return a, b

    d = rng(dst, (0, 65535))
    s = rng(src, (0, 65535))
    if d is None or s is None:
        return None
    return (d[0], d[1], s[0], s[1])


class ServiceBook:
    def __init__(self, vd: Vdom):
        self.custom = vd.table("firewall service custom")
        self.group = vd.table("firewall service group")
        self._cache: Dict[str, SvcSet] = {}

    def resolve_many(self, names: List[str]) -> SvcSet:
        out = SvcSet()
        for n in names:
            out = out.union(self.resolve(n))
        return out

    def resolve(self, name: str, _stack: Optional[Set[str]] = None) -> SvcSet:
        if name in self._cache:
            return self._cache[name]
        stack = _stack or set()
        if name in stack:
            return SvcSet(dyn=(Dyn(name, "group-cycle"),))
        stack = stack | {name}
        ent = self.custom.entries.get(name)
        if ent is not None:
            res = self._custom(ent)
        else:
            g = self.group.entries.get(name)
            if g is not None:
                if g.get("proxy", "disable") == "enable":
                    res = SvcSet(dyn=(Dyn(name, "proxy"),))
                else:
                    res = SvcSet()
                    for m in g.get_list("member"):
                        res = res.union(self.resolve(m, stack))
            else:
                res = SvcSet(dyn=(Dyn(name, "unknown"),))
        self._cache[name] = res
        return res

    def _custom(self, ent: Entry) -> SvcSet:
        name = ent.key
        if ent.get("proxy", "disable") == "enable":
            return SvcSet(dyn=(Dyn(name, "proxy"),))
        iprange = ent.get("iprange", "0.0.0.0") or "0.0.0.0"
        fqdn = ent.get("fqdn", "") or ""
        if iprange not in ("0.0.0.0", "0.0.0.0-0.0.0.0") or fqdn:
            return SvcSet(dyn=(Dyn(name, "service-address"),))
        proto = (ent.get("protocol") or "TCP/UDP/SCTP").upper()
        s = SvcSet()
        if proto.startswith("TCP/UDP"):
            any_range = False
            for key, pnum in (("tcp-portrange", 6), ("udp-portrange", 17), ("udplite-portrange", 136), ("sctp-portrange", 132)):
                for spec in ent.get_list(key):
                    r = parse_portrange(spec)
                    if r is None:
                        return SvcSet(dyn=(Dyn(name, "unparsable"),))
                    s.add(pnum, r)
                    any_range = True
            if not any_range:
                return SvcSet(dyn=(Dyn(name, "no-ports"),))
            return s
        if proto in ("ICMP", "ICMP6"):
            pnum = 1 if proto == "ICMP" else 58
            t = ent.get("icmptype")
            c = ent.get("icmpcode")
            try:
                tr = (int(t), int(t)) if t not in (None, "") else (0, 255)
                cr = (int(c), int(c)) if c not in (None, "") else (0, 255)
            except ValueError:
                return SvcSet(dyn=(Dyn(name, "unparsable"),))
            s.add(pnum, (tr[0], tr[1], cr[0], cr[1]))
            return s
        if proto == "IP":
            try:
                num = int(ent.get("protocol-number", "0") or "0")
            except ValueError:
                return SvcSet(dyn=(Dyn(name, "unparsable"),))
            if num == 0:
                return SvcSet(all=True)
            s.add(num, _full_rect_for(num))
            return s
        # HTTP, FTP, CONNECT, SOCKS-TCP, SOCKS-UDP, ALL (proxy) ...
        return SvcSet(dyn=(Dyn(name, "proxy"),))


def _rects_cover(target: Rect, rects: List[Rect]) -> bool:
    """True if the union of ``rects`` covers ``target`` completely."""
    dlo, dhi, slo, shi = target
    rel = [r for r in rects if r[0] <= dhi and r[1] >= dlo and r[2] <= shi and r[3] >= slo]
    if not rel:
        return False
    # elementary segments on the source-port axis
    cuts = {slo, shi + 1}
    for r in rel:
        if slo < r[2] <= shi:
            cuts.add(r[2])
        if slo <= r[3] + 1 <= shi:
            cuts.add(r[3] + 1)
    pts = sorted(cuts)
    for a, b in zip(pts, pts[1:]):
        seg_lo, seg_hi = a, b - 1
        d = IntervalSet([(max(r[0], dlo), min(r[1], dhi)) for r in rel if r[2] <= seg_lo and r[3] >= seg_hi])
        if not IntervalSet.single(dlo, dhi).issubset(d):
            return False
    return True


def svc_static_covers(e: SvcSet, l: SvcSet) -> bool:
    """Static part of e covers static part of l."""
    if e.all:
        return True
    if l.all:
        return False
    for p, rects in l.protos.items():
        er = e.protos.get(p, [])
        for r in rects:
            if not _rects_cover(r, er):
                return False
    return True


def svc_static_intersects(a: SvcSet, b: SvcSet) -> bool:
    if (a.all and (b.all or b.protos)) or (b.all and a.protos):
        return True
    for p, rects in a.protos.items():
        for r in rects:
            for q in b.protos.get(p, []):
                if r[0] <= q[1] and q[0] <= r[1] and r[2] <= q[3] and q[2] <= r[3]:
                    return True
    return False


# --------------------------------------------------------------------------- #
# interfaces / zones


class InterfaceBook:
    """Expands zone names (normal and SD-WAN zones) to member interfaces."""

    def __init__(self, fc: FortiConfig, vd: Vdom):
        self.zones: Dict[str, FrozenSet[str]] = {}
        for z in vd.table("system zone"):
            self.zones[z.key] = frozenset(z.get_list("interface"))
        sdwan = vd.table("system sdwan")
        members = sdwan.child("members")
        zone_members: Dict[str, Set[str]] = {}
        if members is not None:
            for m in members:
                iface = m.get("interface")
                if iface:
                    zone_members.setdefault(m.get("zone", "virtual-wan-link") or "virtual-wan-link", set()).add(iface)
        zt = sdwan.child("zone")
        if zt is not None:
            for z in zt:
                zone_members.setdefault(z.key, set())
        for z, ms in zone_members.items():
            self.zones.setdefault(z, frozenset(ms))

    def expand(self, names: List[str]) -> Tuple[bool, FrozenSet[str]]:
        """Return (is_any, set_of_interfaces)."""
        out: Set[str] = set()
        for n in names:
            if n == "any":
                return True, frozenset()
            z = self.zones.get(n)
            if z is not None and z:
                out |= z
            else:
                out.add(n)
        return False, frozenset(out)


# --------------------------------------------------------------------------- #
# users / groups


class UserBook:
    def __init__(self, vd: Vdom):
        self.local_groups: Dict[str, FrozenSet[str]] = {}
        self.remote_groups: Set[str] = set()
        for g in vd.table("user group"):
            gtype = g.get("group-type", "firewall")
            match = g.child("match")
            if gtype != "firewall" or (match is not None and len(match) > 0):
                self.remote_groups.add(g.key)
            self.local_groups[g.key] = frozenset(g.get_list("member"))
