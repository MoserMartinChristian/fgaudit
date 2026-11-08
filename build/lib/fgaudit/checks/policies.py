"""Resolved firewall policy model and the coverage logic used by the shadow
check and the change check.

Coverage is three-valued: YES (proven), NO (proven not, or not provable in a
way that could make a finding), UNKNOWN (would need information the backup
does not contain, e.g. what an FQDN resolves to)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple

from ..model import FortiConfig, Vdom
from ..netsets import V4_ALL, V6_ALL, IntervalSet
from ..objects import (
    AddrSet,
    AddressBook,
    Dyn,
    InterfaceBook,
    ServiceBook,
    SvcSet,
    UserBook,
    svc_static_covers,
    svc_static_intersects,
)
from ..parser import Entry

YES, NO, UNKNOWN = "yes", "no", "unknown"

PROFILE_FIELDS = (
    "profile-type",
    "profile-group",
    "av-profile",
    "webfilter-profile",
    "dnsfilter-profile",
    "emailfilter-profile",
    "dlp-profile",
    "file-filter-profile",
    "ips-sensor",
    "application-list",
    "voip-profile",
    "ips-voip-filter",
    "sctp-filter-profile",
    "diameter-filter-profile",
    "virtual-patch-profile",
    "icap-profile",
    "videofilter-profile",
    "waf-profile",
    "ssh-filter-profile",
    "casb-profile",
    "ssl-ssh-profile",
    "profile-protocol-options",
)

ISDB_DST_FIELDS = ("internet-service-name", "internet-service-group", "internet-service-custom", "internet-service-custom-group", "internet-service-fortiguard", "internet-service-negate")
ISDB_SRC_FIELDS = ("internet-service-src-name", "internet-service-src-group", "internet-service-src-custom", "internet-service-src-custom-group", "internet-service-src-fortiguard", "internet-service-src-negate")
ISDB6_DST_FIELDS = tuple(f.replace("internet-service", "internet-service6") for f in ISDB_DST_FIELDS)
ISDB6_SRC_FIELDS = tuple(f.replace("internet-service", "internet-service6") for f in ISDB_SRC_FIELDS)

# Fields that restrict matching in ways fgaudit does not model. If the
# earlier policy sets one of them (and the later one does not set the same
# value), coverage cannot be proven.
RESTRICTING_FIELDS = {
    "ztna-status": "disable",
    "ztna-ems-tag": None,
    "ztna-ems-tag-secondary": None,
    "ztna-geo-tag": None,
    "ztna-ems-tag6": None,
    "src-vendor-mac": None,
    "sgt-check": "disable",
    "sgt": None,
    "reputation-minimum": "0",
    "reputation-minimum6": "0",
    "network-service-dynamic": None,
    "network-service-src-dynamic": None,
    "tos-mask": "0x00",
    "vlan-filter": None,
    "policy-expiry": "disable",
    "vpntunnel": None,
    "scim": "disable",
    "scim-users": None,
    "scim-groups": None,
    "saml-server": None,
    "ztna-device-ownership": "disable",
    "internet-service": "disable",
    "internet-service-src": "disable",
    "internet-service6": "disable",
    "internet-service6-src": "disable",
    "devices": None,
    "users-dynamic": None,
}

MATCH_FIELDS = (
    "srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr6", "dstaddr6",
    "srcaddr-negate", "dstaddr-negate", "srcaddr6-negate", "dstaddr6-negate",
    "service", "service-negate", "schedule", "users", "groups", "fsso-groups",
    "internet-service", "internet-service-src", "internet-service6", "internet-service6-src",
) + ISDB_DST_FIELDS + ISDB_SRC_FIELDS + ISDB6_DST_FIELDS + ISDB6_SRC_FIELDS + tuple(RESTRICTING_FIELDS)

# default values of match fields (as written in backups when not shown)
FIELD_DEFAULTS = {
    "srcaddr-negate": "disable", "dstaddr-negate": "disable",
    "srcaddr6-negate": "disable", "dstaddr6-negate": "disable",
    "service-negate": "disable",
}


@dataclass
class Family:
    src: AddrSet
    dst: AddrSet
    src_neg: bool
    dst_neg: bool
    full: IntervalSet
    isdb_dst: bool
    isdb_src: bool


@dataclass
class Policy:
    id: str
    seq: int
    name: str
    status: bool
    action: str
    entry: Entry
    srcintf: Tuple[bool, FrozenSet[str]]
    dstintf: Tuple[bool, FrozenSet[str]]
    fam: Dict[str, Family]
    svc: SvcSet
    svc_neg: bool
    schedule: str
    users: FrozenSet[str]
    groups: FrozenSet[str]
    fsso: FrozenSet[str]
    restricting: Dict[str, Tuple[str, ...]]
    profiles: Dict[str, Tuple[str, ...]]
    match_sig: Tuple
    logtraffic: str
    nat: bool
    # prefilter data
    bounds: Dict[str, Tuple[Optional[Tuple[int, int]], Optional[Tuple[int, int]]]] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"{self.id}" + (f' "{self.name}"' if self.name else "")


def _vals(e: Entry, name: str) -> Tuple[str, ...]:
    return tuple(e.settings.get(name, ()))


def match_signature(e: Entry) -> Tuple:
    sig = []
    for f in MATCH_FIELDS:
        v = e.settings.get(f)
        if v is None:
            d = FIELD_DEFAULTS.get(f) or RESTRICTING_FIELDS.get(f)
            v = [d] if d else []
        if f in ("schedule",) and not v:
            v = ["always"]
        sig.append((f, tuple(sorted(v))))
    return tuple(sig)


class PolicyContext:
    """Resolver bundle for one VDOM."""

    def __init__(self, fc: FortiConfig, vd: Vdom):
        self.fc = fc
        self.vd = vd
        self.a4 = AddressBook(vd, v6=False)
        self.a6 = AddressBook(vd, v6=True)
        self.svc = ServiceBook(vd)
        self.intf = InterfaceBook(fc, vd)
        self.users = UserBook(vd)

    def build(self, e: Entry, seq: int) -> Policy:
        s = e.settings
        fam: Dict[str, Family] = {}
        isdb4_dst = e.get("internet-service", "disable") == "enable"
        isdb4_src = e.get("internet-service-src", "disable") == "enable"
        isdb6_dst = e.get("internet-service6", "disable") == "enable"
        isdb6_src = e.get("internet-service6-src", "disable") == "enable"
        src4 = list(s.get("srcaddr", []))
        dst4 = list(s.get("dstaddr", []))
        if (src4 or isdb4_src) and (dst4 or isdb4_dst):
            fam["v4"] = Family(
                src=self._isdb_or(self.a4, src4, isdb4_src, e, ISDB_SRC_FIELDS),
                dst=self._isdb_or(self.a4, dst4, isdb4_dst, e, ISDB_DST_FIELDS),
                src_neg=e.get("srcaddr-negate", "disable") == "enable",
                dst_neg=e.get("dstaddr-negate", "disable") == "enable",
                full=V4_ALL, isdb_dst=isdb4_dst, isdb_src=isdb4_src,
            )
        src6 = list(s.get("srcaddr6", []))
        dst6 = list(s.get("dstaddr6", []))
        if (src6 or isdb6_src) and (dst6 or isdb6_dst):
            fam["v6"] = Family(
                src=self._isdb_or(self.a6, src6, isdb6_src, e, ISDB6_SRC_FIELDS),
                dst=self._isdb_or(self.a6, dst6, isdb6_dst, e, ISDB6_DST_FIELDS),
                src_neg=e.get("srcaddr6-negate", "disable") == "enable",
                dst_neg=e.get("dstaddr6-negate", "disable") == "enable",
                full=V6_ALL, isdb_dst=isdb6_dst, isdb_src=isdb6_src,
            )
        if isdb4_dst or isdb6_dst:
            svc = SvcSet(dyn=(Dyn("internet-service", "isdb"),))
        else:
            svc = self.svc.resolve_many(list(s.get("service", [])))
            if not s.get("service"):
                svc = SvcSet(dyn=(Dyn("(none)", "unknown"),))
        restricting = {}
        for f, default in RESTRICTING_FIELDS.items():
            if f in ("internet-service", "internet-service-src", "internet-service6", "internet-service6-src"):
                continue
            v = _vals(e, f)
            if v and (default is None or tuple(v) != (default,)):
                restricting[f] = v
        profiles = {}
        utm = e.get("utm-status", "disable") == "enable"
        for f in PROFILE_FIELDS:
            v = _vals(e, f)
            if v and (utm or f in ("ssl-ssh-profile", "profile-protocol-options")):
                profiles[f] = v
        p = Policy(
            id=e.key,
            seq=seq,
            name=e.get("name", "") or "",
            status=e.get("status", "enable") != "disable",
            action=e.get("action", "deny") or "deny",
            entry=e,
            srcintf=self.intf.expand(list(s.get("srcintf", []))),
            dstintf=self.intf.expand(list(s.get("dstintf", []))),
            fam=fam,
            svc=svc,
            svc_neg=e.get("service-negate", "disable") == "enable",
            schedule=e.get("schedule", "always") or "always",
            users=frozenset(s.get("users", [])),
            groups=frozenset(s.get("groups", [])),
            fsso=frozenset(s.get("fsso-groups", [])),
            restricting=restricting,
            profiles=profiles,
            match_sig=match_signature(e),
            logtraffic=e.get("logtraffic", "utm") or "utm",
            nat=e.get("nat", "disable") == "enable",
        )
        for k, f in fam.items():
            p.bounds[k] = (f.src.ip.bounds(), f.dst.ip.bounds())
        return p

    def _isdb_or(self, book: AddressBook, names: List[str], isdb: bool, e: Entry, fields) -> AddrSet:
        if isdb:
            sig = tuple((f, _vals(e, f)) for f in fields)
            return AddrSet(dyn=(Dyn("isdb:" + repr(sig), "isdb"),))
        return book.resolve_many(names)

    def policies(self) -> List[Policy]:
        return [self.build(e, i) for i, e in enumerate(self.vd.table("firewall policy"))]


# --------------------------------------------------------------------------- #
# coverage


def _addr_cover(E: AddrSet, En: bool, L: AddrSet, Ln: bool, full: IntervalSet) -> Tuple[str, List[Dyn]]:
    """Does the address set matched by E (with negate) contain L's?"""
    e_universe = (not En) and E.ip == full
    if L.dyn:
        if not Ln:
            if e_universe and not any(d.kind in ("vip", "isdb") for d in L.dyn):
                return YES, []
            if not En and set(L.dyn) <= set(E.dyn) and L.ip.issubset(E.ip):
                return YES, []  # same dynamic objects on both sides
            return UNKNOWN, list(L.dyn)
        # L = U \ (static u dyn)  is a subset of U \ static
        bound = full.difference(L.ip)
        r, d = _addr_cover(E, En, AddrSet(bound), False, full)
        if r == YES:
            return YES, []
        return UNKNOWN, list(L.dyn)
    A_L = full.difference(L.ip) if Ln else L.ip
    if A_L.is_empty():
        return YES, []
    if not En:
        if A_L.issubset(E.ip):
            return YES, []
        if E.dyn:
            return UNKNOWN, list(E.dyn)
        return NO, []
    # E negated: matches U \ (E.ip u E.dyn)
    if A_L.overlaps(E.ip):
        return NO, []
    if E.dyn:
        return UNKNOWN, list(E.dyn)
    return YES, []


def _svc_cover(E: SvcSet, En: bool, L: SvcSet, Ln: bool) -> Tuple[str, List[Dyn]]:
    if Ln:
        if not En and E.all:
            return YES, []
        if En and Ln and E.protos == L.protos and E.dyn == L.dyn and E.all == L.all:
            return YES, []
        return UNKNOWN if (L.dyn or E.dyn) else NO, list(L.dyn) + list(E.dyn)
    if L.dyn:
        if not En and E.all and not any(d.kind in ("isdb", "proxy", "service-address") for d in L.dyn):
            return YES, []
        if not En and set(L.dyn) <= set(E.dyn) and svc_static_covers(E, L):
            return YES, []
        return UNKNOWN, list(L.dyn)
    if not En:
        if svc_static_covers(E, L):
            return YES, []
        if E.dyn:
            return UNKNOWN, list(E.dyn)
        return NO, []
    if svc_static_intersects(E, L):
        return NO, []
    if E.dyn:
        return UNKNOWN, list(E.dyn)
    return YES, []


def _intf_cover(E: Tuple[bool, FrozenSet[str]], L: Tuple[bool, FrozenSet[str]]) -> str:
    if E[0]:
        return YES
    if L[0]:
        return NO
    if not L[1]:
        return NO
    return YES if L[1] <= E[1] else NO


def _user_cover(ctx: PolicyContext, E: Policy, L: Policy) -> Tuple[str, List[Dyn]]:
    e_any = not (E.users or E.groups or E.fsso)
    if e_any:
        return YES, []
    l_any = not (L.users or L.groups or L.fsso)
    if l_any:
        return NO, []
    unknown = False
    for u in L.users:
        if u in E.users:
            continue
        if any(u in ctx.users.local_groups.get(g, ()) for g in E.groups):
            continue
        if any(g in ctx.users.remote_groups for g in E.groups) or E.fsso:
            unknown = True
            continue
        return NO, []
    for g in L.groups:
        if g in E.groups:
            continue
        members = ctx.users.local_groups.get(g)
        if g not in ctx.users.remote_groups and members and all(m in E.users or any(m in ctx.users.local_groups.get(eg, ()) for eg in E.groups) for m in members):
            continue
        if E.fsso or any(x in ctx.users.remote_groups for x in E.groups) or g in ctx.users.remote_groups:
            unknown = True
            continue
        return NO, []
    for g in L.fsso:
        if g in E.fsso:
            continue
        unknown = True
    return (UNKNOWN, [Dyn("users/groups", "user")]) if unknown else (YES, [])


def covers(ctx: PolicyContext, E: Policy, L: Policy) -> Tuple[str, Dict[str, List[Dyn]]]:
    """Does earlier policy E match every packet that later policy L matches?

    Returns (YES|NO|UNKNOWN, {dimension: [dynamic objects]})."""
    unknown: Dict[str, List[Dyn]] = {}
    if _intf_cover(E.srcintf, L.srcintf) == NO:
        return NO, {}
    if _intf_cover(E.dstintf, L.dstintf) == NO:
        return NO, {}
    if not L.fam:
        return NO, {}
    for k, lf in L.fam.items():
        ef = E.fam.get(k)
        if ef is None:
            return NO, {}
        # fast pre-filter on bounds for the common non-negated static case
        if not ef.src_neg and not lf.src_neg and not ef.src.dyn and not lf.src.dyn:
            eb, lb = E.bounds[k][0], L.bounds[k][0]
            if lb and (not eb or lb[0] < eb[0] or lb[1] > eb[1]):
                return NO, {}
        if not ef.dst_neg and not lf.dst_neg and not ef.dst.dyn and not lf.dst.dyn:
            eb, lb = E.bounds[k][1], L.bounds[k][1]
            if lb and (not eb or lb[0] < eb[0] or lb[1] > eb[1]):
                return NO, {}
        r, d = _addr_cover(ef.src, ef.src_neg, lf.src, lf.src_neg, lf.full)
        if r == NO:
            return NO, {}
        if r == UNKNOWN:
            unknown.setdefault("src", []).extend(d)
        r, d = _addr_cover(ef.dst, ef.dst_neg, lf.dst, lf.dst_neg, lf.full)
        if r == NO:
            return NO, {}
        if r == UNKNOWN:
            unknown.setdefault("dst", []).extend(d)
    r, d = _svc_cover(E.svc, E.svc_neg, L.svc, L.svc_neg)
    if r == NO:
        return NO, {}
    if r == UNKNOWN:
        unknown["service"] = d
    if E.schedule != "always" and E.schedule != L.schedule:
        if L.schedule == "always":
            return NO, {}
        unknown["schedule"] = [Dyn(E.schedule, "schedule")]
    r, d = _user_cover(ctx, E, L)
    if r == NO:
        return NO, {}
    if r == UNKNOWN:
        unknown["users"] = d
    for f, v in E.restricting.items():
        if L.restricting.get(f) != v:
            unknown.setdefault("other", []).append(Dyn(f, "field"))
    return (UNKNOWN, unknown) if unknown else (YES, {})


def _addr_may_intersect(a: AddrSet, an: bool, b: AddrSet, bn: bool, full: IntervalSet) -> str:
    if a.dyn or b.dyn:
        if not an and not bn and a.ip.overlaps(b.ip):
            return YES
        return UNKNOWN
    A = full.difference(a.ip) if an else a.ip
    B = full.difference(b.ip) if bn else b.ip
    return YES if A.overlaps(B) else NO


def intersects(P: Policy, Q: Policy) -> str:
    """Can a packet match both policies? YES / NO / UNKNOWN."""
    for x, y in ((P.srcintf, Q.srcintf), (P.dstintf, Q.dstintf)):
        if not x[0] and not y[0] and not (x[1] & y[1]):
            return NO
    result = NO
    for k, pf in P.fam.items():
        qf = Q.fam.get(k)
        if qf is None:
            continue
        rs = _addr_may_intersect(pf.src, pf.src_neg, qf.src, qf.src_neg, pf.full)
        rd = _addr_may_intersect(pf.dst, pf.dst_neg, qf.dst, qf.dst_neg, pf.full)
        if NO in (rs, rd):
            continue
        if rs == YES and rd == YES:
            result = YES
            break
        result = UNKNOWN
    if result == NO:
        return NO
    if P.svc.dyn or Q.svc.dyn or P.svc_neg or Q.svc_neg:
        return UNKNOWN
    if not svc_static_intersects(P.svc, Q.svc):
        return NO
    if P.schedule != Q.schedule and "always" not in (P.schedule, Q.schedule):
        return UNKNOWN
    if (P.users or P.groups) and (Q.users or Q.groups):
        if not ((P.users & Q.users) or (P.groups & Q.groups)):
            return UNKNOWN
    return result


def broadness(p: Policy) -> List[str]:
    """Return which parts of an accept policy are 'any'."""
    out = []
    v4 = p.fam.get("v4")
    v6 = p.fam.get("v6")
    if (v4 and not v4.src_neg and v4.src.ip == V4_ALL) or (v6 and not v6.src_neg and v6.src.ip == V6_ALL):
        out.append("src")
    if (v4 and not v4.dst_neg and v4.dst.ip == V4_ALL) or (v6 and not v6.dst_neg and v6.dst.ip == V6_ALL):
        out.append("dst")
    if p.svc.all and not p.svc_neg:
        out.append("service")
    return out


def is_broad_accept(p: Policy) -> Optional[List[str]]:
    if p.action != "accept" or not p.status:
        return None
    b = broadness(p)
    if ("src" in b and "dst" in b) or ("service" in b and ("src" in b or "dst" in b)):
        return b
    return None
