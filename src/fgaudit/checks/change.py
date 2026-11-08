"""Check 2: semantic comparison of two configuration backups with a risk
rating for every change."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..findings import Finding, Obj
from ..model import FortiConfig, Vdom
from ..netsets import v4_subnet
from ..parser import Config, Entry, is_secret_field
from .policies import NO, UNKNOWN, PolicyContext, intersects, is_broad_accept

IGNORED_FIELDS = {"uuid", "uuid-idx", "dirty", "policyid-uuid"}
# Tables in which the order of entries changes behaviour.
ORDERED_TABLES = {
    "firewall policy", "firewall local-in-policy", "firewall central-snat-map", "firewall shaping-policy",
    "firewall proxy-policy", "firewall multicast-policy", "firewall policy6", "firewall security-policy",
    "router policy", "router policy6", "firewall local-in-policy6", "firewall DoS-policy", "firewall DoS-policy6",
    "firewall interface-policy", "firewall acl", "firewall acl6", "firewall sniffer",
}
NESTED_ORDERED = {"service", "rules"}  # e.g. "system sdwan" > "service"

MGMT_PROTOS = {"https", "ssh", "http", "fgfm"}
INSECURE_PROTOS = {"http", "telnet"}
LOCKOUT_GLOBAL = {"admin-sport", "admin-port", "admin-ssh-port", "admin-https-redirect", "admin-telnet-port", "admin-server-cert", "admin-https-ssl-versions", "admin-lockout-threshold", "admin-restrict-local"}
HA_RISKY = {"mode", "group-id", "group-name", "hbdev", "priority", "override", "monitor", "session-pickup", "ha-mgmt-status"}


@dataclass
class FieldChange:
    field: str
    old: Optional[List[str]]
    new: Optional[List[str]]
    secret: bool = False


@dataclass
class ObjChange:
    scope: str  # vdom name or "global"
    path: str  # e.g. "firewall policy" or "system sdwan > members"
    key: Optional[str]  # edit key, None for singleton settings
    kind: str  # added | removed | modified
    fields: List[FieldChange] = field(default_factory=list)
    old: Optional[Entry] = None
    new: Optional[Entry] = None


def _norm(vals: Optional[List[str]]) -> Optional[Tuple[str, ...]]:
    return None if vals is None else tuple(vals)


def _settings_diff(a: Dict[str, List[str]], b: Dict[str, List[str]]) -> List[FieldChange]:
    out = []
    for k in sorted(set(a) | set(b)):
        if k in IGNORED_FIELDS:
            continue
        va, vb = a.get(k), b.get(k)
        secret = is_secret_field(k) or any(v.startswith("ENC ") for v in (va or []) + (vb or []))
        if va is None or vb is None:
            if _norm(va) != _norm(vb):
                out.append(FieldChange(k, va, vb, secret))
            continue
        if secret:
            if va != vb:
                out.append(FieldChange(k, va, vb, True))
            continue
        # order of list values matters for few fields; FortiOS stores member
        # lists in a canonical order, so compare as sets for multi-values
        if len(va) > 1 or len(vb) > 1:
            if sorted(va) != sorted(vb):
                out.append(FieldChange(k, va, vb))
        elif va != vb:
            out.append(FieldChange(k, va, vb))
    return out


def _entry_changed(a: Entry, b: Entry) -> bool:
    if _settings_diff(a.settings, b.settings):
        return True
    for p in set(a.children) | set(b.children):
        ca, cb = a.children.get(p), b.children.get(p)
        if ca is None or cb is None:
            if (ca is not None and (ca.entries or ca.settings)) or (cb is not None and (cb.entries or cb.settings)):
                return True
            continue
        if _config_changed(ca, cb):
            return True
    return False


def _config_changed(a: Config, b: Config) -> bool:
    if _settings_diff(a.settings, b.settings):
        return True
    if set(a.entries) != set(b.entries):
        return True
    for k in a.entries:
        if _entry_changed(a.entries[k], b.entries[k]):
            return True
    return False


def diff_tree(scope: str, a: Config, b: Config, prefix: str = "") -> List[ObjChange]:
    out: List[ObjChange] = []
    for path in list(a.children) + [p for p in b.children if p not in a.children]:
        full = f"{prefix} > {path}" if prefix else path
        ca, cb = a.children.get(path), b.children.get(path)
        if ca is None:
            ca = Config(path=path)
        if cb is None:
            cb = Config(path=path)
        fch = _settings_diff(ca.settings, cb.settings)
        if fch:
            out.append(ObjChange(scope, full, None, "modified", fch))
        for k in list(ca.entries) + [k for k in cb.entries if k not in ca.entries]:
            ea, eb = ca.entries.get(k), cb.entries.get(k)
            if ea is None:
                out.append(ObjChange(scope, full, k, "added", _settings_diff({}, eb.settings), None, eb))
                continue
            if eb is None:
                out.append(ObjChange(scope, full, k, "removed", [], ea, None))
                continue
            fch = _settings_diff(ea.settings, eb.settings)
            sub: List[ObjChange] = []
            for cp in set(ea.children) | set(eb.children):
                sub.extend(diff_tree(scope, _wrap(ea.children.get(cp), cp), _wrap(eb.children.get(cp), cp), f"{full} [{k}]"))
            if fch:
                out.append(ObjChange(scope, full, k, "modified", fch, ea, eb))
            out.extend(sub)
        if ca.children or cb.children:
            out.extend(diff_tree(scope, _strip(ca), _strip(cb), full))
    return out


def _wrap(c: Optional[Config], path: str) -> Config:
    w = Config(path="")
    if c is not None:
        w.children[path] = c
    return w


def _strip(c: Config) -> Config:
    w = Config(path="")
    w.children = c.children
    return w


def _lis_keep(seq: List[int]) -> Set[int]:
    """Indices (into seq) of a longest increasing subsequence."""
    import bisect

    tails: List[int] = []
    tails_idx: List[int] = []
    prev = [-1] * len(seq)
    for i, v in enumerate(seq):
        j = bisect.bisect_left(tails, v)
        if j == len(tails):
            tails.append(v)
            tails_idx.append(i)
        else:
            tails[j] = v
            tails_idx[j] = i
        prev[i] = tails_idx[j - 1] if j > 0 else -1
    keep = set()
    k = tails_idx[-1] if tails_idx else -1
    while k >= 0:
        keep.add(k)
        k = prev[k]
    return keep


# --------------------------------------------------------------------------- #


class ChangeAnalyzer:
    def __init__(self, old: FortiConfig, new: FortiConfig, vdoms: List[str]):
        self.old, self.new = old, new
        self.vdoms = vdoms
        self.findings: List[Finding] = []
        self.stats = {"changes": 0, "ignored_uuid": 0, "not_comparable": 0}
        self._ctx: Dict[Tuple[str, str], PolicyContext] = {}

    def ctx(self, which: str, vdom: str) -> Optional[PolicyContext]:
        fc = self.old if which == "old" else self.new
        if vdom not in fc.vdoms:
            return None
        k = (which, vdom)
        if k not in self._ctx:
            self._ctx[k] = PolicyContext(fc, fc.vdoms[vdom])
        return self._ctx[k]

    def add(self, code: str, sev: str, scope: str, objs: List[Obj], order: int = 0, **params) -> None:
        self.findings.append(Finding("change", code, sev, scope if scope != "global" else None, objs, params, order))

    def run(self) -> List[Finding]:
        changes: List[ObjChange] = []
        if self.old.vdom_mode or self.new.vdom_mode:
            changes.extend(diff_tree("global", self.old.global_root, self.new.global_root))
        all_vd = [v for v in dict.fromkeys(list(self.old.vdoms) + list(self.new.vdoms)) if v in self.vdoms]
        for v in all_vd:
            a, b = self.old.vdoms.get(v), self.new.vdoms.get(v)
            if a is None or b is None:
                self.add("change.vdom-added" if a is None else "change.vdom-removed", "high", v, [Obj("vdom", v, v)], vdom=v)
                continue
            ra, rb = a.root, b.root
            if not (self.old.vdom_mode or self.new.vdom_mode):
                pass
            changes.extend(diff_tree(v, ra, rb))
        self._count_uuid_noise()
        self.stats["changes"] = len(changes)
        for i, ch in enumerate(changes):
            self.classify(ch, i)
        for v in all_vd:
            if v in self.old.vdoms and v in self.new.vdoms:
                self.order_changes(v)
        return self.findings

    def _count_uuid_noise(self) -> None:
        n = 0
        for v in self.old.vdoms:
            if v not in self.new.vdoms:
                continue
            ta = self.old.vdoms[v].table("firewall policy")
            tb = self.new.vdoms[v].table("firewall policy")
            for k, e in ta.entries.items():
                f = tb.entries.get(k)
                if f is not None and e.get("uuid") != f.get("uuid"):
                    n += 1
        self.stats["ignored_uuid"] = n

    # ------------------------------------------------------------------ #
    def classify(self, ch: ObjChange, order: int) -> None:
        path = ch.path
        base = path.split(" > ")[0].split(" [")[0]
        scope = ch.scope
        name = ch.key or base
        obj = Obj(_otype(base), name, None if scope == "global" else scope)
        secret_fields = [f for f in ch.fields if f.secret]
        plain = [f for f in ch.fields if not f.secret]
        if secret_fields and ch.kind == "modified":
            changed = [f for f in secret_fields if f.old is not None and f.new is not None]
            if changed:
                self.stats["not_comparable"] += len(changed)
                self.add("change.secret-not-comparable", "info", scope, [obj], order,
                         path=path, key=ch.key, fields=[f.field for f in changed])
            added_removed = [f for f in secret_fields if f.old is None or f.new is None]
            plain = plain + added_removed
            if not plain:
                return
        fnames = [f.field for f in plain]
        summary = _field_summary(plain)
        common = dict(path=path, key=ch.key, kind=ch.kind, fields=fnames, changes=summary)

        # ---- firewall policy -------------------------------------------
        if base == "firewall policy" and path == "firewall policy":
            self._policy_change(ch, obj, order, common)
            return
        # ---- lockout risks --------------------------------------------
        if base == "system interface" and path == "system interface":
            self._interface_change(ch, obj, order, common)
            return
        if path.startswith("system interface"):
            self.add("change.interface", "medium", scope, [obj], order, **common)
            return
        if base == "system global":
            risky = [f for f in fnames if f in LOCKOUT_GLOBAL]
            if risky:
                self.add("change.lockout-admin-port", "high", scope, [obj], order, **common, risky=risky)
            else:
                self.add("change.global", "low", scope, [obj], order, **common)
            return
        if base == "system admin":
            th = [f for f in fnames if "trusthost" in f]
            if th or ch.kind in ("added", "removed"):
                self.add("change.lockout-admin", "high" if th or ch.kind == "removed" else "medium", scope, [obj], order, **common, trusthost=bool(th))
            else:
                self.add("change.admin", "medium", scope, [obj], order, **common)
            return
        if base in ("firewall local-in-policy", "firewall local-in-policy6"):
            self.add("change.lockout-local-in", "high", scope, [obj], order, **common)
            return
        if base in ("router static", "router static6"):
            default = _is_default_route(ch.old) or _is_default_route(ch.new)
            if default:
                self.add("change.default-route", "high", scope, [obj], order, **common)
            else:
                self.add("change.routing", "medium", scope, [obj], order, **common)
            return
        if base.startswith("router "):
            self.add("change.routing", "medium", scope, [obj], order, **common)
            return
        if base == "system sdwan" or base == "system virtual-wan-link":
            self.add("change.sdwan", "medium", scope, [obj], order, **common)
            return
        if base == "system ha":
            risky = [f for f in fnames if f in HA_RISKY]
            self.add("change.ha", "high" if risky else "medium", scope, [obj], order, **common, risky=risky)
            return
        if base.startswith("vpn ipsec") or base.startswith("vpn ssl") or base.startswith("vpn "):
            self.add("change.vpn", "high" if ch.kind == "removed" else "medium", scope, [obj], order, **common)
            return
        if base in ("firewall vip", "firewall vip6", "firewall vipgrp", "firewall ippool", "firewall ippool6", "firewall central-snat-map"):
            self.add("change.nat", "medium", scope, [obj], order, **common, impact=self._impact(scope, base, ch.key))
            return
        if base in ("firewall address", "firewall address6", "firewall addrgrp", "firewall addrgrp6",
                    "firewall service custom", "firewall service group", "firewall schedule recurring",
                    "firewall schedule onetime", "firewall schedule group", "system zone", "user group", "user local"):
            impact = self._impact(scope, base, ch.key)
            if ch.kind == "added" and not impact:
                self.add("change.object-added", "info", scope, [obj], order, **common)
                return
            sev = "medium" if impact else "low"
            self.add("change.object", sev, scope, [obj], order, **common, impact=impact)
            return
        if base.startswith("log ") or base == "system syslogd" or base.startswith("log"):
            self.add("change.logging", "medium", scope, [obj], order, **common)
            return
        if base in ORDERED_TABLES:
            self.add("change.policy-other", "medium", scope, [obj], order, **common)
            return
        self.add("change.other", "low", scope, [obj], order, **common)

    def _impact(self, scope: str, base: str, key: Optional[str]) -> List[Dict[str, str]]:
        """Policies that reference the object directly or via groups."""
        if key is None or scope == "global":
            return []
        out: List[Dict[str, str]] = []
        for which in ("new", "old"):
            fc = self.new if which == "new" else self.old
            vd = fc.vdoms.get(scope)
            if vd is None:
                continue
            names = _referencing_groups(vd, key)
            for p in vd.table("firewall policy"):
                vals = set()
                for f in ("srcaddr", "dstaddr", "srcaddr6", "dstaddr6", "service", "schedule", "srcintf", "dstintf", "groups", "users", "poolname", "poolname6"):
                    vals.update(p.get_list(f))
                if vals & names:
                    d = {"id": p.key, "name": p.get("name", "") or ""}
                    if d not in out:
                        out.append(d)
            if out:
                break
        return out

    def _interface_change(self, ch: ObjChange, obj: Obj, order: int, common: dict) -> None:
        scope = ch.scope
        if ch.kind == "removed":
            self.add("change.interface-removed", "high", scope, [obj], order, **common)
            return
        if ch.kind == "added":
            self.add("change.interface-added", "low", scope, [obj], order, **common)
            return
        for f in ch.fields:
            if f.field == "allowaccess":
                old = set(f.old or [])
                new = set(f.new or [])
                removed = sorted((old - new) & MGMT_PROTOS)
                added = sorted((new - old) & INSECURE_PROTOS)
                if removed:
                    self.add("change.lockout-allowaccess", "high", scope, [obj], order, **common, removed=removed)
                elif added:
                    self.add("change.insecure-allowaccess", "medium", scope, [obj], order, **common, added=added)
                else:
                    self.add("change.interface", "low", scope, [obj], order, **common)
                return
        names = [f.field for f in ch.fields]
        if "ip" in names or "vdom" in names:
            self.add("change.lockout-interface-ip", "high", scope, [obj], order, **common)
        elif "status" in names:
            self.add("change.interface-status", "high", scope, [obj], order, **common)
        elif "role" in names or "type" in names or "mode" in names:
            self.add("change.interface", "medium", scope, [obj], order, **common)
        else:
            self.add("change.interface", "low", scope, [obj], order, **common)

    def _policy_change(self, ch: ObjChange, obj: Obj, order: int, common: dict) -> None:
        scope = ch.scope
        obj.type = "policy"
        obj.id = ch.key
        ent = ch.new or ch.old
        pname = (ent.get("name", "") if ent else "") or ""
        obj.name = pname or (ch.key or "")
        common = dict(common, policy=ch.key, policy_name=pname)
        if ch.kind == "removed":
            self.add("change.policy-removed", "medium", scope, [obj], order, **common, action=ch.old.get("action", "deny") if ch.old else "")
            return
        ctx = self.ctx("new", scope)
        newp = ctx.build(ch.new, 0) if (ctx and ch.new is not None) else None
        broad = is_broad_accept(newp) if newp else None
        if ch.kind == "added":
            if broad:
                self.add("change.broad-accept", "high", scope, [obj], order, **common, broad=broad)
            elif newp and newp.action == "accept":
                self.add("change.policy-added", "medium", scope, [obj], order, **common, action="accept",
                         nolog=newp.logtraffic == "disable")
            else:
                self.add("change.policy-added", "low", scope, [obj], order, **common, action=newp.action if newp else "",
                         nolog=bool(newp and newp.logtraffic == "disable"))
            return
        octx = self.ctx("old", scope)
        oldp = octx.build(ch.old, 0) if (octx and ch.old is not None) else None
        fn = {f.field: f for f in ch.fields}
        if "action" in fn:
            to = (fn["action"].new or ["deny"])[0]
            sev = "high" if to == "accept" else "medium"
            self.add("change.policy-action", sev, scope, [obj], order, **common, to=to)
            return
        if broad and not (oldp and is_broad_accept(oldp)):
            self.add("change.broad-accept", "high", scope, [obj], order, **common, broad=broad)
            return
        if "status" in fn:
            to = (fn["status"].new or ["enable"])[0]
            self.add("change.policy-status", "medium", scope, [obj], order, **common, to=to)
            return
        if "logtraffic" in fn and (fn["logtraffic"].new or ["utm"])[0] == "disable":
            self.add("change.logging-disabled", "medium", scope, [obj], order, **common)
            return
        match_fields = {"srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr6", "dstaddr6", "service", "schedule", "users", "groups", "internet-service", "internet-service-name", "srcaddr-negate", "dstaddr-negate", "service-negate"}
        nat_fields = {"nat", "ippool", "poolname", "poolname6", "natip", "fixedport"}
        if set(fn) & match_fields:
            self.add("change.policy-match", "medium", scope, [obj], order, **common)
        elif set(fn) & nat_fields:
            self.add("change.nat", "medium", scope, [obj], order, **common, impact=[])
        elif set(fn) <= {"comments", "name", "global-label", "label"}:
            self.add("change.cosmetic", "info", scope, [obj], order, **common)
        else:
            self.add("change.policy-other", "low", scope, [obj], order, **common)

    def order_changes(self, vdom: str) -> None:
        ta = self.old.vdoms[vdom].table("firewall policy")
        tb = self.new.vdoms[vdom].table("firewall policy")
        old_ids = [k for k in ta.entries if k in tb.entries]
        new_ids = [k for k in tb.entries if k in ta.entries]
        if old_ids == new_ids:
            return
        pos_old = {k: i for i, k in enumerate(old_ids)}
        seq = [pos_old[k] for k in new_ids]
        keep = _lis_keep(seq)
        moved = [new_ids[i] for i in range(len(new_ids)) if i not in keep]
        ctx = self.ctx("new", vdom)
        pols = {e.key: ctx.build(e, i) for i, e in enumerate(tb)}
        pos_new = {k: i for i, k in enumerate(new_ids)}
        for m in moved:
            P = pols[m]
            conflicts, same, unknown = [], [], []
            for q in new_ids:
                if q == m:
                    continue
                flipped = (pos_old[m] < pos_old[q]) != (pos_new[m] < pos_new[q])
                if not flipped:
                    continue
                Q = pols[q]
                if not (P.status and Q.status):
                    continue
                r = intersects(P, Q)
                if r == NO:
                    continue
                ent = {"id": q, "name": Q.name, "before": pos_new[m] < pos_new[q]}
                if r == UNKNOWN:
                    unknown.append(ent)
                elif P.action != Q.action:
                    conflicts.append(ent)
                else:
                    same.append(ent)
            obj = Obj("policy", P.name or P.id, vdom, id=P.id)
            extra_objs = [Obj("policy", o["name"] or o["id"], vdom, id=o["id"]) for o in (conflicts or unknown or same)[:6]]
            base = dict(policy=P.id, policy_name=P.name, old_pos=pos_old[m] + 1, new_pos=pos_new[m] + 1)
            if conflicts:
                self.add("change.order-conflict", "high", vdom, [obj] + extra_objs, pos_new[m], **base, others=conflicts[:6], action=P.action)
            elif unknown:
                self.add("change.order-unknown", "medium", vdom, [obj] + extra_objs, pos_new[m], **base, others=unknown[:6])
            elif same:
                self.add("change.order-same", "low", vdom, [obj] + extra_objs, pos_new[m], **base, others=same[:6])
            else:
                self.add("change.order-none", "info", vdom, [obj], pos_new[m], **base)


def _referencing_groups(vd: Vdom, key: str) -> Set[str]:
    names = {key}
    changed = True
    tables = [vd.table(t) for t in ("firewall addrgrp", "firewall addrgrp6", "firewall service group", "firewall schedule group", "system zone", "user group", "firewall vipgrp")]
    while changed:
        changed = False
        for t in tables:
            for g in t:
                if g.key in names:
                    continue
                members = set(g.get_list("member")) | set(g.get_list("interface"))
                if members & names:
                    names.add(g.key)
                    changed = True
    return names


def _is_default_route(e: Optional[Entry]) -> bool:
    if e is None:
        return False
    if e.get("dstaddr") or e.get("internet-service") or e.get("internet-service-custom"):
        return False
    dst = e.get_list("dst")
    if not dst:
        return True  # default dst is 0.0.0.0 0.0.0.0
    if ":" in dst[0]:
        return dst[0] in ("::/0",)
    s = v4_subnet(dst)
    return bool(s and s[2] == 0)


def _otype(base: str) -> str:
    return {
        "firewall policy": "policy", "firewall address": "address", "firewall address6": "address",
        "firewall addrgrp": "addrgrp", "firewall addrgrp6": "addrgrp", "firewall service custom": "service",
        "firewall service group": "servicegrp", "system interface": "interface", "router static": "route",
        "firewall vip": "vip", "firewall ippool": "ippool", "system admin": "admin",
        "vpn ipsec phase1-interface": "phase1", "vpn ipsec phase2-interface": "phase2",
        "firewall local-in-policy": "local-in-policy", "system zone": "zone",
    }.get(base, "config")


def _field_summary(fields: List[FieldChange]) -> List[Dict[str, object]]:
    out = []
    for f in fields[:12]:
        if f.secret:
            out.append({"field": f.field, "old": None if f.old is None else "<secret>", "new": None if f.new is None else "<secret>"})
        else:
            out.append({"field": f.field, "old": None if f.old is None else " ".join(f.old)[:200],
                        "new": None if f.new is None else " ".join(f.new)[:200]})
    return out


def run(old: FortiConfig, new: FortiConfig, vdoms: List[str]) -> Tuple[List[Finding], dict]:
    a = ChangeAnalyzer(old, new, vdoms)
    f = a.run()
    return f, a.stats
