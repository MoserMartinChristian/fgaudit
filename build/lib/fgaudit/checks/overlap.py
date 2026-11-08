"""Check 3: overlapping IP ranges between interfaces (incl. secondary IPs),
VIPs, IP pools, DHCP ranges and IPsec phase 2 selectors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from ..findings import Finding, Obj
from ..model import FortiConfig
from ..netsets import IntervalSet, fmt_set, v4_int, v4_subnet, v6_prefix
from ..objects import AddressBook, parse_portrange


@dataclass
class Item:
    kind: str  # interface, interface6, dhcp, ippool, vip-ext, vip-mapped, p2-local, p2-remote
    name: str  # display name, e.g. "port1" or "port1 (secondary 2)"
    vdom: str
    ip: IntervalSet
    v6: bool = False
    owner: str = ""  # interface name / phase1 name / extintf
    host32: bool = False  # /32 on tunnel or loopback interface
    vrf: str = "0"
    extra: Optional[dict] = None


def _rng(a: str, b: str) -> Optional[IntervalSet]:
    lo, hi = v4_int(a), v4_int(b)
    if lo is None or hi is None or lo > hi:
        return None
    return IntervalSet.single(lo, hi)


def _ip_or_range(tok: str) -> Optional[IntervalSet]:
    if "-" in tok:
        a, _, b = tok.partition("-")
        return _rng(a.strip(), b.strip())
    v = v4_int(tok)
    return IntervalSet.single(v, v) if v is not None else None


def collect(fc: FortiConfig, vdoms: List[str]) -> List[Item]:
    items: List[Item] = []
    for e in fc.interfaces():
        vd = fc.interface_vdom(e)
        if vd not in vdoms:
            continue
        itype = e.get("type", "physical")
        tunnel_like = itype in ("tunnel", "loopback") or bool(e.get("remote-ip"))
        sub = v4_subnet(e.get_list("ip"))
        if sub and not (sub[0] == 0 and sub[2] == 0):
            items.append(Item("interface", e.key, vd, IntervalSet.single(sub[0], sub[1]), owner=e.key,
                              host32=tunnel_like and sub[2] == 32, vrf=e.get("vrf", "0") or "0"))
        sec = e.child("secondaryip")
        if sec is not None and e.get("secondary-IP", "disable") == "enable":
            for s in sec:
                ss = v4_subnet(s.get_list("ip"))
                if ss and ss[2] > 0:
                    items.append(Item("interface", f"{e.key} (secondary {s.key})", vd,
                                      IntervalSet.single(ss[0], ss[1]), owner=e.key, vrf=e.get("vrf", "0") or "0"))
        v6 = e.child("ipv6")
        if v6 is not None:
            p = v6_prefix(v6.get("ip6-address", "::/0") or "::/0")
            if p and p[2] > 0:
                items.append(Item("interface", e.key, vd, IntervalSet.single(p[0], p[1]), v6=True, owner=e.key,
                                  host32=tunnel_like and p[2] == 128))
    for vname in vdoms:
        vd = fc.vdoms[vname]
        for d in vd.table("system dhcp server"):
            iface = d.get("interface", "") or ""
            rngs = d.child("ip-range")
            total = IntervalSet()
            if rngs is not None:
                for r in rngs:
                    s = _rng(r.get("start-ip", "0.0.0.0") or "", r.get("end-ip", "0.0.0.0") or "")
                    if s and s.bounds() != (0, 0):
                        total = total.union(s)
            exr = d.child("exclude-range")
            if exr is not None:
                for r in exr:
                    s = _rng(r.get("start-ip", "0.0.0.0") or "", r.get("end-ip", "0.0.0.0") or "")
                    if s:
                        total = total.difference(s)
            if total:
                items.append(Item("dhcp", f"{d.key} ({iface})", vname, total, owner=iface))
        for p in vd.table("firewall ippool"):
            s = _rng(p.get("startip", "0.0.0.0") or "", p.get("endip", "0.0.0.0") or "")
            if s and s.bounds() != (0, 0):
                items.append(Item("ippool", p.key, vname, s))
        for v in vd.table("firewall vip"):
            vtype = v.get("type", "static-nat")
            if vtype not in ("static-nat", "server-load-balance"):
                continue
            ext = _ip_or_range(v.get("extip", "") or "")
            pf = v.get("portforward", "disable") == "enable"
            proto = v.get("protocol", "tcp") or "tcp"
            ports = None
            if pf:
                pr = parse_portrange(v.get("extport", "0") or "0")
                ports = (pr[0], pr[1]) if pr else (0, 65535)
            extra = {"portforward": pf, "protocol": proto, "ports": ports, "extintf": v.get("extintf", "any") or "any"}
            if ext and ext.bounds() != (0, 0):
                items.append(Item("vip-ext", v.key, vname, ext, owner=extra["extintf"], extra=extra))
            mapped = IntervalSet()
            for tok in v.get_list("mappedip"):
                m = _ip_or_range(tok)
                if m:
                    mapped = mapped.union(m)
            if mapped:
                items.append(Item("vip-mapped", v.key, vname, mapped))
        a4 = AddressBook(vd)
        for p2 in vd.table("vpn ipsec phase2-interface"):
            p1 = p2.get("phase1name", "") or ""
            for side, kind in (("src", "p2-local"), ("dst", "p2-remote")):
                sel = _selector(p2, side, a4)
                if sel is None:
                    continue
                items.append(Item(kind, p2.key, vname, sel, owner=p1))
    return items


def _selector(p2, side: str, a4: AddressBook) -> Optional[IntervalSet]:
    t = p2.get(f"{side}-addr-type", "subnet") or "subnet"
    if t == "subnet":
        s = v4_subnet(p2.get_list(f"{side}-subnet") or ["0.0.0.0", "0.0.0.0"])
        if not s or s[2] == 0:
            return None  # 0.0.0.0/0 selectors are normal for route-based VPNs
        return IntervalSet.single(s[0], s[1])
    if t == "range":
        r = _rng(p2.get(f"{side}-start-ip", "0.0.0.0") or "", p2.get(f"{side}-end-ip", "0.0.0.0") or "")
        if r is None or r.bounds() == (0, 0):
            return None
        return r
    if t == "ip":
        v = v4_int(p2.get(f"{side}-start-ip", "0.0.0.0") or "")
        if not v:
            return None
        return IntervalSet.single(v, v)
    if t == "name":
        res = a4.resolve(p2.get(f"{side}-name", "") or "")
        if res.dyn or not res.ip or res.ip.is_full(0, (1 << 32) - 1):
            return None
        return res.ip
    return None  # IPv6 selector types are not compared


def _f(code: str, sev: str, a: Item, b: Item, ov: IntervalSet, **extra) -> Finding:
    v6 = a.v6
    params = {
        "a_kind": a.kind, "a_name": a.name, "a_vdom": a.vdom, "a_range": fmt_set(a.ip, v6),
        "b_kind": b.kind, "b_name": b.name, "b_vdom": b.vdom, "b_range": fmt_set(b.ip, v6),
        "overlap": fmt_set(ov, v6),
    }
    params.update(extra)
    return Finding(
        check="overlap", code=code, severity=sev, vdom=a.vdom,
        objects=[Obj(_otype(a.kind), a.name, a.vdom), Obj(_otype(b.kind), b.name, b.vdom)],
        params=params,
    )


def _otype(kind: str) -> str:
    return {"vip-ext": "vip", "vip-mapped": "vip", "p2-local": "phase2", "p2-remote": "phase2"}.get(kind, kind)


def run(fc: FortiConfig, vdoms: List[str]) -> List[Finding]:
    items = collect(fc, vdoms)
    allow_overlap = {
        v: fc.vdoms[v].table("system settings").get("allow-subnet-overlap", "disable") == "enable" for v in vdoms
    }
    out: List[Finding] = []
    ifs = [i for i in items if i.kind == "interface"]
    seen = set()
    # interface vs interface
    for i, a in enumerate(ifs):
        for b in ifs[i + 1:]:
            if a.v6 != b.v6 or a.owner == b.owner and a.vdom == b.vdom and a.name == b.name:
                continue
            if a.host32 or b.host32:
                continue
            ov = a.ip.intersection(b.ip)
            if not ov:
                continue
            key = (a.name, a.vdom, b.name, b.vdom)
            if key in seen:
                continue
            seen.add(key)
            if a.vdom != b.vdom:
                out.append(_f("overlap.interface-vdom", "info", a, b, ov))
            elif a.vrf != b.vrf:
                out.append(_f("overlap.interface-vrf", "info", a, b, ov, a_vrf=a.vrf, b_vrf=b.vrf))
            elif a.owner == b.owner:
                out.append(_f("overlap.interface-self", "medium", a, b, ov))
            else:
                out.append(_f("overlap.interface", "high", a, b, ov, allow_subnet_overlap=allow_overlap.get(a.vdom, False)))
    same = lambda a, b: a.vdom == b.vdom and not a.v6 and not b.v6  # noqa: E731
    dhcp = [i for i in items if i.kind == "dhcp"]
    pools = [i for i in items if i.kind == "ippool"]
    vext = [i for i in items if i.kind == "vip-ext"]
    vmap = [i for i in items if i.kind == "vip-mapped"]
    remote = [i for i in items if i.kind == "p2-remote"]
    local = [i for i in items if i.kind == "p2-local"]
    # DHCP
    for d in dhcp:
        own = [i for i in ifs if i.owner == d.owner and i.vdom == d.vdom and not i.v6]
        if own:
            covered = IntervalSet()
            for o in own:
                covered = covered.union(o.ip)
            outside = d.ip.difference(covered)
            if outside:
                out.append(_f("overlap.dhcp-outside", "medium", d, own[0], outside))
        d_vrf = own[0].vrf if own else "0"
        for i in ifs:
            if same(d, i) and i.owner != d.owner and not i.host32 and i.vrf == d_vrf:
                ov = d.ip.intersection(i.ip)
                if ov:
                    out.append(_f("overlap.dhcp-interface", "high", d, i, ov))
    for i, a in enumerate(dhcp):
        for b in dhcp[i + 1:]:
            if same(a, b):
                ov = a.ip.intersection(b.ip)
                if ov:
                    out.append(_f("overlap.dhcp-dhcp", "high", a, b, ov))
    for d in dhcp:
        for v in vmap:
            if same(d, v):
                ov = d.ip.intersection(v.ip)
                if ov:
                    out.append(_f("overlap.dhcp-vip", "medium", d, v, ov))
        for p in pools:
            if same(d, p):
                ov = d.ip.intersection(p.ip)
                if ov:
                    out.append(_f("overlap.dhcp-ippool", "medium", d, p, ov))
    # IP pools
    for i, a in enumerate(pools):
        for b in pools[i + 1:]:
            if same(a, b):
                ov = a.ip.intersection(b.ip)
                if ov:
                    out.append(_f("overlap.ippool", "medium", a, b, ov))
    # VIP external addresses
    for i, a in enumerate(vext):
        for b in vext[i + 1:]:
            if not same(a, b):
                continue
            ea, eb = a.extra or {}, b.extra or {}
            if ea.get("extintf") != eb.get("extintf") and "any" not in (ea.get("extintf"), eb.get("extintf")):
                continue
            ov = a.ip.intersection(b.ip)
            if not ov:
                continue
            if ea.get("portforward") and eb.get("portforward"):
                if ea.get("protocol") != eb.get("protocol"):
                    continue
                pa, pb = ea.get("ports"), eb.get("ports")
                if pa and pb and (pa[1] < pb[0] or pb[1] < pa[0]):
                    continue
            out.append(_f("overlap.vip", "medium", a, b, ov))
    # IPsec phase 2
    for r in remote:
        for i in ifs:
            if not same(r, i) or i.host32:
                continue
            ov = r.ip.intersection(i.ip)
            if not ov:
                continue
            if i.ip.issubset(r.ip) and i.ip != r.ip:
                continue  # remote selector is a supernet (summary route) - normal
            out.append(_f("overlap.p2-local-net", "high", r, i, ov))
        for l in local:
            if l.vdom == r.vdom and l.name == r.name:
                ov = r.ip.intersection(l.ip)
                if ov and not (l.ip.issubset(r.ip) and l.ip != r.ip):
                    out.append(_f("overlap.p2-self", "high", l, r, ov))
    for i, a in enumerate(remote):
        for b in remote[i + 1:]:
            if not same(a, b) or a.owner == b.owner:
                continue
            ov = a.ip.intersection(b.ip)
            if ov and not a.ip.issubset(b.ip) and not b.ip.issubset(a.ip):
                out.append(_f("overlap.p2-p2", "low", a, b, ov))
    for n, f in enumerate(out):
        f.order = n
    return out
