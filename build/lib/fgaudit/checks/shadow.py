"""Check 1: shadowed, redundant and duplicate firewall policies, plus
unreferenced objects."""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from ..findings import Finding, Obj
from ..model import FortiConfig, Vdom
from .policies import UNKNOWN, YES, Policy, PolicyContext, covers

# Factory-default object names that exist in every backup and are not
# reported as "unreferenced". Built from FortiOS factory configs; the list
# may be incomplete, which only means a few extra low-severity notes.
FACTORY_ADDRESSES = {
    "all", "none", "FIREWALL_AUTH_PORTAL_ADDRESS", "FABRIC_DEVICE", "SSLVPN_TUNNEL_ADDR1",
    "SSLVPN_TUNNEL_IPv6_ADDR1", "login.microsoftonline.com", "login.microsoft.com",
    "login.windows.net", "gmail.com", "wildcard.google.com", "wildcard.dropbox.com",
    "G Suite", "Microsoft Office 365", "EMS_ALL_UNKNOWN_CLIENTS", "EMS_ALL_UNMANAGEABLE_CLIENTS",
    "FCTEMS_ALL_FORTICLOUD_SERVERS", "FCTEMS_ALL_FORTICLOUD_SERVERS", "LOCAL_EMS_ALL_FORTICLOUD_SERVERS",
    "GoogleDNS", "Firebase", "ZTNA_ALL", "update.microsoft.com", "autoupdate.opera.com",
    "fortinet", "adobe", "Adobe Login", "android", "apple", "appstore", "auth.gfx.ms", "citrix",
    "dropbox.com", "eease", "firefox update server", "google-drive", "google-play", "google-play2",
    "google-play3", "microsoft", "skype", "swscan.apple.com", "verisign", "Windows update 2", "cdn-apple",
}
FACTORY_SERVICES = {
    "ALL", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "ALL_ICMP6", "GRE", "AH", "ESP", "AOL", "BGP", "DHCP",
    "DNS", "FINGER", "FTP", "FTP_GET", "FTP_PUT", "GOPHER", "H323", "HTTP", "HTTPS", "IKE", "IMAP",
    "IMAPS", "Internet-Locator-Service", "IRC", "L2TP", "LDAP", "NetMeeting", "NFS", "NNTP", "NTP",
    "OSPF", "PC-Anywhere", "PING", "TIMESTAMP", "INFO_REQUEST", "INFO_ADDRESS", "ONC-RPC", "DCE-RPC",
    "POP3", "POP3S", "PPTP", "QUAKE", "RAUDIO", "REXEC", "RIP", "RLOGIN", "RSH", "SCCP", "SIP",
    "SIP-MSNmessenger", "SAMBA", "SMTP", "SMTPS", "SNMP", "SSH", "SYSLOG", "TALK", "TELNET", "TFTP",
    "MGCP", "UUCP", "VDOLIVE", "WAIS", "WINFRAME", "X-WINDOWS", "PING6", "MS-SQL", "MYSQL", "RDP",
    "VNC", "DHCP6", "SQUID", "SOCKS", "WINS", "RADIUS", "RADIUS-OLD", "CVSPSERVER", "AFS3",
    "TRACEROUTE", "RTSP", "MMS", "KERBEROS", "LDAP_UDP", "SMB", "NONE", "webproxy", "Email Access",
    "Web Access", "File Access", "Network Services", "Windows AD", "Exchange Server", "DNS-over-HTTPS",
    "QUIC", "ICMP_ANY",
}
FACTORY_SCHEDULES = {"always", "none", "default-darrp-optimize"}


def _policy_obj(p: Policy, vdom: str) -> Obj:
    return Obj("policy", p.name or p.id, vdom, id=p.id)


def _profile_diff(a: Policy, b: Policy) -> Dict[str, List[str]]:
    keys = sorted(set(a.profiles) | set(b.profiles))
    out = {}
    for k in keys:
        va, vb = a.profiles.get(k, ()), b.profiles.get(k, ())
        if va != vb:
            out[k] = [" ".join(va) or "-", " ".join(vb) or "-"]
    return out


def _dyn_names(d) -> List[str]:
    out = []
    for x in d:
        n = "Internet Service" if x.kind == "isdb" else x.name
        if n not in out:
            out.append(n)
    return out


def check_vdom(fc: FortiConfig, vd: Vdom) -> List[Finding]:
    ctx = PolicyContext(fc, vd)
    pols = ctx.policies()
    findings: List[Finding] = []
    active = [p for p in pols if p.status]
    # index of earlier active policies by srcintf token for pre-filtering
    for li, L in enumerate(active):
        if not L.fam:
            continue
        uncertain: Optional[tuple] = None
        for E in active[:li]:
            r, unk = covers(ctx, E, L)
            if r == YES:
                f = _make_cover_finding(fc, vd, E, L)
                findings.append(f)
                uncertain = None
                break
            if r == UNKNOWN and uncertain is None:
                uncertain = (E, unk)
        if uncertain is not None:
            E, unk = uncertain
            dims = sorted(unk)
            objs = []
            for d in dims:
                objs.extend(_dyn_names(unk[d]))
            findings.append(
                Finding(
                    check="shadow",
                    code="shadow.uncertain",
                    severity="info",
                    vdom=vd.name,
                    objects=[_policy_obj(L, vd.name), _policy_obj(E, vd.name)],
                    params={
                        "later": L.id, "later_name": L.name, "earlier": E.id, "earlier_name": E.name,
                        "dims": dims, "dyn": objs[:8],
                    },
                    order=L.seq,
                )
            )
    findings.extend(_unreferenced(vd))
    return findings


def _make_cover_finding(fc: FortiConfig, vd: Vdom, E: Policy, L: Policy) -> Finding:
    order_note = None
    try:
        if int(E.id) > int(L.id):
            order_note = True
    except ValueError:
        pass
    prof = _profile_diff(E, L)
    params = {
        "later": L.id, "later_name": L.name, "later_action": L.action,
        "earlier": E.id, "earlier_name": E.name, "earlier_action": E.action,
        "later_pos": L.seq + 1, "earlier_pos": E.seq + 1,
        "id_order_differs": bool(order_note),
        "profiles": prof,
    }
    if E.action != L.action:
        code, sev = "shadow.conflict", "high"
    elif E.match_sig == L.match_sig:
        code, sev = "shadow.duplicate", "low"
    else:
        code, sev = "shadow.redundant", ("medium" if prof else "low")
    return Finding(
        check="shadow", code=code, severity=sev, vdom=vd.name,
        objects=[_policy_obj(L, vd.name), _policy_obj(E, vd.name)],
        params=params, order=L.seq,
    )


def _collect_tokens(node, skip_paths: Set[str], out: Set[str], path: str = "") -> None:
    for p, c in node.children.items():
        full = p
        if full in skip_paths:
            # still scan nested references (e.g. group members) but not keys
            for e in c.entries.values():
                for k, vals in e.settings.items():
                    if k in ("member", "exclude-member"):
                        out.update(vals)
                _collect_tokens(e, set(), out)
            continue
        for k, vals in c.settings.items():
            out.update(vals)
        for e in c.entries.values():
            for k, vals in e.settings.items():
                out.update(vals)
            _collect_tokens(e, set(), out)
        _collect_tokens(c, set(), out)


OBJECT_TABLES = {
    "firewall address": ("address", FACTORY_ADDRESSES),
    "firewall address6": ("address", FACTORY_ADDRESSES),
    "firewall addrgrp": ("addrgrp", FACTORY_ADDRESSES),
    "firewall addrgrp6": ("addrgrp", FACTORY_ADDRESSES),
    "firewall service custom": ("service", FACTORY_SERVICES),
    "firewall service group": ("servicegrp", FACTORY_SERVICES),
    "firewall schedule recurring": ("schedule", FACTORY_SCHEDULES),
    "firewall schedule onetime": ("schedule", FACTORY_SCHEDULES),
    "firewall schedule group": ("schedule", FACTORY_SCHEDULES),
}


def _unreferenced(vd: Vdom) -> List[Finding]:
    tokens: Set[str] = set()
    _collect_tokens(vd.root, set(OBJECT_TABLES), tokens)
    by_type: Dict[str, List[str]] = {}
    for path, (otype, factory) in OBJECT_TABLES.items():
        t = vd.root.children.get(path)
        if t is None:
            continue
        for e in t:
            if e.key in factory or e.key in tokens:
                continue
            if e.get("fabric-object") == "enable":
                continue  # may be used by other Security Fabric members
            by_type.setdefault(otype, []).append(e.key)
    out = []
    for i, (otype, names) in enumerate(sorted(by_type.items())):
        out.append(
            Finding(
                check="unused", code="unused.object", severity="low", vdom=vd.name,
                objects=[Obj(otype, n, vd.name) for n in names],
                params={"otype": otype, "names": names, "count": len(names)},
                order=100000 + i,
            )
        )
    return out


def run(fc: FortiConfig, vdoms: List[str]) -> List[Finding]:
    out: List[Finding] = []
    for name in vdoms:
        out.extend(check_vdom(fc, fc.vdoms[name]))
    return out
