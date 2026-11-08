"""Generator for synthetic, made-up FortiOS configurations and logs.

Used by ``fgaudit --demo`` and the test suite. Every scenario returns the
generated text together with the findings that *must* appear (ground truth).
All names, addresses and serial numbers are invented. IPv4 addresses come
from private ranges and the documentation ranges (RFC 5737), IPv6 from
2001:db8::/32 (RFC 3849).

Header build numbers are fictitious; only the version part follows the
FortiOS header format (#config-version=MODEL-X.Y.Z-FW-buildNNNN-YYMMDD).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple, Union

VERSIONS = {"7.4": "7.4.8", "7.6": "7.6.4", "8.0": "8.0.2"}

Val = Union[str, int, Sequence[Union[str, int]]]

KEYWORDS = {
    "enable", "disable", "accept", "deny", "ipsec", "all", "utm", "ipmask", "iprange", "fqdn", "geography",
    "static", "physical", "vlan", "tunnel", "loopback", "TCP/UDP/SCTP", "TCP/UDP/UDP-Lite/SCTP", "ICMP", "ICMP6", "IP",
    "overload", "one-to-one", "static-nat", "subnet", "range", "name", "ip", "ipprefix", "tcp", "udp", "default",
    "lan", "wan", "dmz", "undefined", "none", "on", "off", "multi-vdom", "no-vdom", "flow", "proxy", "a-p", "a-a", "standalone",
    "local", "server", "manual", "dynamic", "aggressive", "main", "custom", "aes256-sha256", "ike", "always",
    "ping", "https", "ssh", "http", "fgfm", "snmp", "telnet", "interface", "monday", "tuesday", "wednesday",
    "thursday", "friday", "saturday", "sunday", "ftm", "fabric", "policy-based", "profile-based", "ipv4", "ipv6",
}


def _fmt_val(v: Union[str, int]) -> str:
    s = str(v)
    if isinstance(v, int) or s in KEYWORDS:
        return s
    if _is_ipish(s):
        return s
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _is_ipish(s: str) -> bool:
    import re

    return bool(re.fullmatch(r"[0-9a-fA-F:./-]+", s)) and any(c in s for c in ".:") and not s.startswith("ENC")


@dataclass
class Node:
    """config / edit tree used for rendering."""

    settings: List[Tuple[str, Val]] = field(default_factory=list)
    children: List[Tuple[str, "Table"]] = field(default_factory=list)

    def set(self, k: str, v: Val) -> "Node":
        self.settings = [(a, b) for a, b in self.settings if a != k]
        self.settings.append((k, v))
        return self

    def unset(self, k: str) -> "Node":
        self.settings = [(a, b) for a, b in self.settings if a != k]
        return self

    def get(self, k: str) -> Optional[Val]:
        for a, b in self.settings:
            if a == k:
                return b
        return None

    def sub(self, path: str) -> "Table":
        for p, t in self.children:
            if p == path:
                return t
        t = Table()
        self.children.append((path, t))
        return t


@dataclass
class Table(Node):
    entries: List[Tuple[Union[str, int], Node]] = field(default_factory=list)

    def edit(self, key: Union[str, int]) -> Node:
        for k, n in self.entries:
            if k == key:
                return n
        n = Node()
        self.entries.append((key, n))
        return n

    def remove(self, key: Union[str, int]) -> None:
        self.entries = [(k, n) for k, n in self.entries if k != key]

    def move_before(self, key, before) -> None:
        item = next(x for x in self.entries if x[0] == key)
        self.entries.remove(item)
        idx = next(i for i, x in enumerate(self.entries) if x[0] == before)
        self.entries.insert(idx, item)

    def move_after(self, key, after) -> None:
        item = next(x for x in self.entries if x[0] == key)
        self.entries.remove(item)
        idx = next(i for i, x in enumerate(self.entries) if x[0] == after)
        self.entries.insert(idx + 1, item)


def _render_node(n: Node, ind: int, out: List[str]) -> None:
    pad = "    " * ind
    for k, v in n.settings:
        if isinstance(v, (list, tuple)):
            vals = " ".join(_fmt_val(x) for x in v)
        else:
            vals = _fmt_val(v)
        out.append(f"{pad}set {k} {vals}")
    for path, t in n.children:
        _render_table(path, t, ind, out)


def _render_table(path: str, t: Table, ind: int, out: List[str]) -> None:
    pad = "    " * ind
    out.append(f"{pad}config {path}")
    _render_node(t, ind + 1, out)
    for k, n in t.entries:
        out.append(f"{pad}    edit {_fmt_val(k) if not isinstance(k, int) else k}")
        _render_node(n, ind + 2, out)
        out.append(f"{pad}    next")
    out.append(f"{pad}end")


class FGConfig:
    def __init__(self, version: str = "7.4", vdoms: Optional[List[str]] = None, model: str = "FGVM64", build: int = 4242):
        self.version = version
        self.full_version = VERSIONS.get(version, version)
        self.vdoms = vdoms
        self.model = model
        self.build = build
        self.glob = Node()
        self.vd: Dict[str, Node] = {v: Node() for v in (vdoms or ["root"])}
        self.raw_tail: List[str] = []

    def g(self, path: str) -> Table:
        """global table (or root table without VDOMs)"""
        if self.vdoms:
            return self.glob.sub(path)
        return self.vd["root"].sub(path)

    def t(self, path: str, vdom: str = "root") -> Table:
        return self.vd[vdom].sub(path)

    @property
    def proto_default(self) -> str:
        return "TCP/UDP/SCTP" if self.version == "7.4" else "TCP/UDP/UDP-Lite/SCTP"

    def render(self, crlf: bool = False, bom: bool = False, user: str = "admin") -> str:
        out = [f"#config-version={self.model}-{self.full_version}-FW-build{self.build}-260101:opmode=0:vdom={1 if self.vdoms else 0}:user={user}",
               "#conf_file_ver=84000000000000", f"#buildno={self.build}", f"#global_vdom={1 if self.vdoms else 0}"]
        if self.vdoms:
            out.append("config vdom")
            for v in self.vdoms:
                out.append(f"edit {v}")
                out.append("next")
            out.append("end")
            out.append("config global")
            _render_node(self.glob, 0, out)
            out.append("end")
            for v in self.vdoms:
                out.append("config vdom")
                out.append(f"edit {v}")
                _render_node(self.vd[v], 0, out)
                out.append("end")
        else:
            _render_node(self.vd["root"], 0, out)
        out.extend(self.raw_tail)
        text = "\n".join(out) + "\n"
        if crlf:
            text = text.replace("\n", "\r\n")
        if bom:
            text = "﻿" + text
        return text


# --------------------------------------------------------------------------- #
# building blocks

FAKE_CERT = "\n".join(
    ["-----BEGIN CERTIFICATE-----"]
    + ["MIIDdzCCAl+gAwIBAgIUSYNTHETICDEMOCERTIFICATEONLYxxxxxxxxxxxxxxxx"] * 3
    + ["-----END CERTIFICATE-----"]
)
FAKE_KEY = "\n".join(
    ["-----BEGIN ENCRYPTED PRIVATE KEY-----"]
    + ["MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqDEMOPRIVATEKEYNOTREALzzzzzzzzzzzz"] * 3
    + ["-----END ENCRYPTED PRIVATE KEY-----"]
)


def enc(seed: str) -> str:
    """A made-up ENC value. Real FortiOS ENC values are base64 data."""
    import base64
    import hashlib

    return "ENC " + base64.b64encode(hashlib.sha256(seed.encode()).digest() * 2).decode()


FACTORY_SERVICES = [
    ("ALL", {"protocol": "IP"}),
    ("ALL_TCP", {"tcp-portrange": "1-65535"}),
    ("ALL_UDP", {"udp-portrange": "1-65535"}),
    ("ALL_ICMP", {"protocol": "ICMP"}),
    ("HTTP", {"tcp-portrange": "80"}),
    ("HTTPS", {"tcp-portrange": "443"}),
    ("DNS", {"tcp-portrange": "53", "udp-portrange": "53"}),
    ("SSH", {"tcp-portrange": "22"}),
    ("NTP", {"tcp-portrange": "123", "udp-portrange": "123"}),
    ("PING", {"protocol": "ICMP", "icmptype": 8}),
    ("SMTP", {"tcp-portrange": "25"}),
    ("RDP", {"tcp-portrange": "3389"}),
]


def add_factory(c: FGConfig, vdom: str = "root") -> None:
    a = c.t("firewall address", vdom)
    a.edit("all").set("uuid", _uuid(vdom + "all"))
    a.edit("none").set("uuid", _uuid(vdom + "none")).set("subnet", ["0.0.0.0", "255.255.255.255"])
    a6 = c.t("firewall address6", vdom)
    a6.edit("all").set("uuid", _uuid(vdom + "all6"))
    a6.edit("none").set("ip6", "::/128")
    svc = c.t("firewall service custom", vdom)
    for name, f in FACTORY_SERVICES:
        n = svc.edit(name)
        for k, v in f.items():
            n.set(k, v)
    s = c.t("firewall schedule recurring", vdom)
    s.edit("always").set("day", ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"])


def _uuid(seed: str, salt: str = "") -> str:
    import hashlib

    h = hashlib.md5((seed + salt).encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def policy(c: FGConfig, pid: int, vdom: str = "root", salt: str = "", **kw) -> Node:
    t = c.t("firewall policy", vdom)
    n = t.edit(pid)
    n.set("uuid", _uuid(f"{vdom}-pol-{pid}", salt))
    defaults = {"srcintf": ["port2"], "dstintf": ["port1"], "action": "accept", "srcaddr": ["all"], "dstaddr": ["all"],
                "schedule": "always", "service": ["ALL"]}
    for k, v in defaults.items():
        if k not in kw:
            n.set(k, v)
    for k, v in kw.items():
        k = k.replace("_", "-")
        if v is None:
            n.unset(k)
        else:
            n.set(k, v)
    if n.get("action") == "accept" and n.get("logtraffic") is None:
        n.set("logtraffic", "all")
    return n


# --------------------------------------------------------------------------- #
# reference configuration (clean)


def clean_config(version: str = "7.4", vdom_mode: bool = False, salt: str = "") -> FGConfig:
    vdoms = ["root", "dmz-vd"] if vdom_mode else None
    c = FGConfig(version, vdoms)
    gl = c.g("system global")
    gl.set("hostname", "fw-demo-01").set("timezone", "Europe/Vienna" if version != "7.4" else 28).set("admin-sport", 443).set("admintimeout", 15)
    adm = c.g("system admin")
    adm.edit("admin").set("accprofile", "super_admin").set("vdom", "root").set("password", enc("admin" + salt)).set("trusthost1", ["10.10.0.0", "255.255.255.0"])
    adm.edit("netops").set("accprofile", "super_admin").set("vdom", "root").set("password", enc("netops" + salt))
    ifs = c.g("system interface")
    ifs.edit("port1").set("vdom", "root").set("ip", ["203.0.113.2", "255.255.255.248"]).set("allowaccess", ["ping"]).set("role", "wan").set("alias", "Internet")
    ifs.edit("port2").set("vdom", "root").set("ip", ["10.10.0.1", "255.255.255.0"]).set("allowaccess", ["ping", "https", "ssh"]).set("role", "lan")
    p3 = ifs.edit("port3").set("vdom", "root").set("ip", ["10.20.0.1", "255.255.255.0"]).set("allowaccess", ["ping"]).set("role", "dmz")
    p3.set("secondary-IP", "enable")
    p3.sub("secondaryip").edit(1).set("ip", ["10.21.0.1", "255.255.255.0"]).set("allowaccess", ["ping"])
    ifs.edit("vlan100").set("vdom", "root").set("ip", ["10.30.0.1", "255.255.255.0"]).set("interface", "port2").set("vlanid", 100).set("type", "vlan")
    ifs.edit("to-hub").set("vdom", "root").set("type", "tunnel").set("ip", ["169.254.10.2", "255.255.255.255"]).set("remote-ip", ["169.254.10.1", "255.255.255.252"]).set("interface", "port1")
    ifs.edit("loop0").set("vdom", "root").set("type", "loopback").set("ip", ["10.255.0.1", "255.255.255.255"])
    v6 = ifs.edit("port2").sub("ipv6")
    v6.set("ip6-address", "2001:db8:10::1/64")
    if vdom_mode:
        ifs.edit("port4").set("vdom", "dmz-vd").set("ip", ["10.40.0.1", "255.255.255.0"])
        ifs.edit("port5").set("vdom", "dmz-vd").set("ip", ["192.168.50.1", "255.255.255.0"])
    # vdom root content
    add_factory(c)
    c.t("system settings").set("opmode", "nat")
    z = c.t("system zone")
    z.edit("inside").set("interface", ["port2", "vlan100"])
    a = c.t("firewall address")
    a.edit("lan-net").set("subnet", ["10.10.0.0", "255.255.255.0"])
    a.edit("voice-net").set("subnet", ["10.30.0.0", "255.255.255.0"])
    a.edit("dmz-net").set("subnet", ["10.20.0.0", "255.255.255.0"])
    a.edit("web-srv").set("subnet", ["10.20.0.10", "255.255.255.255"]).set("comment", 'Web server "A"')
    a.edit("mail-srv").set("subnet", ["10.20.0.25", "255.255.255.255"])
    a.edit("hub-nets").set("subnet", ["10.0.0.0", "255.0.0.0"])
    a.edit("printer-range").set("type", "iprange").set("start-ip", "10.10.0.200").set("end-ip", "10.10.0.220")
    a.edit("update-fqdn").set("type", "fqdn").set("fqdn", "updates.example.com")
    a.edit("ntp-ext").set("subnet", ["192.0.2.123", "255.255.255.255"])
    g = c.t("firewall addrgrp")
    g.edit("internal-nets").set("member", ["lan-net", "voice-net"])
    a6 = c.t("firewall address6")
    a6.edit("lan6").set("ip6", "2001:db8:10::/64")
    svc = c.t("firewall service custom")
    svc.edit("app-8443").set("tcp-portrange", "8443")
    sg = c.t("firewall service group")
    sg.edit("web").set("member", ["HTTP", "HTTPS"])
    ug = c.t("user group")
    c.t("user local").edit("alice").set("type", "password").set("passwd", enc("alice" + salt))
    ug.edit("vpn-users").set("member", ["alice"])
    pol = lambda pid, **kw: policy(c, pid, salt=salt, **kw)  # noqa: E731
    pol(1, name="lan-to-dmz-web", srcintf=["inside"], dstintf=["port3"], srcaddr=["internal-nets"], dstaddr=["web-srv"], service=["web", "app-8443"])
    pol(2, name="lan-to-mail", srcintf=["port2"], dstintf=["port3"], srcaddr=["lan-net"], dstaddr=["mail-srv"], service=["SMTP"], utm_status="enable", av_profile="default")
    pol(3, name="printers-no-internet", srcintf=["port2"], dstintf=["port1"], srcaddr=["printer-range"], dstaddr=["all"], action="deny", service=["ALL"], logtraffic="all")
    pol(4, name="lan-web-out", srcintf=["port2"], dstintf=["port1"], srcaddr=["lan-net"], dstaddr=["all"], service=["web"], nat="enable",
        utm_status="enable", webfilter_profile="default", ssl_ssh_profile="certificate-inspection")
    # partial overlap with policy 4: 10.10.0.0/24 is not inside voice-net -> no shadow
    pol(5, name="voice-out", srcintf=["vlan100"], dstintf=["port1"], srcaddr=["voice-net"], dstaddr=["all"], service=["ALL"], nat="enable")
    pol(6, name="lan-dns-ntp", srcintf=["port2"], dstintf=["port1"], srcaddr=["lan-net"], dstaddr=["ntp-ext"], service=["NTP"], nat="enable")
    pol(7, name="updates", srcintf=["port3"], dstintf=["port1"], srcaddr=["dmz-net"], dstaddr=["update-fqdn"], service=["HTTPS"], nat="enable")
    pol(8, name="to-hub", srcintf=["inside"], dstintf=["to-hub"], srcaddr=["internal-nets"], dstaddr=["hub-nets"], service=["ALL"])
    pol(9, name="v6-lan-out", srcintf=["port2"], dstintf=["port1"], srcaddr=None, dstaddr=None, srcaddr6=["lan6"], dstaddr6=["all"], service=["web"])
    pol(10, name="vpn-users", srcintf=["to-hub"], dstintf=["port2"], srcaddr=["hub-nets"], dstaddr=["lan-net"], groups=["vpn-users"], service=["HTTPS"])
    # routing
    rs = c.t("router static")
    rs.edit(1).set("gateway", "203.0.113.1").set("device", "port1")
    rs.edit(2).set("dst", ["10.0.0.0", "255.0.0.0"]).set("device", "to-hub")
    rs.edit(3).set("dst", ["10.10.0.0", "255.255.255.128"]).set("gateway", "10.10.0.254").set("device", "port2")  # more specific: normal
    # VPN: route-based with 0.0.0.0/0 selectors and a hub summary selector
    p1 = c.t("vpn ipsec phase1-interface")
    p1.edit("to-hub").set("interface", "port1").set("ike-version", 2).set("peertype", "any").set("proposal", "aes256-sha256").set("remote-gw", "198.51.100.10").set("psksecret", enc("psk" + salt))
    p2 = c.t("vpn ipsec phase2-interface")
    p2.edit("to-hub-p2").set("phase1name", "to-hub").set("proposal", "aes256-sha256")
    p2.edit("to-hub-summary").set("phase1name", "to-hub").set("proposal", "aes256-sha256").set("src-subnet", ["10.10.0.0", "255.255.255.0"]).set("dst-subnet", ["10.0.0.0", "255.0.0.0"])
    # DHCP / pools / VIPs
    d = c.t("system dhcp server")
    srv = d.edit(1).set("default-gateway", "10.10.0.1").set("netmask", "255.255.255.0").set("interface", "port2")
    srv.sub("ip-range").edit(1).set("start-ip", "10.10.0.100").set("end-ip", "10.10.0.199")
    pool = c.t("firewall ippool")
    pool.edit("wan-pool").set("startip", "203.0.113.3").set("endip", "203.0.113.4")
    vip = c.t("firewall vip")
    vip.edit("web-vip").set("extip", "203.0.113.2").set("mappedip", ["10.20.0.10"]).set("extintf", "port1").set("portforward", "enable").set("extport", 443).set("mappedport", 443)
    vip.edit("mail-vip").set("extip", "203.0.113.2").set("mappedip", ["10.20.0.25"]).set("extintf", "port1").set("portforward", "enable").set("extport", 25).set("mappedport", 25)
    pol(11, name="inbound-web", srcintf=["port1"], dstintf=["port3"], srcaddr=["all"], dstaddr=["web-vip"], service=["HTTPS"])
    pol(12, name="inbound-mail", srcintf=["port1"], dstintf=["port3"], srcaddr=["all"], dstaddr=["mail-vip"], service=["SMTP"], ippool="enable", poolname=["wan-pool"])
    # certificate with a multi-line value, and an unknown section
    cert = c.t("vpn certificate local")
    cert.edit("demo-cert").set("password", enc("certpw" + salt)).set("private-key", FAKE_KEY).set("certificate", FAKE_CERT)
    c.t("system some-future-feature").set("mode", "experimental-value")
    if vdom_mode:
        add_factory(c, "dmz-vd")
        a2 = c.t("firewall address", "dmz-vd")
        a2.edit("dmz2-net").set("subnet", ["10.40.0.0", "255.255.255.0"])
        a2.edit("lab-net").set("subnet", ["192.168.50.0", "255.255.255.0"])
        policy(c, 1, "dmz-vd", salt=salt, name="dmz2-out", srcintf=["port4"], dstintf=["port5"], srcaddr=["dmz2-net"], dstaddr=["lab-net"], service=["HTTPS"])
    return c


# --------------------------------------------------------------------------- #
# audit scenario with faults


@dataclass
class Expect:
    code: str
    vdom: Optional[str] = None
    objects: Tuple[str, ...] = ()  # names/ids that must appear in the finding objects


def faulty_config(version: str = "7.4", vdom_mode: bool = False) -> Tuple[FGConfig, List[Expect], List[str]]:
    """Return (config, expected findings, forbidden codes-with-object)."""
    c = clean_config(version, vdom_mode)
    a = c.t("firewall address")
    g = c.t("firewall addrgrp")
    svc = c.t("firewall service custom")
    exp: List[Expect] = []
    pt = c.t("firewall policy")

    # 1) conflict + ID/order mismatch: policy 40 is listed before 20 but has the higher ID
    a.edit("guest-net").set("subnet", ["10.10.0.128", "255.255.255.128"])
    policy(c, 40, name="lan-any-out", srcintf=["port2"], dstintf=["port1"], srcaddr=["lan-net"], dstaddr=["all"], service=["ALL"], nat="enable")
    policy(c, 20, name="block-guest-smtp", srcintf=["port2"], dstintf=["port1"], srcaddr=["guest-net"], dstaddr=["all"], service=["SMTP"], action="deny")
    exp.append(Expect("shadow.conflict", "root", ("20", "40")))

    # 2) redundant via nested groups and service group, different profiles
    a.edit("pc-01").set("subnet", ["10.10.0.21", "255.255.255.255"])
    g.edit("staff-pcs").set("member", ["pc-01"])
    g.edit("all-staff").set("member", ["staff-pcs", "printer-range"])
    policy(c, 41, name="staff-https", srcintf=["port2"], dstintf=["port1"], srcaddr=["all-staff"], dstaddr=["all"], service=["HTTPS"], nat="enable",
           utm_status="enable", av_profile="strict-av")
    exp.append(Expect("shadow.redundant", "root", ("41", "4")))

    # 3) duplicate of policy 6
    policy(c, 42, name="lan-dns-ntp-copy", srcintf=["port2"], dstintf=["port1"], srcaddr=["lan-net"], dstaddr=["ntp-ext"], service=["NTP"], nat="enable")
    exp.append(Expect("shadow.duplicate", "root", ("42", "6")))

    # 4) dynamic object: later policy to an FQDN that the earlier one does not provably cover
    a.edit("partner-fqdn").set("type", "fqdn").set("fqdn", "partner.example.net")
    policy(c, 43, name="dmz-partner", srcintf=["port3"], dstintf=["port1"], srcaddr=["dmz-net"], dstaddr=["partner-fqdn"], service=["HTTPS"], action="deny")
    a.edit("geo-xx").set("type", "geography").set("country", "XX")
    policy(c, 44, name="dmz-geo-block", srcintf=["port3"], dstintf=["port1"], srcaddr=["dmz-net"], dstaddr=["geo-xx"], service=["ALL"], action="deny")
    policy(c, 45, name="dmz-any-out", srcintf=["port3"], dstintf=["port1"], srcaddr=["dmz-net"], dstaddr=["update-fqdn", "ntp-ext"], service=["HTTPS"], nat="enable")
    # policy 45 vs policy 7: 7 has dst update-fqdn only -> 45 (fqdn+static) not provable
    exp.append(Expect("shadow.uncertain", "root", ("45", "7")))
    # 43 (partner FQDN) vs 7 (updates FQDN): two different FQDNs could resolve to the same IPs
    exp.append(Expect("shadow.uncertain", "root", ("43", "7")))

    # 5) VIP must never count as covered, even under dstaddr all
    policy(c, 46, name="inbound-any-deny", srcintf=["port1"], dstintf=["port3"], srcaddr=["all"], dstaddr=["all"], service=["ALL"], action="deny")
    # move 46 before 11 so it sits above the VIP policies
    pt.move_before(46, 11)
    exp.append(Expect("shadow.uncertain", "root", ("11", "46")))
    exp.append(Expect("shadow.uncertain", "root", ("12", "46")))

    # 6) negation: earlier deny "everything except 10/8", later accept to a public host -> conflict
    a.edit("public-dns").set("subnet", ["192.0.2.53", "255.255.255.255"])
    policy(c, 47, name="vlan-only-internal", srcintf=["vlan100"], dstintf=["port1"], srcaddr=["voice-net"], dstaddr=["hub-nets"], dstaddr_negate="enable", service=["ALL"], action="deny")
    pt.move_before(47, 5)
    policy(c, 48, name="voice-dns", srcintf=["vlan100"], dstintf=["port1"], srcaddr=["voice-net"], dstaddr=["public-dns"], service=["DNS"], nat="enable")
    exp.append(Expect("shadow.conflict", "root", ("48", "47")))
    # policy 5 (voice-out, accept all) is now partially covered by 47: no finding for 5
    # 7) exclusion: group with exclude - covered host and excluded host
    a.edit("lan-low").set("subnet", ["10.10.0.0", "255.255.255.128"])
    g.edit("lan-minus-guest").set("member", ["lan-net"]).set("exclude", "enable").set("exclude-member", ["guest-net"])
    a.edit("guest-pc").set("subnet", ["10.10.0.200", "255.255.255.255"])
    policy(c, 49, name="lan-ssh-dmz", srcintf=["port2"], dstintf=["port3"], srcaddr=["lan-minus-guest"], dstaddr=["dmz-net"], service=["SSH"], action="deny")
    policy(c, 50, name="guest-ssh-dmz", srcintf=["port2"], dstintf=["port3"], srcaddr=["guest-pc"], dstaddr=["dmz-net"], service=["SSH"])  # not covered (excluded)
    policy(c, 51, name="lowlan-ssh-dmz", srcintf=["port2"], dstintf=["port3"], srcaddr=["lan-low"], dstaddr=["dmz-net"], service=["SSH"])  # covered -> conflict
    exp.append(Expect("shadow.conflict", "root", ("51", "49")))

    # 8) ports and source ports
    svc.edit("tcp-high-src").set("protocol", c.proto_default).set("tcp-portrange", "8080:1024-65535")
    svc.edit("http-alt-strict-src").set("tcp-portrange", "8081:1024-2048")
    policy(c, 52, name="dmz-tcp-all", srcintf=["port3"], dstintf=["port2"], srcaddr=["dmz-net"], dstaddr=["lan-net"], service=["ALL_TCP"], action="deny")
    policy(c, 53, name="dmz-8080", srcintf=["port3"], dstintf=["port2"], srcaddr=["web-srv"], dstaddr=["lan-net"], service=["tcp-high-src"])  # covered -> conflict
    exp.append(Expect("shadow.conflict", "root", ("53", "52")))
    policy(c, 54, name="dmz-8081-any-src", srcintf=["port3"], dstintf=["port2"], srcaddr=["web-srv"], dstaddr=["voice-net"], service=["tcp-high-src"])
    policy(c, 55, name="dmz-8081", srcintf=["port3"], dstintf=["port2"], srcaddr=["web-srv"], dstaddr=["voice-net"], service=["http-alt-strict-src"])  # src ports 1024-2048 vs 1024-65535 but dport 8081 != 8080 -> no
    # 9) disabled earlier policy must not shadow
    policy(c, 56, name="old-disabled", srcintf=["port3"], dstintf=["vlan100"], srcaddr=["all"], dstaddr=["all"], service=["ALL"], action="deny", status="disable")
    policy(c, 57, name="dmz-voice", srcintf=["port3"], dstintf=["vlan100"], srcaddr=["dmz-net"], dstaddr=["voice-net"], service=["HTTPS"])
    # 10) IPv6 conflict
    a6 = c.t("firewall address6")
    a6.edit("lan6-printers").set("ip6", "2001:db8:10::200/120")
    policy(c, 58, name="v6-printers-block", srcintf=["port2"], dstintf=["port1"], srcaddr=None, dstaddr=None, srcaddr6=["lan6-printers"], dstaddr6=["all"], service=["HTTPS"], action="deny")
    exp.append(Expect("shadow.conflict", "root", ("58", "9")))
    # 11) users: earlier group-based policy must not cover a later policy without users
    policy(c, 59, name="hub-to-lan-https", srcintf=["to-hub"], dstintf=["port2"], srcaddr=["hub-nets"], dstaddr=["lan-net"], service=["HTTPS"], action="deny")
    # 12) unused objects
    a.edit("old-server").set("subnet", ["10.20.0.99", "255.255.255.255"])
    svc.edit("legacy-app").set("tcp-portrange", "9999")
    exp.append(Expect("unused.object", "root", ("old-server",)))
    exp.append(Expect("unused.object", "root", ("legacy-app",)))

    # ---- overlaps
    st = c.t("system settings")
    st.set("allow-subnet-overlap", "enable")
    ifs = c.g("system interface")
    ifs.edit("port6").set("vdom", "root").set("ip", ["10.10.0.129", "255.255.255.128"])
    exp.append(Expect("overlap.interface", "root", ("port2", "port6")))
    d = c.t("system dhcp server")
    srv = d.edit(2).set("default-gateway", "10.20.0.1").set("netmask", "255.255.255.0").set("interface", "port3")
    srv.sub("ip-range").edit(1).set("start-ip", "10.20.0.200").set("end-ip", "10.20.1.20")
    exp.append(Expect("overlap.dhcp-outside", "root", ("2 (port3)",)))
    pool = c.t("firewall ippool")
    pool.edit("wan-pool-2").set("startip", "203.0.113.4").set("endip", "203.0.113.5")
    exp.append(Expect("overlap.ippool", "root", ("wan-pool", "wan-pool-2")))
    vip = c.t("firewall vip")
    vip.edit("old-web-vip").set("extip", "203.0.113.2").set("mappedip", ["10.20.0.11"]).set("extintf", "port1").set("portforward", "enable").set("extport", 443).set("mappedport", 443)
    exp.append(Expect("overlap.vip", "root", ("web-vip", "old-web-vip")))
    p1 = c.t("vpn ipsec phase1-interface")
    p1.edit("partner").set("interface", "port1").set("ike-version", 2).set("peertype", "any").set("proposal", "aes256-sha256").set("remote-gw", "198.51.100.77").set("psksecret", enc("partner"))
    p2 = c.t("vpn ipsec phase2-interface")
    p2.edit("partner-p2").set("phase1name", "partner").set("proposal", "aes256-sha256").set("src-subnet", ["10.20.0.0", "255.255.255.0"]).set("dst-subnet", ["10.30.0.0", "255.255.255.0"])
    exp.append(Expect("overlap.p2-local-net", "root", ("partner-p2", "vlan100")))
    policy(c, 60, name="dmz-to-partner", srcintf=["port3"], dstintf=["partner"], srcaddr=["dmz-net"], dstaddr=["voice-net"], service=["HTTPS"])
    return c, exp, []


# --------------------------------------------------------------------------- #
# change scenario


def change_pair(version: str = "7.6") -> Tuple[str, str, List[Expect], List[str]]:
    before = clean_config(version, salt="a")
    after = clean_config(version, salt="b")  # different UUIDs and ENC values: noise
    after.build = before.build + 7
    ifs = after.g("system interface")
    ifs.edit("port2").set("allowaccess", ["ping"])  # ssh/https removed
    ifs.edit("port1").set("allowaccess", ["ping", "http"])
    pt = after.t("firewall policy")
    policy(after, 70, name="temp-any", srcintf=["any"], dstintf=["any"], srcaddr=["all"], dstaddr=["all"], service=["ALL"], salt="b")
    pt.move_before(70, 1)
    pt.edit(2).set("logtraffic", "disable")
    after.t("firewall address").edit("web-srv").set("subnet", ["10.20.0.12", "255.255.255.255"])
    # move the printer deny below the general web-out accept: behaviour change
    pt.move_after(3, 4)
    after.t("router static").edit(1).set("gateway", "203.0.113.6")
    # re-order address objects: no meaning
    at = after.t("firewall address")
    at.entries.reverse()
    exp = [
        Expect("change.lockout-allowaccess", "root", ("port2",)),
        Expect("change.insecure-allowaccess", "root", ("port1",)),
        Expect("change.broad-accept", "root", ("70",)),
        Expect("change.logging-disabled", "root", ("2",)),
        Expect("change.object", "root", ("web-srv",)),
        Expect("change.order-conflict", "root", ("3",)),
        Expect("change.default-route", "root", ("1",)),
        Expect("change.secret-not-comparable", "root", ("to-hub",)),
    ]
    forbidden = ["change.order-conflict:1", "change.object:lan-net", "change.other"]
    return before.render(), after.render(crlf=True), exp, forbidden


# --------------------------------------------------------------------------- #
# logs


def _ns(ts: float) -> int:
    return int(ts * 1e9)


def _line(ts_utc: float, tz: Optional[str], dev: str, devid: str, logid: str, typ: str, sub: str, level: str, extra: Dict[str, str],
          syslog: bool = False, with_eventtime: bool = True) -> str:
    from datetime import datetime, timedelta, timezone

    off = timedelta(0)
    if tz:
        sign = -1 if tz[0] == "-" else 1
        off = sign * timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5]))
    local = datetime.fromtimestamp(ts_utc, timezone.utc) + off
    parts = [f"date={local:%Y-%m-%d}", f"time={local:%H:%M:%S}", f'devname="{dev}"', f'devid="{devid}"']
    if with_eventtime:
        parts.append(f"eventtime={_ns(ts_utc)}")
    if tz:
        parts.append(f'tz="{tz}"')
    parts += [f'logid="{logid}"', f'type="{typ}"', f'subtype="{sub}"', f'level="{level}"', 'vd="root"']
    for k, v in extra.items():
        parts.append(f'{k}="{v}"' if not v.isdigit() else f"{k}={v}")
    s = " ".join(parts)
    if syslog:
        s = f"<185>{local:%b %d %H:%M:%S} {dev} " + s
    return s


def incident_logs(version: str = "8.0", seed: int = 7) -> Tuple[Dict[str, str], Dict[str, object]]:
    """Return ({filename: text}, ground truth)."""
    from datetime import datetime, timezone

    rnd = random.Random(seed)
    t0 = datetime(2026, 10, 14, 9, 2, 3, tzinfo=timezone.utc).timestamp()  # 10:02:03 +0100
    br, brid = "fw-branch-01", "FGVMDEMO00000001"
    hub, hubid = "fw-hub-01", "FGVMDEMO00000002"
    L = []
    tzb = "+0100"
    L.append((t0 - 300, _line(t0 - 300, tzb, br, brid, "0100032001", "event", "system", "information",
                              {"user": "netops", "ui": "https(10.10.0.50)", "action": "login", "status": "success", "msg": "Administrator netops logged in successfully from https(10.10.0.50)"})))
    L.append((t0 - 180, _line(t0 - 180, tzb, br, brid, "0100044547", "event", "system", "information",
                              {"user": "netops", "ui": "GUI(10.10.0.50)", "action": "Edit", "cfgtid": "1234", "cfgpath": "system.interface", "cfgobj": "port1",
                               "cfgattr": "speed[auto->1000full]", "msg": "Edit system.interface port1"})))
    L.append((t0, _line(t0, tzb, br, brid, "0100020090", "event", "system", "notice", {"intf": "port1", "status": "down", "msg": "Link monitor: Interface port1 was turned down"})))
    L.append((t0 + 2, _line(t0 + 2, tzb, br, brid, "0113022923", "event", "sdwan", "notice",
                            {"eventtype": "Health Check", "healthcheck": "internet", "interface": "port1", "member": "1", "oldvalue": "alive", "newvalue": "dead",
                             "msg": "Member status changed. Member out-of-sla."})))
    for i in range(400):
        ts = t0 + 3 + i
        L.append((ts, _line(ts, tzb, br, brid, "0113022923", "event", "sdwan", "notice",
                            {"eventtype": "Health Check", "healthcheck": "internet", "interface": "port1", "member": "1", "oldvalue": "dead", "newvalue": "dead",
                             "msg": "Member status changed. Member out-of-sla."})))
    L.append((t0 + 7, _line(t0 + 7, tzb, br, brid, "0101037138", "event", "vpn", "notice",
                            {"action": "tunnel-down", "vpntunnel": "to-hub", "outintf": "port1", "remip": "198.51.100.10", "locip": "203.0.113.2",
                             "msg": "IPsec connection status change"})))
    L.append((t0 + 40, _line(t0 + 40, tzb, br, brid, "0103020300", "event", "router", "warning",
                             {"msg": "BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.10.1 Down Hold Timer Expired"})))
    # traffic logs (skipped but counted)
    for i in range(50):
        ts = t0 - 600 + i * 7
        L.append((ts, _line(ts, tzb, br, brid, "0000000013", "traffic", "forward", "notice",
                            {"srcip": f"10.10.0.{rnd.randint(2, 250)}", "dstip": "192.0.2.80", "action": "close", "policyid": "4"})))
    # unknown event logs
    for i in range(7):
        ts = t0 + 900 + i
        L.append((ts, _line(ts, tzb, br, brid, "0100099999", "event", "system", "notice", {"logdesc": "Demo unknown event", "msg": "something not in the table"})))
    # recovery
    L.append((t0 + 1080, _line(t0 + 1080, tzb, br, brid, "0100020090", "event", "system", "notice", {"intf": "port1", "status": "up", "msg": "Link monitor: Interface port1 was turned up"})))
    L.append((t0 + 1090, _line(t0 + 1090, tzb, br, brid, "0101037138", "event", "vpn", "notice", {"action": "tunnel-up", "vpntunnel": "to-hub", "outintf": "port1", "remip": "198.51.100.10", "msg": "IPsec connection status change"})))
    L.append((t0 + 1120, _line(t0 + 1120, tzb, br, brid, "0103020300", "event", "router", "notice", {"msg": "BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.10.1 Up"})))
    # second, unrelated incident: conserve mode
    t2 = t0 + 4 * 3600 + 1500
    L.append((t2, _line(t2, tzb, br, brid, "0100022011", "event", "system", "critical", {"conserve": "on", "total": "2048", "used": "1801", "red": "1802", "green": "1720", "msg": "Kernel enters memory conserve mode"})))
    L.append((t2 + 240, _line(t2 + 240, tzb, br, brid, "0100022012", "event", "system", "critical", {"conserve": "exit", "total": "2048", "used": "1600", "red": "1802", "green": "1720", "msg": "Kernel leaves memory conserve mode"})))
    L.sort(key=lambda x: x[0])
    branch_lines = [x[1] for x in L]
    # garbage lines
    branch_lines.insert(10, "this line is not a FortiGate log")
    branch_lines.insert(20, "\x00\x01 broken")
    branch_lines.insert(30, 'date=2026-10-14 time=garbled logid=')

    # hub: syslog format with tz, sees the tunnel go down a few seconds later
    H = []
    H.append(_line(t0 + 9, "+0100", hub, hubid, "0101037138", "event", "vpn", "notice",
                   {"action": "tunnel-down", "vpntunnel": "branch-01", "outintf": "port1", "remip": "203.0.113.2", "msg": "IPsec connection status change"}, syslog=True))
    H.append(_line(t0 + 41, "+0100", hub, hubid, "0103020300", "event", "router", "warning",
                   {"msg": "BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.10.2 Down Hold Timer Expired"}, syslog=True))
    H.append(_line(t0 + 1095, "+0100", hub, hubid, "0101037138", "event", "vpn", "notice",
                   {"action": "tunnel-up", "vpntunnel": "branch-01", "outintf": "port1", "remip": "203.0.113.2", "msg": "IPsec connection status change"}, syslog=True))
    # lab device without tz and without eventtime
    lab = [
        _line(t0 + 7200, None, "fw-lab-01", "FGVMDEMO00000003", "0100032002", "event", "system", "alert",
              {"user": "test", "ui": "ssh(192.0.2.99)", "action": "login", "status": "failed", "reason": "passwd_invalid", "msg": "Administrator test login failed from ssh(192.0.2.99) because of invalid password"},
              with_eventtime=False),
    ]
    files = {
        "branch-01.log": "\n".join(branch_lines) + "\n",
        "hub-01-syslog.log": "\n".join(H) + "\n",
        "lab-01.log": "\r\n".join(lab) + "\r\n",
    }
    truth = {
        "trigger": ("interface", "port1", br),
        "chain_cats": {"sdwan", "ipsec", "bgp"},
        "repeat_count": 401,
        "unknown_logid": "0100099999",
        "unknown_count": 7,
        "unparseable": 3,
        "traffic": 50,
        "tz_missing": ["fw-lab-01"],
        "incidents_min": 2,
    }
    return files, truth


# --------------------------------------------------------------------------- #
# large config


def large_config(n: int = 5000, version: str = "7.6", seed: int = 1) -> Tuple[str, List[Tuple[str, str]]]:
    """n policies over many interface pairs, with a few injected shadows.
    Returns (text, [(later_id, earlier_id)] of injected conflicts)."""
    rnd = random.Random(seed)
    c = FGConfig(version)
    add_factory(c)
    ifs = c.g("system interface")
    nif = 24
    for i in range(1, nif + 1):
        ifs.edit(f"port{i}").set("vdom", "root").set("ip", [f"10.{i}.0.1", "255.255.0.0"])
    a = c.t("firewall address")
    names = []
    for i in range(1500):
        nm = f"h-{i:04d}"
        a.edit(nm).set("subnet", [f"10.{rnd.randint(1, nif)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}", "255.255.255.255"])
        names.append(nm)
    for i in range(300):
        nm = f"n-{i:03d}"
        a.edit(nm).set("subnet", [f"10.{rnd.randint(1, nif)}.{rnd.randint(0, 255)}.0", "255.255.255.0"])
        names.append(nm)
    g = c.t("firewall addrgrp")
    for i in range(100):
        g.edit(f"grp-{i:03d}").set("member", rnd.sample(names, 5))
        names.append(f"grp-{i:03d}")
    svc = c.t("firewall service custom")
    snames = [s for s, _ in FACTORY_SERVICES]
    for i in range(200):
        svc.edit(f"tcp-{8000 + i}").set("tcp-portrange", str(8000 + i))
        snames.append(f"tcp-{8000 + i}")
    injected = []
    pid = 1
    for k in range(n):
        si, di = rnd.sample(range(1, nif + 1), 2)
        if k % 1000 == 500:
            # injected: broad deny followed by specific accept on same pair
            policy(c, pid, srcintf=[f"port{si}"], dstintf=[f"port{di}"], srcaddr=["all"], dstaddr=["all"], service=["ALL"], action="deny")
            policy(c, pid + 1, srcintf=[f"port{si}"], dstintf=[f"port{di}"], srcaddr=[rnd.choice(names)], dstaddr=[rnd.choice(names)], service=["HTTPS"])
            injected.append((str(pid + 1), str(pid)))
            pid += 2
            continue
        policy(c, pid, srcintf=[f"port{si}"], dstintf=[f"port{di}"], srcaddr=rnd.sample(names, rnd.randint(1, 3)),
               dstaddr=rnd.sample(names, rnd.randint(1, 3)), service=rnd.sample(snames, rnd.randint(1, 3)),
               action=rnd.choice(["accept", "accept", "accept", "deny"]))
        pid += 1
    return c.render(), injected


def demo_inputs() -> Dict[str, object]:
    cfg, _, _ = faulty_config("7.4")
    before, after, _, _ = change_pair("7.6")
    logs, _ = incident_logs("8.0")
    return {"audit": ("fw-demo-01_7-4.conf", cfg.render()), "before": ("fw-demo-01_before.conf", before),
            "after": ("fw-demo-01_after.conf", after), "logs": logs}
