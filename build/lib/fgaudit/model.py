"""VDOM-aware view on a parsed FortiOS configuration."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .parser import Config, Entry, ParseResult, ParseWarning, decode_bytes, parse

SUPPORTED_VERSIONS = {(7, 4), (7, 6), (8, 0)}

_HEADER_RE = re.compile(
    r"config-version=(?P<model>[A-Za-z0-9_]+)-(?P<maj>\d+)\.(?P<min>\d+)\.(?P<patch>\d+)"
    r"-FW-build(?P<build>\d+)(?:-(?P<date>\d+))?(?P<rest>.*)"
)

# Sections that only exist in "config global" when VDOMs are enabled.
GLOBAL_ONLY_HINT = ("system global", "system admin", "system ha", "system interface")


class InputError(Exception):
    """Raised for input files that cannot be audited (exit code 2).

    ``code`` is a stable key that the CLI translates; ``params`` never contain
    file content."""

    def __init__(self, code: str, **params: object):
        super().__init__(code)
        self.code = code
        self.params = params


@dataclass
class Vdom:
    name: str
    root: Config  # container whose children are the vdom's config blocks

    def table(self, path: str) -> Config:
        c = self.root.children.get(path)
        return c if c is not None else Config(path=path)

    def has(self, path: str) -> bool:
        return path in self.root.children


@dataclass
class FortiConfig:
    filename: str
    parsed: ParseResult
    model: Optional[str] = None
    version: Optional[Tuple[int, int, int]] = None
    build: Optional[str] = None
    vdom_mode: bool = False
    header_user: Optional[str] = None
    global_root: Config = field(default_factory=lambda: Config(path=""))
    vdoms: Dict[str, Vdom] = field(default_factory=dict)

    @property
    def version_str(self) -> str:
        if not self.version:
            return "unknown"
        return "%d.%d.%d" % self.version

    @property
    def supported(self) -> bool:
        return bool(self.version) and self.version[:2] in SUPPORTED_VERSIONS

    @property
    def warnings(self) -> List[ParseWarning]:
        return self.parsed.warnings

    def gtable(self, path: str) -> Config:
        c = self.global_root.children.get(path)
        return c if c is not None else Config(path=path)

    def interfaces(self) -> Config:
        return self.gtable("system interface")

    def interface_vdom(self, ent: Entry) -> str:
        if not self.vdom_mode:
            return next(iter(self.vdoms), "root")
        return ent.get("vdom", "root") or "root"


def looks_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:65536]
    if b"\x00" in sample:
        return True
    bad = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return bad / max(1, len(sample)) > 0.02


def load_config(data: bytes, filename: str) -> FortiConfig:
    """Build a FortiConfig from raw file bytes. Raises InputError for files
    that are encrypted, binary or not a FortiOS configuration."""
    if not data.strip():
        raise InputError("empty-file", file=filename)
    text = decode_bytes(data)
    first = text.lstrip()[:400]
    has_header = "#config-version=" in first
    if looks_binary(data):
        if has_header or data[:1] == b"#":
            raise InputError("encrypted-backup", file=filename)
        raise InputError("binary-file", file=filename)
    pr = parse(text)
    config_blocks = len(pr.root.children)
    if config_blocks == 0:
        if has_header:
            # header present but no readable configuration: encrypted backups
            # keep a text header followed by encoded data
            raise InputError("encrypted-backup", file=filename)
        raise InputError("not-a-config", file=filename)
    fc = FortiConfig(filename=filename, parsed=pr)
    for h in pr.header:
        m = _HEADER_RE.search(h)
        if m:
            fc.model = m.group("model")
            fc.version = (int(m.group("maj")), int(m.group("min")), int(m.group("patch")))
            fc.build = m.group("build")
            rest = m.group("rest") or ""
            vm = re.search(r":vdom=(\d)", rest)
            if vm:
                fc.vdom_mode = vm.group(1) == "1"
            um = re.search(r":user=([^:]+)", rest)
            if um:
                fc.header_user = um.group(1).strip()
            break
    root = pr.root
    if "global" in root.children or (
        "vdom" in root.children and "global" in root.children
    ):
        fc.vdom_mode = True
    if fc.vdom_mode and "global" in root.children:
        fc.global_root = root.children["global"]
        vd = root.children.get("vdom")
        if vd is not None:
            for name, ent in vd.entries.items():
                fc.vdoms[name] = Vdom(name=name, root=_entry_as_config(ent))
        if not fc.vdoms:
            fc.vdoms["root"] = Vdom(name="root", root=Config(path=""))
    else:
        fc.vdom_mode = False
        fc.global_root = root
        fc.vdoms["root"] = Vdom(name="root", root=root)
    return fc


def _entry_as_config(ent: Entry) -> Config:
    c = Config(path="", line=ent.line)
    c.children = ent.children
    c.settings = ent.settings
    return c


def is_log_text(text: str) -> bool:
    """Heuristic: FortiGate key=value log lines."""
    hits = 0
    lines = 0
    for line in text.splitlines()[:200]:
        if not line.strip():
            continue
        lines += 1
        if ("logid=" in line or "logid=\"" in line) and ("type=" in line):
            hits += 1
    return lines > 0 and hits / lines >= 0.3


def is_config_text(text: str) -> bool:
    head = text.lstrip()[:2000]
    if "#config-version=" in head:
        return True
    return bool(re.search(r"^\s*config (system|firewall|vdom|global|router|vpn|user|log)\b", head, re.M))
