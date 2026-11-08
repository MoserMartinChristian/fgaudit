"""Data structures shared by all checks and renderers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SEVERITIES = ("high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Obj:
    type: str  # policy, address, service, interface, vip, ippool, dhcp, phase2, ...
    name: str
    vdom: Optional[str] = None
    id: Optional[str] = None  # policy id where relevant

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"type": self.type, "name": self.name}
        if self.vdom is not None:
            d["vdom"] = self.vdom
        if self.id is not None:
            d["id"] = self.id
        return d


@dataclass
class Finding:
    check: str  # shadow | change | overlap | timeline
    code: str  # stable id, e.g. "shadow.conflict"
    severity: str
    vdom: Optional[str] = None
    objects: List[Obj] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)
    order: int = 0  # secondary sort key (e.g. policy sequence)
    # filled by i18n.localize()
    title: str = ""
    detail: str = ""
    next_step: str = ""

    @property
    def counts(self) -> bool:
        """Findings that make the exit code 1 (``info`` notes do not)."""
        return self.severity != "info"


@dataclass
class Notice:
    code: str
    params: Dict[str, Any] = field(default_factory=dict)
    text: str = ""  # localized


@dataclass
class Report:
    mode: str  # audit | change | timeline | demo
    inputs: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    notices: List[Notice] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    timeline: Optional[Dict[str, Any]] = None
    sections: List["Report"] = field(default_factory=list)  # demo mode
    title: str = ""

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (SEV_RANK[f.severity], f.check, f.vdom or "", f.order))

    def all_findings(self) -> List[Finding]:
        out = list(self.findings)
        for s in self.sections:
            out.extend(s.all_findings())
        return out

    def severity_counts(self) -> Dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.all_findings():
            c[f.severity] += 1
        return c

    @property
    def has_findings(self) -> bool:
        return any(f.counts for f in self.all_findings())
