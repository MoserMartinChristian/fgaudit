"""Small integer interval sets used for IP address and port arithmetic.

Only the standard library is used. IP addresses are converted to integers with
:mod:`ipaddress`.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, List, Optional, Sequence, Tuple

V4_MAX = (1 << 32) - 1
V6_MAX = (1 << 128) - 1

Range = Tuple[int, int]


class IntervalSet:
    """Immutable, normalised set of inclusive integer ranges."""

    __slots__ = ("r",)

    def __init__(self, ranges: Iterable[Range] = ()):
        self.r: Tuple[Range, ...] = _normalise(ranges)

    # constructors ------------------------------------------------------
    @classmethod
    def single(cls, lo: int, hi: int) -> "IntervalSet":
        return cls([(lo, hi)])

    # predicates --------------------------------------------------------
    def is_empty(self) -> bool:
        return not self.r

    def __bool__(self) -> bool:
        return bool(self.r)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, IntervalSet) and self.r == other.r

    def __hash__(self) -> int:
        return hash(self.r)

    def __repr__(self) -> str:
        return f"IntervalSet({list(self.r)!r})"

    def is_full(self, lo: int, hi: int) -> bool:
        return len(self.r) == 1 and self.r[0][0] <= lo and self.r[0][1] >= hi

    def issubset(self, other: "IntervalSet") -> bool:
        """True if every element of self is in other."""
        if not self.r:
            return True
        o = other.r
        if not o:
            return False
        j = 0
        for lo, hi in self.r:
            while j < len(o) and o[j][1] < lo:
                j += 1
            if j >= len(o) or o[j][0] > lo or o[j][1] < hi:
                return False
        return True

    def overlaps(self, other: "IntervalSet") -> bool:
        a, b = self.r, other.r
        i = j = 0
        while i < len(a) and j < len(b):
            if a[i][1] < b[j][0]:
                i += 1
            elif b[j][1] < a[i][0]:
                j += 1
            else:
                return True
        return False

    # operations --------------------------------------------------------
    def union(self, other: "IntervalSet") -> "IntervalSet":
        return IntervalSet(self.r + other.r)

    def intersection(self, other: "IntervalSet") -> "IntervalSet":
        a, b = self.r, other.r
        i = j = 0
        out: List[Range] = []
        while i < len(a) and j < len(b):
            lo = max(a[i][0], b[j][0])
            hi = min(a[i][1], b[j][1])
            if lo <= hi:
                out.append((lo, hi))
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        s = IntervalSet()
        s.r = tuple(out)
        return s

    def difference(self, other: "IntervalSet") -> "IntervalSet":
        out: List[Range] = []
        b = other.r
        for lo, hi in self.r:
            cur = lo
            for blo, bhi in b:
                if bhi < cur:
                    continue
                if blo > hi:
                    break
                if blo > cur:
                    out.append((cur, blo - 1))
                cur = max(cur, bhi + 1)
                if cur > hi:
                    break
            if cur <= hi:
                out.append((cur, hi))
        s = IntervalSet()
        s.r = tuple(out)
        return s

    def complement(self, lo: int, hi: int) -> "IntervalSet":
        return IntervalSet.single(lo, hi).difference(self)

    def bounds(self) -> Optional[Range]:
        if not self.r:
            return None
        return (self.r[0][0], self.r[-1][1])


def _normalise(ranges: Iterable[Range]) -> Tuple[Range, ...]:
    rs = sorted((lo, hi) for lo, hi in ranges if lo <= hi)
    out: List[Range] = []
    for lo, hi in rs:
        if out and lo <= out[-1][1] + 1:
            if hi > out[-1][1]:
                out[-1] = (out[-1][0], hi)
        else:
            out.append((lo, hi))
    return tuple(out)


EMPTY = IntervalSet()
V4_ALL = IntervalSet.single(0, V4_MAX)
V6_ALL = IntervalSet.single(0, V6_MAX)


# --------------------------------------------------------------------------- #
# parsing helpers


def v4_int(s: str) -> Optional[int]:
    try:
        return int(ipaddress.IPv4Address(s))
    except (ipaddress.AddressValueError, ValueError):
        return None


def v6_int(s: str) -> Optional[int]:
    try:
        return int(ipaddress.IPv6Address(s.split("%")[0]))
    except (ipaddress.AddressValueError, ValueError):
        return None


def mask_to_prefix(mask: str) -> Optional[int]:
    """Return the prefix length of a contiguous dotted mask, else None."""
    m = v4_int(mask)
    if m is None:
        return None
    inv = (~m) & V4_MAX
    if inv & (inv + 1):
        return None  # not contiguous
    return 32 - inv.bit_length()


def v4_subnet(tokens: Sequence[str]) -> Optional[Tuple[int, int, int]]:
    """Parse FortiOS subnet notation (``a.b.c.d m.m.m.m`` or ``a.b.c.d/len``).
    Returns (network_int, broadcast_int, prefix) or None.
    For interface IPs the host bits are cleared."""
    if not tokens:
        return None
    t0 = tokens[0]
    if "/" in t0:
        ip, _, plen = t0.partition("/")
        if "." in plen:
            prefix = mask_to_prefix(plen)
        else:
            try:
                prefix = int(plen)
            except ValueError:
                return None
    else:
        ip = t0
        if len(tokens) < 2:
            prefix = 32
        else:
            prefix = mask_to_prefix(tokens[1])
    if prefix is None or not 0 <= prefix <= 32:
        return None
    a = v4_int(ip)
    if a is None:
        return None
    hostmask = (1 << (32 - prefix)) - 1
    net = a & ~hostmask & V4_MAX
    return net, net | hostmask, prefix


def v6_prefix(token: str) -> Optional[Tuple[int, int, int]]:
    ip, _, plen = token.partition("/")
    try:
        prefix = int(plen) if plen else 128
    except ValueError:
        return None
    if not 0 <= prefix <= 128:
        return None
    a = v6_int(ip)
    if a is None:
        return None
    hostmask = (1 << (128 - prefix)) - 1
    net = a & ~hostmask & V6_MAX
    return net, net | hostmask, prefix


def fmt_v4(i: int) -> str:
    return str(ipaddress.IPv4Address(i))


def fmt_v6(i: int) -> str:
    return str(ipaddress.IPv6Address(i))


def fmt_range(lo: int, hi: int, v6: bool = False) -> str:
    """Format a range as CIDR when it is one, else as ``a-b``."""
    bits = 128 if v6 else 32
    f = fmt_v6 if v6 else fmt_v4
    size = hi - lo + 1
    if size & (size - 1) == 0 and lo % size == 0:
        plen = bits - (size.bit_length() - 1)
        if plen == bits:
            return f(lo)
        return f"{f(lo)}/{plen}"
    return f"{f(lo)}-{f(hi)}"


def fmt_set(s: IntervalSet, v6: bool = False, limit: int = 4) -> str:
    parts = [fmt_range(lo, hi, v6) for lo, hi in s.r[:limit]]
    if len(s.r) > limit:
        parts.append(f"(+{len(s.r) - limit})")
    return ", ".join(parts)
