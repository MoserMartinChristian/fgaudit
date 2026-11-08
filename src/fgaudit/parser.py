"""Reusable parser for FortiOS configuration files (``show full-configuration`` /
backup format).

The parser is deliberately independent from the audit checks. It turns the text
into a tree of :class:`Config` (a ``config ...`` block) and :class:`Entry` (an
``edit ...`` block) objects and never raises on malformed input: problems are
collected in :attr:`ParseResult.warnings` together with a line number. It never
copies raw line content into warnings, so secrets cannot leak through them.

Supported syntax:

* nested ``config`` / ``edit`` / ``set`` / ``unset`` / ``append`` / ``select`` /
  ``next`` / ``end`` blocks of arbitrary depth
* double- and single-quoted values with backslash escapes (``\\"``, ``\\\\``)
* values spanning several lines (certificates, private keys, scripts)
* CRLF / CR line endings, a UTF-8 byte order mark, tabs
* ``#`` header and comment lines, unknown sections (kept generically)
* ``end`` without a preceding ``next`` (used in VDOM sections of real backups)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

__all__ = [
    "Config",
    "Entry",
    "ParseResult",
    "ParseWarning",
    "decode_bytes",
    "parse",
    "parse_bytes",
    "tokenize",
]


@dataclass
class ParseWarning:
    line: int
    code: str  # stable machine-readable code, e.g. "unbalanced-end"
    detail: str = ""  # never contains raw file content

    def __str__(self) -> str:  # pragma: no cover - convenience
        return f"line {self.line}: {self.code}{(' ' + self.detail) if self.detail else ''}"


@dataclass
class Entry:
    """An ``edit <key>`` block inside a table."""

    key: str
    line: int = 0
    settings: Dict[str, List[str]] = field(default_factory=dict)
    unset: List[str] = field(default_factory=list)
    children: Dict[str, "Config"] = field(default_factory=dict)

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        vals = self.settings.get(name)
        if not vals:
            return default
        return vals[0]

    def get_list(self, name: str) -> List[str]:
        return list(self.settings.get(name, []))

    def child(self, path: str) -> Optional["Config"]:
        return self.children.get(path)


@dataclass
class Config:
    """A ``config <path>`` block. It can hold direct settings (singleton
    sections such as ``config system global``), table entries (``edit``), and
    nested ``config`` blocks."""

    path: str
    line: int = 0
    settings: Dict[str, List[str]] = field(default_factory=dict)
    unset: List[str] = field(default_factory=list)
    entries: Dict[str, Entry] = field(default_factory=dict)
    children: Dict[str, "Config"] = field(default_factory=dict)

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        vals = self.settings.get(name)
        if not vals:
            return default
        return vals[0]

    def get_list(self, name: str) -> List[str]:
        return list(self.settings.get(name, []))

    def child(self, path: str) -> Optional["Config"]:
        return self.children.get(path)

    def __iter__(self) -> Iterator[Entry]:
        return iter(self.entries.values())

    def __len__(self) -> int:
        return len(self.entries)


@dataclass
class ParseResult:
    root: Config
    header: List[str]
    warnings: List[ParseWarning]
    statements: int
    secret_values: List[str]

    @property
    def ok(self) -> bool:
        return self.statements > 0


# --------------------------------------------------------------------------- #
# decoding


def decode_bytes(data: bytes) -> str:
    """Decode file bytes to text. Strips a UTF-8 BOM, tolerates invalid
    sequences (latin-1 fallback) and normalises line endings to ``\\n``."""
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    elif data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        try:
            text = data.decode("utf-16")
        except UnicodeDecodeError:
            text = data.decode("latin-1")
        return text.replace("\r\n", "\n").replace("\r", "\n")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    return text.replace("\r\n", "\n").replace("\r", "\n")


# --------------------------------------------------------------------------- #
# tokenizer

Statement = Tuple[int, List[str], List[bool]]  # (line, tokens, quoted-flags)


def tokenize(text: str, warnings: Optional[List[ParseWarning]] = None) -> Iterator[Statement]:
    """Yield statements as ``(line_number, tokens, quoted_flags)``.

    A statement ends at a newline that is not inside quotes. ``#`` starts a
    comment only at the beginning of a statement.
    """
    if warnings is None:
        warnings = []
    i = 0
    n = len(text)
    line = 1
    tokens: List[str] = []
    quoted: List[bool] = []
    stmt_line = 1
    while i < n:
        c = text[i]
        if c == "\n":
            if tokens:
                yield stmt_line, tokens, quoted
                tokens, quoted = [], []
            line += 1
            i += 1
            continue
        if c in " \t\f\v\x00":
            i += 1
            continue
        if not tokens:
            stmt_line = line
            if c == "#":
                j = text.find("\n", i)
                if j < 0:
                    j = n
                yield stmt_line, ["#", text[i + 1 : j]], [False, False]
                i = j
                continue
        if c in "\"'":
            q = c
            start_line = line
            buf = []
            i += 1
            closed = False
            while i < n:
                ch = text[i]
                if ch == "\\" and i + 1 < n:
                    nxt = text[i + 1]
                    if nxt == "\n":
                        line += 1
                    buf.append(nxt)
                    i += 2
                    continue
                if ch == q:
                    closed = True
                    i += 1
                    break
                if ch == "\n":
                    line += 1
                buf.append(ch)
                i += 1
            if not closed:
                warnings.append(ParseWarning(start_line, "unterminated-quote"))
            tokens.append("".join(buf))
            quoted.append(True)
            continue
        # bare word
        buf = []
        while i < n:
            ch = text[i]
            if ch in " \t\n\f\v\x00":
                break
            if ch == "\\" and i + 1 < n and text[i + 1] != "\n":
                buf.append(text[i + 1])
                i += 2
                continue
            buf.append(ch)
            i += 1
        tokens.append("".join(buf))
        quoted.append(False)
    if tokens:
        yield stmt_line, tokens, quoted


# --------------------------------------------------------------------------- #
# parser

_SECRET_HINTS = ("pass", "secret", "psk", "pwd", "token", "ppk", "passphrase")


def is_secret_field(name: str) -> bool:
    """Heuristic used by the parser and the redaction layer."""
    n = name.lower()
    if any(h in n for h in _SECRET_HINTS):
        return True
    if n in ("key", "private-key", "authkey", "auth-key", "key-string", "md5-key", "server-key"):
        return True
    if n.endswith("-key") or n.startswith("key-") or n.endswith("_key"):
        return True
    return False


def _looks_secret_value(v: str) -> bool:
    return v.startswith("ENC ") or "PRIVATE KEY" in v or v.startswith("SH2") or v.startswith("AK1")


def parse(text: str, max_warnings: int = 500) -> ParseResult:
    """Parse configuration text into a tree. Never raises for bad input."""
    warnings: List[ParseWarning] = []
    root = Config(path="", line=0)
    # stack elements: Config or Entry
    stack: List[object] = [root]
    header: List[str] = []
    statements = 0
    secret_values: List[str] = []
    seen_config = False

    def warn(line: int, code: str, detail: str = "") -> None:
        if len(warnings) < max_warnings:
            warnings.append(ParseWarning(line, code, detail))

    for line, toks, quoted in tokenize(text, warnings):
        kw = toks[0]
        if kw == "#" and not quoted[0]:
            if not seen_config:
                header.append(toks[1].strip())
            continue
        kwl = kw.lower()
        top = stack[-1]
        if kwl == "config" and not quoted[0]:
            if len(toks) < 2:
                warn(line, "config-without-path")
                continue
            seen_config = True
            path = " ".join(toks[1:])
            container = top
            existing = container.children.get(path)  # type: ignore[union-attr]
            if existing is None:
                existing = Config(path=path, line=line)
                container.children[path] = existing  # type: ignore[union-attr]
            stack.append(existing)
            statements += 1
        elif kwl == "edit" and not quoted[0]:
            if len(toks) < 2:
                warn(line, "edit-without-key")
                continue
            if isinstance(top, Entry):
                # missing "next" - close the previous entry implicitly
                warn(line, "missing-next")
                stack.pop()
                top = stack[-1]
            if not isinstance(top, Config) or top is root:
                warn(line, "edit-outside-config")
                continue
            key = toks[1]
            ent = top.entries.get(key)
            if ent is None:
                ent = Entry(key=key, line=line)
                top.entries[key] = ent
            stack.append(ent)
            statements += 1
        elif kwl in ("set", "append", "select", "unselect") and not quoted[0]:
            if top is root:
                warn(line, "set-outside-config")
                continue
            if len(toks) < 2:
                warn(line, "set-without-name")
                continue
            name = toks[1]
            values = toks[2:]
            if is_secret_field(name) or any(_looks_secret_value(v) for v in values):
                secret_values.extend(v for v in values if len(v) >= 4)
            target = top.settings  # type: ignore[union-attr]
            if kwl == "set":
                target[name] = values
            elif kwl in ("append", "select"):
                target.setdefault(name, [])
                target[name].extend(values)
            else:  # unselect
                cur = target.get(name, [])
                target[name] = [v for v in cur if v not in values]
            statements += 1
        elif kwl == "unset" and not quoted[0]:
            if top is root:
                warn(line, "unset-outside-config")
                continue
            if len(toks) >= 2:
                top.settings.pop(toks[1], None)  # type: ignore[union-attr]
                top.unset.append(toks[1])  # type: ignore[union-attr]
            statements += 1
        elif kwl == "next" and not quoted[0]:
            if isinstance(top, Entry):
                stack.pop()
            else:
                warn(line, "next-without-edit")
            statements += 1
        elif kwl == "end" and not quoted[0]:
            if isinstance(top, Entry):
                # "end" directly after an entry (real VDOM sections do this)
                stack.pop()
                top = stack[-1]
            if top is root:
                warn(line, "unbalanced-end")
                continue
            stack.pop()
            statements += 1
        else:
            warn(line, "unknown-statement")
    if len(stack) > 1:
        warn(0, "unclosed-blocks", str(len(stack) - 1))
    return ParseResult(
        root=root,
        header=header,
        warnings=warnings,
        statements=statements,
        secret_values=secret_values,
    )


def parse_bytes(data: bytes) -> ParseResult:
    return parse(decode_bytes(data))
