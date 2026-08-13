#!/usr/bin/env python3
"""Reference RFC 8941 Structured Field Values parser and canonical serializer.

This is the ONE decision surface for the sfv_v0 conformance corpus: it decides,
for a given field type (item, list or dictionary) and a raw field value, whether
the value parses, and if so what its canonical serialization is (RFC 8941
Section 4.1). tools/gen_sfv_v0.py stamps every expected verdict from here; the
runners re-derive independently in twelve languages; tools/check_kat_sfv.py
re-checks every verdict with a separate third-party implementation (http_sfv),
so a corpus that merely agrees with this parser cannot pass.

Scope: the RFC 8941 core that RFC 9651 keeps byte-identical (Integer, Decimal,
String, Token, Byte Sequence, Boolean, Inner List, Parameters, List,
Dictionary). The RFC 9651 additions (Date, Display String) are deliberately out
of sfv_v0 so the corpus is version-neutral; they are a later sfv_v1 section.

No dependencies beyond the standard library. Pure functions, no I/O.
"""
from __future__ import annotations

import base64
import binascii
from decimal import Decimal, ROUND_HALF_EVEN, InvalidOperation

DIGITS = set("0123456789")
LCALPHA = set("abcdefghijklmnopqrstuvwxyz")
ALPHA = LCALPHA | set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
# tchar per RFC 7230, the Token continuation set, plus ":" and "/" (RFC 8941 4.2.6).
TOKEN_TAIL = ALPHA | DIGITS | set("!#$%&'*+-.^_`|~:/")
KEY_TAIL = LCALPHA | DIGITS | set("_-.*")
B64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

INT_MIN = -999_999_999_999_999
INT_MAX = 999_999_999_999_999


class SFVError(ValueError):
    """A structured field value that must be rejected."""


# ---------------------------------------------------------------------------
# Parsing (RFC 8941 Section 4.2)
# ---------------------------------------------------------------------------

class _Parser:
    def __init__(self, text: str):
        # A field value is ASCII; a non-ASCII byte can never appear in a
        # structured field, so reject it up front rather than mis-parsing.
        if any(ord(c) > 0x7F for c in text):
            raise SFVError("non-ASCII in field value")
        self.s = text
        self.i = 0

    # -- primitives ------------------------------------------------------
    def _eof(self) -> bool:
        return self.i >= len(self.s)

    def _peek(self):
        return None if self._eof() else self.s[self.i]

    def _discard_sp(self):
        while not self._eof() and self.s[self.i] == " ":
            self.i += 1

    def _discard_ows(self):
        while not self._eof() and self.s[self.i] in " \t":
            self.i += 1

    # -- bare item (4.2.3.1) --------------------------------------------
    def bare_item(self):
        c = self._peek()
        if c is None:
            raise SFVError("empty bare item")
        if c == "-" or c in DIGITS:
            return self._number()
        if c == '"':
            return ("string", self._string())
        if c == ":":
            return ("bytes", self._byteseq())
        if c == "?":
            return ("boolean", self._boolean())
        if c == "*" or c in ALPHA:
            return ("token", self._token())
        raise SFVError(f"unexpected char {c!r} starting a bare item")

    def _number(self):
        typ = "integer"
        sign = 1
        num = ""
        if self._peek() == "-":
            self.i += 1
            sign = -1
        if self._eof() or self._peek() not in DIGITS:
            raise SFVError("number with no digits")
        while not self._eof():
            c = self.s[self.i]
            if c in DIGITS:
                num += c
                self.i += 1
            elif typ == "integer" and c == ".":
                if len(num) > 12:
                    raise SFVError("too many integer digits before decimal point")
                num += "."
                typ = "decimal"
                self.i += 1
            else:
                break
            if typ == "integer" and len(num) > 15:
                raise SFVError("integer too long")
            if typ == "decimal" and len(num) > 16:
                raise SFVError("decimal too long")
        if typ == "integer":
            val = sign * int(num)
            if val < INT_MIN or val > INT_MAX:
                raise SFVError("integer out of range")
            return ("integer", val)
        if num.endswith("."):
            raise SFVError("decimal ends with a dot")
        if len(num) - num.index(".") - 1 > 3:
            raise SFVError("too many fractional digits")
        try:
            return ("decimal", Decimal(num) * sign)
        except InvalidOperation:
            raise SFVError("bad decimal")

    def _string(self):
        assert self.s[self.i] == '"'
        self.i += 1
        out = []
        while not self._eof():
            c = self.s[self.i]
            self.i += 1
            if c == "\\":
                if self._eof():
                    raise SFVError("trailing backslash in string")
                nxt = self.s[self.i]
                self.i += 1
                if nxt not in ('"', "\\"):
                    raise SFVError("bad string escape")
                out.append(nxt)
            elif c == '"':
                return "".join(out)
            elif ord(c) < 0x20 or ord(c) > 0x7E:
                raise SFVError("control or non-printable char in string")
            else:
                out.append(c)
        raise SFVError("unterminated string")

    def _token(self):
        start = self.i
        # first char already validated as ALPHA or "*"
        self.i += 1
        while not self._eof() and self.s[self.i] in TOKEN_TAIL:
            self.i += 1
        return self.s[start:self.i]

    def _byteseq(self):
        assert self.s[self.i] == ":"
        self.i += 1
        start = self.i
        while not self._eof() and self.s[self.i] != ":":
            if self.s[self.i] not in B64_ALPHABET:
                raise SFVError("non-base64 char in byte sequence")
            self.i += 1
        if self._eof():
            raise SFVError("unterminated byte sequence")
        content = self.s[start:self.i]
        self.i += 1  # closing ":"
        try:
            return base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError):
            raise SFVError("invalid base64 in byte sequence")

    def _boolean(self):
        assert self.s[self.i] == "?"
        self.i += 1
        c = self._peek()
        if c == "1":
            self.i += 1
            return True
        if c == "0":
            self.i += 1
            return False
        raise SFVError("boolean must be ?0 or ?1")

    # -- keys and parameters (4.2.3.2 / 4.2.3.3) ------------------------
    def _key(self):
        c = self._peek()
        if c is None or (c not in LCALPHA and c != "*"):
            raise SFVError("key must start with lcalpha or *")
        start = self.i
        self.i += 1
        while not self._eof() and self.s[self.i] in KEY_TAIL:
            self.i += 1
        return self.s[start:self.i]

    def parameters(self):
        params: list[tuple[str, tuple]] = []
        seen: dict[str, int] = {}
        while self._peek() == ";":
            self.i += 1
            self._discard_sp()
            key = self._key()
            if self._peek() == "=":
                self.i += 1
                value = self.bare_item()
            else:
                value = ("boolean", True)
            if key in seen:
                # RFC 8941 4.2.3.2: a duplicate parameter key overwrites the
                # value in place, RETAINING the key's original position (an
                # ordered map update, not a move-to-end).
                params[seen[key]] = (key, value)
            else:
                seen[key] = len(params)
                params.append((key, value))
        return params

    # -- items and inner lists (4.2.3 / 4.2.1.2) ------------------------
    def item(self):
        bare = self.bare_item()
        params = self.parameters()
        return ("item", bare, params)

    def inner_list(self):
        assert self.s[self.i] == "("
        self.i += 1
        members = []
        while True:
            self._discard_sp()
            if self._peek() == ")":
                self.i += 1
                params = self.parameters()
                return ("inner_list", members, params)
            if self._eof():
                raise SFVError("unterminated inner list")
            bare = self.bare_item()
            params = self.parameters()
            members.append((bare, params))
            if self._peek() not in (" ", ")"):
                raise SFVError("inner-list items must be space separated")

    def item_or_inner_list(self):
        if self._peek() == "(":
            return self.inner_list()
        return self.item()

    # -- top-level structures (4.2.1 / 4.2.2) ---------------------------
    def parse_list(self):
        members = []
        self._discard_sp()
        if self._eof():
            return members
        while True:
            members.append(self.item_or_inner_list())
            self._discard_ows()
            if self._eof():
                return members
            if self._peek() != ",":
                raise SFVError("list members must be comma separated")
            self.i += 1
            self._discard_ows()
            if self._eof():
                raise SFVError("trailing comma in list")

    def parse_dictionary(self):
        members: list[tuple[str, tuple]] = []
        seen: dict[str, int] = {}
        self._discard_sp()
        if self._eof():
            return members
        while True:
            key = self._key()
            if self._peek() == "=":
                self.i += 1
                value = self.item_or_inner_list()
            else:
                params = self.parameters()
                value = ("item", ("boolean", True), params)
            if key in seen:
                # RFC 8941 4.2.2: a duplicate dictionary key overwrites the
                # value in place, RETAINING the key's original position (an
                # ordered map update, not a move-to-end).
                members[seen[key]] = (key, value)
            else:
                seen[key] = len(members)
                members.append((key, value))
            self._discard_ows()
            if self._eof():
                return members
            if self._peek() != ",":
                raise SFVError("dictionary members must be comma separated")
            self.i += 1
            self._discard_ows()
            if self._eof():
                raise SFVError("trailing comma in dictionary")


def parse(field_type: str, text: str):
    """Parse a whole field value; raise SFVError on any trailing garbage."""
    p = _Parser(text)
    if field_type == "item":
        p._discard_sp()
        value = p.item()
    elif field_type == "list":
        value = p.parse_list()
    elif field_type == "dictionary":
        value = p.parse_dictionary()
    else:
        raise ValueError(f"unknown field type {field_type!r}")
    p._discard_sp()
    if not p._eof():
        raise SFVError("trailing characters after value")
    return value


# ---------------------------------------------------------------------------
# Canonical serialization (RFC 8941 Section 4.1)
# ---------------------------------------------------------------------------

def _ser_bare(bare) -> str:
    kind, val = bare
    if kind == "integer":
        if val < INT_MIN or val > INT_MAX:
            raise SFVError("integer out of range")
        return str(val)
    if kind == "decimal":
        return _ser_decimal(val)
    if kind == "string":
        out = ['"']
        for c in val:
            if ord(c) < 0x20 or ord(c) > 0x7E:
                raise SFVError("control char in string")
            if c in ('"', "\\"):
                out.append("\\")
            out.append(c)
        out.append('"')
        return "".join(out)
    if kind == "token":
        return val
    if kind == "bytes":
        return ":" + base64.b64encode(val).decode("ascii") + ":"
    if kind == "boolean":
        return "?1" if val else "?0"
    raise SFVError(f"unknown bare item kind {kind!r}")


def _ser_decimal(d: Decimal) -> str:
    q = d.quantize(Decimal("0.001"), rounding=ROUND_HALF_EVEN)
    neg = q < 0
    q = abs(q)
    whole = int(q)
    if whole >= 10 ** 12:
        raise SFVError("decimal integer part too large")
    txt = f"{q:.3f}"
    intpart, frac = txt.split(".")
    frac = frac.rstrip("0") or "0"
    intpart = str(int(intpart))
    return f"{'-' if neg else ''}{intpart}.{frac}"


def _ser_params(params) -> str:
    out = []
    for key, value in params:
        if value == ("boolean", True):
            out.append(";" + key)
        else:
            out.append(";" + key + "=" + _ser_bare(value))
    return "".join(out)


def _ser_inner_list(node) -> str:
    _, members, params = node
    inner = " ".join(_ser_bare(bare) + _ser_params(ps) for bare, ps in members)
    return "(" + inner + ")" + _ser_params(params)


def _ser_member(node) -> str:
    if node[0] == "inner_list":
        return _ser_inner_list(node)
    _, bare, params = node
    return _ser_bare(bare) + _ser_params(params)


def serialize(field_type: str, value) -> str:
    if field_type == "item":
        return _ser_member(value)
    if field_type == "list":
        return ", ".join(_ser_member(m) for m in value)
    if field_type == "dictionary":
        out = []
        for key, member in value:
            if member[0] == "item" and member[1] == ("boolean", True):
                out.append(key + _ser_params(member[2]))
            else:
                out.append(key + "=" + _ser_member(member))
        return ", ".join(out)
    raise ValueError(f"unknown field type {field_type!r}")


# ---------------------------------------------------------------------------
# The verdict surface used by the generator
# ---------------------------------------------------------------------------

def verdict(field_type: str, text: str):
    """Return (parse_ok, canonical_or_None) for one field value."""
    try:
        value = parse(field_type, text)
    except SFVError:
        return False, None
    try:
        return True, serialize(field_type, value)
    except SFVError:
        # A value that parses but cannot be canonically serialized is a reject.
        return False, None
