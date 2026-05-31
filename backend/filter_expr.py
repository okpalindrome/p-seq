"""Tiny Wireshark-ish display-filter evaluator.

Supports field == value, !=, >, <, >=, <=, contains; combine with and/&&, or/||, not/!,
and parentheses. Fields supported (mapped to packet row dict):

  ip.src, ip.dst, ip.addr
  eth.src, eth.dst, eth.addr
  tcp.port, udp.port, tcp.srcport, tcp.dstport, udp.srcport, udp.dstport
  port            (any src/dst port)
  proto           ("TCP", "UDP", "ICMP", ...)
  frame.len       (int)
  payload         (hex string — used with contains)
  tcp, udp, icmp  (bare protocol tokens)
"""
from __future__ import annotations

import re
from typing import Any, Callable


_TOKEN_RE = re.compile(
    r"""
    \s*(
        (?P<op>==|!=|>=|<=|>|<|&&|\|\||contains)
      | (?P<paren>[()])
      | (?P<not>!)
      | (?P<str>"[^"]*"|'[^']*')
      | (?P<num>\d[\w\.\-:]*)
      | (?P<ident>[A-Za-z_][\w\.\-:]*)
    )
    """,
    re.VERBOSE,
)


def tokenize(expr: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            if expr[pos].isspace():
                pos += 1
                continue
            raise ValueError(f"unexpected char at {pos}: {expr[pos]!r}")
        pos = m.end()
        if m.group("op"):
            tokens.append(("op", m.group("op")))
        elif m.group("paren"):
            tokens.append(("paren", m.group("paren")))
        elif m.group("not"):
            tokens.append(("not", "!"))
        elif m.group("str"):
            tokens.append(("str", m.group("str")[1:-1]))
        elif m.group("num"):
            tokens.append(("num", m.group("num")))
        elif m.group("ident"):
            ident = m.group("ident")
            low = ident.lower()
            if low in ("and",):
                tokens.append(("op", "&&"))
            elif low in ("or",):
                tokens.append(("op", "||"))
            elif low == "not":
                tokens.append(("not", "!"))
            else:
                tokens.append(("ident", ident))
    return tokens


# ---------- Pratt-ish recursive descent ----------
# Grammar:
#   expr   := or
#   or     := and ('||' and)*
#   and    := unary ('&&' unary)*
#   unary  := '!' unary | atom
#   atom   := '(' expr ')' | comparison | bare_ident
#   comparison := ident op (str|num|ident)
#   bare_ident := ident   (treated as proto == ident e.g. "tcp")

class _Parser:
    def __init__(self, tokens: list[tuple[str, str]]):
        self.tokens = tokens
        self.i = 0

    def peek(self) -> tuple[str, str] | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def eat(self) -> tuple[str, str]:
        t = self.tokens[self.i]
        self.i += 1
        return t

    def parse(self) -> Callable[[dict], bool]:
        node = self.parse_or()
        if self.i != len(self.tokens):
            raise ValueError(f"unexpected token {self.tokens[self.i]}")
        return node

    def parse_or(self) -> Callable[[dict], bool]:
        left = self.parse_and()
        while (t := self.peek()) and t == ("op", "||"):
            self.eat()
            right = self.parse_and()
            l, r = left, right
            left = lambda row, l=l, r=r: l(row) or r(row)
        return left

    def parse_and(self) -> Callable[[dict], bool]:
        left = self.parse_unary()
        while (t := self.peek()) and t == ("op", "&&"):
            self.eat()
            right = self.parse_unary()
            l, r = left, right
            left = lambda row, l=l, r=r: l(row) and r(row)
        return left

    def parse_unary(self) -> Callable[[dict], bool]:
        t = self.peek()
        if t and t[0] == "not":
            self.eat()
            inner = self.parse_unary()
            return lambda row, inner=inner: not inner(row)
        return self.parse_atom()

    def parse_atom(self) -> Callable[[dict], bool]:
        t = self.peek()
        if t is None:
            raise ValueError("unexpected end of expression")
        if t == ("paren", "("):
            self.eat()
            inner = self.parse_or()
            close = self.eat()
            if close != ("paren", ")"):
                raise ValueError("expected )")
            return inner
        if t[0] == "ident":
            # could be bare ident (proto) or ident op value
            ident = self.eat()[1]
            nxt = self.peek()
            if nxt and nxt[0] == "op" and nxt[1] in ("==", "!=", ">", "<", ">=", "<=", "contains"):
                op = self.eat()[1]
                rhs_t = self.eat()
                if rhs_t[0] not in ("ident", "str", "num"):
                    raise ValueError(f"expected value after {op}")
                rhs = rhs_t[1]
                return _make_cmp(ident, op, rhs)
            # bare protocol token => proto match
            return _make_bare(ident)
        raise ValueError(f"unexpected token {t}")


# ---------- predicates ----------

def _get_field(row: dict[str, Any], field: str) -> Any:
    f = field.lower()
    if f in ("ip.src",):
        return row.get("src_ip")
    if f in ("ip.dst",):
        return row.get("dst_ip")
    if f in ("ip.addr", "ip.host"):
        return [row.get("src_ip"), row.get("dst_ip")]
    if f in ("eth.src",):
        return row.get("src_mac")
    if f in ("eth.dst",):
        return row.get("dst_mac")
    if f in ("eth.addr",):
        return [row.get("src_mac"), row.get("dst_mac")]
    if f in ("tcp.srcport", "udp.srcport"):
        return row.get("src_port") if row.get("proto", "").startswith(f.split(".")[0].upper()) else None
    if f in ("tcp.dstport", "udp.dstport"):
        return row.get("dst_port") if row.get("proto", "").startswith(f.split(".")[0].upper()) else None
    if f in ("tcp.port",):
        return [row.get("src_port"), row.get("dst_port")] if row.get("proto") == "TCP" else [None, None]
    if f in ("udp.port",):
        return [row.get("src_port"), row.get("dst_port")] if row.get("proto") == "UDP" else [None, None]
    if f == "port":
        return [row.get("src_port"), row.get("dst_port")]
    if f == "proto":
        return row.get("proto")
    if f in ("frame.len", "length"):
        return row.get("length")
    if f == "payload":
        return row.get("payload_hex", "")
    if f == "info":
        return row.get("info", "")
    if f == "frame":
        return row.get("frame")
    return None


def _cmp(lhs: Any, op: str, rhs: str) -> bool:
    if lhs is None:
        return False
    if isinstance(lhs, list):
        return any(_cmp(x, op, rhs) for x in lhs)
    if op == "contains":
        return str(rhs).lower() in str(lhs).lower()
    # numeric compare if both numeric
    if op in (">", "<", ">=", "<="):
        try:
            l = float(lhs)
            r = float(rhs)
        except (TypeError, ValueError):
            return False
        return {
            ">": l > r, "<": l < r, ">=": l >= r, "<=": l <= r,
        }[op]
    if op == "==":
        try:
            if isinstance(lhs, (int, float)):
                return float(lhs) == float(rhs)
        except (TypeError, ValueError):
            pass
        return str(lhs).lower() == str(rhs).lower()
    if op == "!=":
        try:
            if isinstance(lhs, (int, float)):
                return float(lhs) != float(rhs)
        except (TypeError, ValueError):
            pass
        return str(lhs).lower() != str(rhs).lower()
    return False


def _make_cmp(field: str, op: str, rhs: str) -> Callable[[dict], bool]:
    return lambda row: _cmp(_get_field(row, field), op, rhs)


def _make_bare(ident: str) -> Callable[[dict], bool]:
    """Bare token like `tcp` matches packets whose proto starts with TCP."""
    name = ident.upper()
    return lambda row: (row.get("proto") or "").upper().startswith(name) or name in (row.get("encap") or "").upper()


def compile_filter(expr: str) -> Callable[[dict], bool]:
    """Compile a display-filter expression to a predicate. Empty => match all."""
    expr = (expr or "").strip()
    if not expr:
        return lambda row: True
    tokens = tokenize(expr)
    if not tokens:
        return lambda row: True
    return _Parser(tokens).parse()
