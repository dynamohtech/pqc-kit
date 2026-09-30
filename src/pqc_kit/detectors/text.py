"""Helpers for the regex-based source scanners (Java, Go, JavaScript/TypeScript)."""

from __future__ import annotations

import bisect
import re


def strip_comments(src: str, *, backtick_strings: bool = False, raw_backticks: bool = False) -> str:
    """Blank out // and /* */ comments, keeping strings, offsets and line numbers intact.

    backtick_strings: treat `...` as a string (JavaScript template literals, Go raw strings).
    """
    out = list(src)
    i, n = 0, len(src)
    quote = None
    while i < n:
        c = src[i]
        if quote:
            if c == "\\" and not (quote == "`" and raw_backticks):
                i += 2
                continue
            if c == quote:
                quote = None
            elif c == "\n" and quote != "`":
                quote = None  # unterminated string: stop at the end of the line
            i += 1
            continue
        if c in "\"'" or (c == "`" and backtick_strings):
            quote = c
            i += 1
            continue
        if c == "/" and i + 1 < n:
            nxt = src[i + 1]
            if nxt == "/":
                j = src.find("\n", i)
                j = n if j == -1 else j
                for k in range(i, j):
                    out[k] = " "
                i = j
                continue
            if nxt == "*":
                j = src.find("*/", i + 2)
                j = n if j == -1 else j + 2
                for k in range(i, j):
                    if out[k] != "\n":
                        out[k] = " "
                i = j
                continue
        i += 1
    return "".join(out)


class Lines:
    """Map string offsets to 1-based (line, column)."""

    def __init__(self, text: str):
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def at(self, offset: int) -> tuple[int, int]:
        idx = bisect.bisect_right(self.starts, offset) - 1
        return idx + 1, offset - self.starts[idx] + 1


def call_args(text: str, open_paren: int, limit: int = 2000) -> list[str] | None:
    """Split the arguments of a call whose '(' is at open_paren. Returns None if unbalanced."""
    if open_paren >= len(text) or text[open_paren] != "(":
        return None
    depth = 0
    args: list[str] = []
    start = open_paren + 1
    quote = None
    i = open_paren
    end = min(len(text), open_paren + limit)
    while i < end:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                last = text[start:i].strip()
                if last or args:
                    args.append(last)
                return args
        elif c == "," and depth == 1:
            args.append(text[start:i].strip())
            start = i + 1
        i += 1
    return None


_STR = re.compile(r"""^(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`([^`$]*)`)$""", re.S)


def string_literal(expr: str | None) -> str | None:
    if not expr:
        return None
    m = _STR.match(expr.strip())
    if not m:
        return None
    return next(g for g in m.groups() if g is not None)


def int_literal(expr: str | None, consts: dict[str, int] | None = None) -> int | None:
    if not expr:
        return None
    e = expr.strip()
    number = e.rstrip("Ll").replace("_", "")
    if re.fullmatch(r"\d{2,6}", number):
        return int(number)
    if consts and re.fullmatch(r"[A-Za-z_]\w*", e):
        return consts.get(e)
    return None


def object_block(text: str, pos: int, limit: int = 600) -> str:
    """The text of the innermost {...} literal around pos (best effort)."""
    start = text.rfind("{", max(0, pos - limit), pos)
    if start == -1:
        return ""
    depth = 0
    for i in range(start, min(len(text), start + limit * 2)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return text[start : start + limit]


def is_test_path(path: str) -> bool:
    low = path.lower()
    parts = low.split("/")
    name = parts[-1]
    dirs = set(parts[:-1])
    if dirs & {"test", "tests", "testing", "__tests__", "spec", "specs", "testdata", "fixtures", "test-fixtures",
               "e2e", "__mocks__", "mocks", "examples-test"}:
        return True
    if re.search(r"(^test_.*\.py$|_test\.py$|^conftest\.py$|_test\.go$|\.(test|spec)\.[cm]?[jt]sx?$)", name):
        return True
    if re.search(r"[a-z0-9](Test|Tests|IT)\.(java|kt)$|^Test\w*\.(java|kt)$", path.split("/")[-1]):
        return True
    return "src/test/" in low
