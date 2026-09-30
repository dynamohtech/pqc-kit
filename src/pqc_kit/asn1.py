"""A small, strict DER reader: just enough to read certificates and keys.

It never executes anything and bounds every loop by the input length, so a
malformed or hostile file raises DERError instead of hanging or crashing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

UNIVERSAL, APPLICATION, CONTEXT, PRIVATE = 0, 1, 2, 3

BOOLEAN, INTEGER, BIT_STRING, OCTET_STRING, NULL, OID = 1, 2, 3, 4, 5, 6
UTF8_STRING, SEQUENCE, SET = 12, 16, 17
PRINTABLE_STRING, T61_STRING, IA5_STRING, UTC_TIME, GENERALIZED_TIME = 19, 20, 22, 23, 24
VISIBLE_STRING, UNIVERSAL_STRING, BMP_STRING = 26, 28, 30

MAX_CHILDREN = 10_000


class DERError(ValueError):
    """The bytes are not the DER structure we expected."""


@dataclass(frozen=True)
class TLV:
    cls: int
    constructed: bool
    tag: int
    value: bytes
    raw: bytes  # the full encoding, header included

    def is_(self, tag: int, cls: int = UNIVERSAL) -> bool:
        return self.tag == tag and self.cls == cls

    def children(self) -> list["TLV"]:
        if not self.constructed:
            raise DERError("not a constructed value")
        return parse_all(self.value)


def read(data: bytes, pos: int = 0) -> tuple[TLV, int]:
    """Read one TLV at pos; return it and the position after it."""
    n = len(data)
    if pos >= n:
        raise DERError("unexpected end of data")
    start = pos
    first = data[pos]
    pos += 1
    cls, constructed, tag = first >> 6, bool(first & 0x20), first & 0x1F
    if tag == 0x1F:  # high tag number form
        tag = 0
        for _ in range(4):
            if pos >= n:
                raise DERError("truncated tag")
            b = data[pos]
            pos += 1
            tag = (tag << 7) | (b & 0x7F)
            if not b & 0x80:
                break
        else:
            raise DERError("tag number too large")
    if pos >= n:
        raise DERError("truncated length")
    length = data[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0:
            raise DERError("indefinite length is not DER")
        if count > 4 or pos + count > n:
            raise DERError("bad length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    end = pos + length
    if end > n:
        raise DERError("value runs past the end of the data")
    return TLV(cls, constructed, tag, bytes(data[pos:end]), bytes(data[start:end])), end


def parse(data: bytes) -> TLV:
    """Parse exactly one TLV (trailing bytes are allowed and ignored)."""
    tlv, _ = read(data, 0)
    return tlv


def parse_all(data: bytes) -> list[TLV]:
    out: list[TLV] = []
    pos = 0
    while pos < len(data):
        tlv, pos = read(data, pos)
        out.append(tlv)
        if len(out) > MAX_CHILDREN:
            raise DERError("too many elements")
    return out


def expect(tlv: TLV, tag: int, cls: int = UNIVERSAL) -> TLV:
    if not tlv.is_(tag, cls):
        raise DERError(f"expected tag {tag} class {cls}, got tag {tlv.tag} class {tlv.cls}")
    return tlv


def seq(tlv: TLV) -> list[TLV]:
    return expect(tlv, SEQUENCE).children()


def oid(tlv: TLV) -> str:
    expect(tlv, OID)
    return decode_oid(tlv.value)


def decode_oid(value: bytes) -> str:
    if not value or len(value) > 128:
        raise DERError("bad OID")
    arcs: list[int] = []
    acc = 0
    for i, b in enumerate(value):
        acc = (acc << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(acc)
            acc = 0
        elif i == len(value) - 1:
            raise DERError("truncated OID")
    first = arcs[0]
    head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
    return ".".join(str(a) for a in head + arcs[1:])


def integer(tlv: TLV) -> int:
    expect(tlv, INTEGER)
    return int.from_bytes(tlv.value, "big", signed=True)


def unsigned_bits(value: bytes) -> int:
    """Bit length of a positive INTEGER's magnitude (e.g. an RSA modulus)."""
    return int.from_bytes(value, "big").bit_length()


def bit_string(tlv: TLV) -> bytes:
    expect(tlv, BIT_STRING)
    if not tlv.value:
        raise DERError("empty BIT STRING")
    return tlv.value[1:]  # first byte is the count of unused bits


def octet_string(tlv: TLV) -> bytes:
    return expect(tlv, OCTET_STRING).value


def string(tlv: TLV) -> str:
    v = tlv.value
    if tlv.tag == BMP_STRING:
        return v.decode("utf-16-be", errors="replace")
    if tlv.tag == UNIVERSAL_STRING:
        return v.decode("utf-32-be", errors="replace")
    if tlv.tag in (UTF8_STRING, PRINTABLE_STRING, IA5_STRING, VISIBLE_STRING):
        return v.decode("utf-8", errors="replace")
    return v.decode("latin-1")


def time(tlv: TLV) -> datetime:
    text = tlv.value.decode("ascii", errors="replace").rstrip("Z")
    try:
        if tlv.tag == UTC_TIME:
            yy = int(text[:2])
            year = 1900 + yy if yy >= 50 else 2000 + yy
            dt = datetime.strptime(f"{year}{text[2:14]}", "%Y%m%d%H%M%S")
        elif tlv.tag == GENERALIZED_TIME:
            dt = datetime.strptime(text[:14], "%Y%m%d%H%M%S")
        else:
            raise DERError("not a time value")
    except ValueError as exc:
        raise DERError(f"bad time value {text!r}") from exc
    return dt.replace(tzinfo=timezone.utc)


def algorithm_identifier(tlv: TLV) -> tuple[str, TLV | None]:
    """AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }"""
    parts = seq(tlv)
    if not parts:
        raise DERError("empty AlgorithmIdentifier")
    params = parts[1] if len(parts) > 1 else None
    if params is not None and params.is_(NULL):
        params = None
    return oid(parts[0]), params
