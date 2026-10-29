"""Just enough SNMP: decode v1/v2c TRAPS, and a v2c GET for interface status.

Standard library only (BER by hand) - a collector should not need net-snmp or
pysnmp installed at a customer site. SNMPv3 (auth/priv) traps are NOT decoded
here; such a trap is reported as undecodable rather than silently lost.
"""
from __future__ import annotations

import random
import socket

# Well-known trap OIDs -> names, so rules can say "linkDown", not an OID.
TRAP_NAMES = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart", "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown", "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.2.1.33.2.0.1": "upsTrapOnBattery", "1.3.6.1.2.1.33.2.0.3": "upsTrapAlarmEntryAdded",
    "1.3.6.1.4.1.318.0.5": "upsOnBattery", "1.3.6.1.4.1.318.0.7": "lowBattery",  # APC
}
GENERIC_V1 = {0: "coldStart", 1: "warmStart", 2: "linkDown", 3: "linkUp", 4: "authenticationFailure"}
VAR_NAMES = {
    "1.3.6.1.2.1.2.2.1.1": "ifIndex", "1.3.6.1.2.1.2.2.1.2": "ifDescr",
    "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus", "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
    "1.3.6.1.2.1.31.1.1.1.1": "ifName", "1.3.6.1.2.1.31.1.1.1.18": "ifAlias",
}
SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"


class BerError(ValueError):
    pass


def _read(buf: bytes, i: int) -> tuple[int, bytes, int]:
    """(tag, value, next_index) for the TLV at i."""
    if i + 2 > len(buf):
        raise BerError("truncated")
    tag = buf[i]
    ln = buf[i + 1]
    i += 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or i + n > len(buf):
            raise BerError("bad length")
        ln = int.from_bytes(buf[i:i + n], "big")
        i += n
    if i + ln > len(buf):
        raise BerError("truncated value")
    return tag, buf[i:i + ln], i + ln


def _children(v: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i < len(v):
        t, val, i = _read(v, i)
        out.append((t, val))
    return out


def _oid(v: bytes) -> str:
    if not v:
        return ""
    parts = [v[0] // 40, v[0] % 40]
    n = 0
    for b in v[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


def _value(tag: int, v: bytes) -> str:
    if tag in (0x02, 0x41, 0x42, 0x43, 0x46):          # INTEGER, Counter, Gauge, Ticks
        return str(int.from_bytes(v, "big", signed=(tag == 0x02)))
    if tag == 0x06:
        oid = _oid(v)
        return TRAP_NAMES.get(oid, oid)
    if tag == 0x40 and len(v) == 4:                    # IpAddress
        return ".".join(map(str, v))
    if tag == 0x04:
        try:
            s = v.decode("utf-8")
            return s if s.isprintable() else v.hex(":")
        except UnicodeDecodeError:
            return v.hex(":")
    if tag in (0x05, 0x80, 0x81, 0x82):                # NULL / noSuch* / endOfMib
        return ""
    return v.hex()


def _varbinds(v: bytes) -> list[tuple[str, str]]:
    out = []
    for _t, vb in _children(v):
        kids = _children(vb)
        if len(kids) == 2 and kids[0][0] == 0x06:
            out.append((_oid(kids[0][1]), _value(*kids[1])))
    return out


def _name(oid: str) -> str:
    for base, name in VAR_NAMES.items():
        if oid == base or oid.startswith(base + "."):
            return name
    return oid


def decode_trap(data: bytes) -> dict:
    """{version, community, trap, varbinds:{name: value}} or raises BerError."""
    t, msg, _ = _read(data, 0)
    if t != 0x30:
        raise BerError("not an SNMP message")
    kids = _children(msg)
    if len(kids) < 3:
        raise BerError("short message")
    version = int.from_bytes(kids[0][1], "big")
    if version == 3:
        raise BerError("SNMPv3 traps are not decoded - use v2c on this device")
    community = kids[1][1].decode("utf-8", "replace")
    pdu_tag, pdu = kids[2]
    vb: dict[str, str] = {}
    if pdu_tag == 0xA4:                                 # SNMPv1 Trap-PDU
        f = _children(pdu)
        enterprise, generic, specific = _oid(f[0][1]), int.from_bytes(f[2][1], "big"), int.from_bytes(f[3][1], "big")
        trap = GENERIC_V1.get(generic) if generic != 6 else TRAP_NAMES.get(f"{enterprise}.0.{specific}", f"{enterprise}.{specific}")
        for oid, val in _varbinds(f[5][1]):
            vb[_name(oid)] = val
    elif pdu_tag in (0xA7, 0xA6):                       # SNMPv2-Trap / Inform
        f = _children(pdu)
        trap = "unknown"
        for oid, val in _varbinds(f[3][1]):
            if oid == SNMP_TRAP_OID:
                trap = val
            elif oid != "1.3.6.1.2.1.1.3.0":           # sysUpTime: not interesting
                vb[_name(oid)] = val
    else:
        raise BerError(f"PDU type {pdu_tag:#x} is not a trap")
    return {"version": "v1" if version == 0 else "v2c", "community": community,
            "trap": trap or "unknown", "varbinds": vb}


def trap_text(d: dict) -> str:
    """One line rules can match: 'linkDown ifIndex=3 ifDescr=Gi0/1 ...'."""
    return " ".join([d["trap"], *(f"{k}={v}" for k, v in d["varbinds"].items())])[:2000]


# --- GET (v2c) -----------------------------------------------------------------

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, v: bytes) -> bytes:
    return bytes([tag]) + _len(len(v)) + v


def _enc_int(n: int) -> bytes:
    return _tlv(0x02, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True))


def _enc_oid(oid: str) -> bytes:
    p = [int(x) for x in oid.split(".")]
    out = bytearray([p[0] * 40 + p[1]])
    for n in p[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.insert(0, 0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(chunk)
    return _tlv(0x06, bytes(out))


def _request(host: str, community: str, tag: int, oids: list[str], port: int, timeout: float,
             non_rep: int = 0, max_rep: int = 0, retries: int = 1) -> list[tuple[str, int, str]]:
    """One v2c request (GET 0xA0 / GETBULK 0xA5). [(oid, value tag, value)]."""
    rid = random.randint(1, 2**30)
    vbs = b"".join(_tlv(0x30, _enc_oid(o) + b"\x05\x00") for o in oids)
    pdu = _tlv(tag, _enc_int(rid) + _enc_int(non_rep) + _enc_int(max_rep) + _tlv(0x30, vbs))
    msg = _tlv(0x30, _enc_int(1) + _tlv(0x04, community.encode()) + pdu)
    data = b""
    for attempt in range(retries + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.sendto(msg, (host, port))
                while True:                              # skip a late answer to an earlier try
                    data, _ = s.recvfrom(65535)
                    _t, body, _ = _read(data, 0)
                    resp = _children(_children(body)[2][1])
                    if int.from_bytes(resp[0][1], "big", signed=True) == rid:
                        break
                break
            except socket.timeout:
                if attempt == retries:
                    raise
    if int.from_bytes(resp[1][1], "big"):
        raise BerError(f"SNMP error status {int.from_bytes(resp[1][1], 'big')}")
    out = []
    for _t, vb in _children(resp[3][1]):
        kids = _children(vb)
        if len(kids) == 2 and kids[0][0] == 0x06:
            vt, vv = kids[1]
            out.append((_oid(kids[0][1]), vt, _oid(vv) if vt == 0x06 else _value(vt, vv)))
    return out


def walk(host: str, community: str, base: str, port: int = 161, timeout: float = 2.0,
         max_rows: int = 5000) -> dict[str, str]:
    """Every value under `base` with GETBULK: {suffix after base: value}. Ends at
    the subtree's end, endOfMibView, or max_rows (a runaway agent cannot loop us)."""
    out: dict[str, str] = {}
    cur = base
    while len(out) < max_rows:
        rows = _request(host, community, 0xA5, [cur], port, timeout, 0, 30)
        if not rows:
            break
        for oid, vt, val in rows:
            if vt in (0x80, 0x81, 0x82) or not oid.startswith(base + "."):
                return out
            suf = oid[len(base) + 1:]
            if suf in out:
                return out                               # not advancing - a broken agent
            out[suf] = val
            cur = oid
    return out


def get_raw(host: str, community: str, oids: list[str], port: int = 161, timeout: float = 2.0) -> dict[str, str]:
    """GET that keeps OID values as OIDs (sysObjectID) and drops noSuch* answers."""
    return {o: v for o, vt, v in _request(host, community, 0xA0, oids, port, timeout) if vt not in (0x80, 0x81, 0x82)}


def get(host: str, community: str, oids: list[str], port: int = 161,
        timeout: float = 3.0) -> dict[str, str]:
    """SNMPv2c GET. {oid: value}. Raises OSError/BerError on failure."""
    rid = random.randint(1, 2**30)
    vbs = b"".join(_tlv(0x30, _enc_oid(o) + b"\x05\x00") for o in oids)
    pdu = _tlv(0xA0, _enc_int(rid) + _enc_int(0) + _enc_int(0) + _tlv(0x30, vbs))
    msg = _tlv(0x30, _enc_int(1) + _tlv(0x04, community.encode()) + pdu)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(msg, (host, port))
        data, _ = s.recvfrom(65535)
    _t, body, _ = _read(data, 0)
    kids = _children(body)
    resp = _children(kids[2][1])
    if int.from_bytes(resp[1][1], "big"):
        raise BerError(f"SNMP error status {int.from_bytes(resp[1][1], 'big')}")
    return dict(_varbinds(resp[3][1]))
