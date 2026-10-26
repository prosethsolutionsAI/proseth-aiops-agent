"""Log rules: is this syslog line / SNMP trap / Windows event a PROBLEM, or noise?

**Copied verbatim into the agent** (agent/proseth_aiops_agent/rules.py), like
protocol.py: the collector filters syslog and traps with it, the platform
filters pulled Windows events with it, and the self-test fails if the two
copies differ - so "what counts as a problem" has exactly one definition.
Standard library only.

A rule is a plain dict (it travels as JSON in the CONFIG frame):

    {"name": "Cisco interface down", "source": "syslog",       # syslog|trap|winevent|*
     "match": "%LINK-3-UPDOWN: Interface (?P<iface>\\S+), changed state to down",
     "host": "",                    # optional regex on the sending host/IP
     "event_ids": [],               # winevent only
     "max_level": null,             # syslog: only severity <= this (0 emerg .. 7 debug)
     "action": "alert",             # alert | drop
     "severity": "high", "alertname": "InterfaceDown",
     "title": "Interface {iface} down", "enabled": true}

Rules are evaluated IN ORDER; the first that matches decides. Nothing matching
means drop (counted) - unknown chatter never reaches the platform.
Named groups in `match` fill `{placeholders}` in the title, plus {host}.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

SEVERITIES = ("info", "warning", "high", "critical")
SYSLOG_LEVELS = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")


@dataclass
class Event:
    source: str                     # syslog | trap | winevent
    host: str                       # IP or hostname of the sender
    message: str
    level: int | None = None        # syslog severity 0..7, winevent 1 crit 2 err 3 warn
    event_id: int | None = None
    fields: dict = field(default_factory=dict)


@dataclass
class Decision:
    action: str                     # alert | drop
    rule: str = ""
    severity: str = "warning"
    alertname: str = ""
    title: str = ""


class _Safe(dict):
    def __missing__(self, key):     # an unknown {placeholder} stays visible
        return "{" + key + "}"


def compile_rules(rules: list[dict]) -> list[tuple[dict, re.Pattern | None, re.Pattern | None]]:
    out = []
    for r in rules or []:
        if not isinstance(r, dict) or not r.get("enabled", True):
            continue
        try:
            m = re.compile(r["match"], re.IGNORECASE) if r.get("match") else None
            h = re.compile(r["host"], re.IGNORECASE) if r.get("host") else None
        except re.error:
            continue                # a broken rule is skipped, never fatal
        out.append((r, m, h))
    return out


def evaluate(compiled, ev: Event) -> Decision:
    for r, m, h in compiled:
        src = r.get("source") or "*"
        if src not in ("*", ev.source):
            continue
        if h is not None and not h.search(ev.host or ""):
            continue
        ids = r.get("event_ids") or []
        if ids and ev.event_id not in ids:
            continue
        lvl = r.get("max_level")
        if lvl is not None and (ev.level is None or ev.level > int(lvl)):
            continue
        found = m.search(ev.message or "") if m is not None else None
        if m is not None and found is None:
            continue
        if r.get("action", "alert") == "drop":
            return Decision("drop", rule=r.get("name", ""))
        vals = _Safe(host=ev.host, **(found.groupdict() if found else {}))
        title = (r.get("title") or r.get("name") or "").format_map(vals)
        sev = r.get("severity") if r.get("severity") in SEVERITIES else "warning"
        return Decision("alert", rule=r.get("name", ""), severity=sev,
                        alertname=r.get("alertname") or re.sub(r"\W+", "", r.get("name", "")) or "LogMatch",
                        title=title[:300] or ev.message[:200])
    return Decision("drop", rule="(no rule matched)")


class Gate:
    """De-duplicate and rate-limit what passes: the same (host, alertname) within
    `window` seconds is counted, not resent; at most `per_minute` per host."""

    def __init__(self, window: int = 300, per_minute: int = 20):
        self.window, self.per_minute = window, per_minute
        self._last: dict[tuple[str, str], float] = {}
        self._minute: dict[str, list[float]] = {}
        self.suppressed = 0

    def allow(self, host: str, alertname: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        key = (host, alertname)
        if now - self._last.get(key, -1e18) < self.window:
            self.suppressed += 1
            return False
        recent = [t for t in self._minute.get(host, []) if now - t < 60]
        if len(recent) >= self.per_minute:
            self.suppressed += 1
            self._minute[host] = recent
            return False
        recent.append(now)
        self._minute[host], self._last[key] = recent, now
        if len(self._last) > 20000:            # bounded memory on a noisy site
            cutoff = now - self.window
            self._last = {k: v for k, v in self._last.items() if v >= cutoff}
        return True


# --- syslog parsing (RFC 3164 and 5424, tolerant) -----------------------------

_PRI = re.compile(r"^<(\d{1,3})>(.*)$", re.S)


def parse_syslog(raw: str, sender: str) -> Event:
    """An Event from one syslog datagram/line. The SENDER IP is the host: the
    hostname field in the message is often absent or wrong on network gear."""
    text = raw.strip()
    level = None
    m = _PRI.match(text)
    if m:
        pri = int(m.group(1))
        level, text = pri % 8, m.group(2).lstrip()
        fac = pri // 8
    else:
        fac = None
    return Event(source="syslog", host=sender, message=text[:4000], level=level,
                 fields={"facility": fac})
