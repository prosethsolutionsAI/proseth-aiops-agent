"""Log rules: is this syslog line / SNMP trap / Windows event a PROBLEM, or noise?

**Copied verbatim into the agent** (agent/proseth_aiops_agent/rules.py), like
protocol.py: the collector filters syslog and traps with it, the platform
filters pulled Windows events with it, and the self-test fails if the two
copies differ - so "what counts as a problem" has exactly one definition.
Standard library only.

A rule is a plain dict (it travels as JSON in the CONFIG frame). Every field
but `name` is optional; an old rule (v1) means exactly what it always meant:

    {"name": "Cisco interface down", "source": "syslog",      # syslog|trap|winevent|*
     # --- WHAT it matches (all must hold) ---------------------------------
     "match": "%LINK-3-UPDOWN: Interface (?P<iface>\\S+), changed state to down",
     "not_match": "",               # ...unless this matches too (exclusions)
     "host": "",                    # regex on the sending host/IP
     "program": "",                 # regex on the syslog program/tag (sshd, kernel)
     "event_ids": [],               # winevent only
     "max_level": null,             # syslog: only severity <= this (0 emerg .. 7 debug)
     # --- WHEN it fires --------------------------------------------------
     "count": 1, "within": 60,      # threshold: `count` matches within `within` s
     "group_by": "",                # ...counted per this (default: per host/key)
     "key": "",                     # which INSTANCE, e.g. "{iface}" - one alert each
     "recovery": "",                # a line matching this RESOLVES that instance
     "dedup": null,                 # seconds before the same alert is sent again
     "silence": null,               # WATCHDOG (Zabbix nodata): alert when NO matching
                                    # line came from a host for this many seconds;
                                    # the next matching line resolves it. A watchdog
                                    # never decides a line - the other rules still do.
     # --- WHAT happens ---------------------------------------------------
     "action": "alert",             # alert (send) | record (count only) | drop
     "severity": "high",            # info|warning|high|critical|auto (from the level)
     "ai": "auto",                  # gate 2 hint: auto | always | never investigate
     "alertname": "InterfaceDown", "title": "Interface {iface} down", "enabled": true}

Rules are evaluated IN ORDER; the first whose conditions match decides - by its
`match` (fire) or its `recovery` (resolve). Nothing matching = drop (counted).
Placeholders in title/key/group_by: named regex groups, key=value pairs found
in the line (FortiGate-style), {host}, {program}, {msg}.
"""
from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field

SEVERITIES = ("info", "warning", "high", "critical")
SYSLOG_LEVELS = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
ACTIONS = ("alert", "record", "drop")
AI_MODES = ("auto", "always", "never")


@dataclass
class Event:
    source: str                     # syslog | trap | winevent
    host: str                       # IP or hostname of the sender
    message: str
    level: int | None = None        # syslog severity 0..7, winevent 1 crit 2 err 3 warn
    event_id: int | None = None
    fields: dict = field(default_factory=dict)
    program: str = ""               # syslog tag / app-name (sshd, kernel, CRON)
    body: str = ""                  # the message without its syslog header


@dataclass
class Decision:
    action: str                     # alert | record | drop | resolve
    rule: str = ""
    severity: str = "warning"
    alertname: str = ""
    title: str = ""
    key: str = ""                   # the instance ("Gi0/1"), "" = one per host
    group: str = ""                 # what a threshold counts per
    count: int = 1
    within: int = 60
    dedup: int | None = None
    ai: str = "auto"
    values: dict = field(default_factory=dict)


class _Safe(dict):
    def __missing__(self, key):     # an unknown {placeholder} stays visible
        return "{" + key + "}"


def _fill(template: str, vals: dict) -> str:
    try:
        return (template or "").format_map(vals)
    except (ValueError, IndexError, AttributeError):
        return template or ""


def compile_rules(rules: list[dict]) -> list[tuple]:
    """(rule, match, host, program, not_match, recovery) per enabled, valid rule."""
    out = []
    for r in rules or []:
        if not isinstance(r, dict) or not r.get("enabled", True):
            continue
        try:
            pats = tuple(re.compile(r[k], re.IGNORECASE) if r.get(k) else None
                         for k in ("match", "host", "program", "not_match", "recovery"))
        except (re.error, TypeError):
            continue                # a broken rule is skipped, never fatal
        out.append((r, *pats))
    return out


_KV = re.compile(r'(?<![\w.-])([A-Za-z_][\w.-]{0,40})=("[^"]{0,300}"|[^\s,;]{1,300})')


def kv_fields(text: str) -> dict:
    """key=value / key="value" pairs (FortiGate, Palo Alto, many appliances)."""
    out = {}
    for k, v in _KV.findall(text or "")[:60]:
        out.setdefault(k.replace(".", "_").replace("-", "_"), v.strip('"'))
    return out


def level_severity(ev: Event) -> str:
    """severity "auto": from the syslog level (winevent: 1 crit, 2 err, 3 warn)."""
    lvl = ev.level
    if lvl is None:
        return "warning"
    if ev.source == "winevent":
        return {1: "critical", 2: "high", 3: "warning"}.get(lvl, "info")
    return "critical" if lvl <= 2 else "high" if lvl == 3 else "warning" if lvl == 4 else "info"


def _applies(r, m, h, prog, nm, ev: Event):
    """(scope holds, fires, match) - SCOPE is source/host/program/event IDs (a
    recovery line must pass it too); FIRES is the match minus exclusions, within
    the level ceiling."""
    src = r.get("source") or "*"
    if src not in ("*", ev.source):
        return False, False, None
    if h is not None and not h.search(ev.host or ""):
        return False, False, None
    if prog is not None and not prog.search(ev.program or ""):
        return False, False, None
    ids = r.get("event_ids") or []
    if ids and ev.event_id not in ids:
        return False, False, None
    found = m.search(ev.message or "") if m is not None else None
    fires = (m is None or found is not None) and not (nm is not None and nm.search(ev.message or ""))
    lvl = r.get("max_level")
    if fires and lvl is not None and (ev.level is None or ev.level > int(lvl)):
        fires = False
    return True, fires, found


def _values(ev: Event, hit) -> "_Safe":
    groups = hit.groupdict() if hit is not None else {}
    return _Safe({**ev.fields, **kv_fields(ev.message), "host": ev.host,
                  "program": ev.program or "", "msg": (ev.body or ev.message or "")[:160],
                  **{k: v for k, v in groups.items() if v is not None}})


def evaluate(compiled, ev: Event) -> Decision:
    for r, m, h, prog, nm, rec in compiled:
        if r.get("silence"):
            continue                # watchdogs observe; they never decide a line
        scope, fires, found = _applies(r, m, h, prog, nm, ev)
        if not scope:
            continue
        recovered = None if fires or rec is None else rec.search(ev.message or "")
        if not fires and recovered is None:
            continue
        action = r.get("action", "alert")
        if action not in ACTIONS:
            action = "alert"
        if fires and action == "drop":
            return Decision("drop", rule=r.get("name", ""))
        vals = _values(ev, found if fires else recovered)
        sev = r.get("severity")
        sev = level_severity(ev) if sev == "auto" else sev if sev in SEVERITIES else "warning"
        key = _fill(r.get("key") or "", vals)[:120]
        return Decision(
            action if fires else "resolve", rule=r.get("name", ""), severity=sev,
            alertname=r.get("alertname") or re.sub(r"\W+", "", r.get("name", "")) or "LogMatch",
            title=(_fill(r.get("title") or r.get("name") or "", vals)[:300]
                   or (ev.message or "")[:200]),
            key=key, group=_fill(r.get("group_by") or "", vals)[:120] or key,
            count=max(1, int(r.get("count") or 1)), within=max(1, int(r.get("within") or 60)),
            dedup=(int(r["dedup"]) if r.get("dedup") not in (None, "") else None),
            ai=r.get("ai") if r.get("ai") in AI_MODES else "auto", values=dict(vals))
    return Decision("drop", rule="(no rule matched)")


class Gate:
    """De-duplicate and rate-limit what passes: the same (host, alertname) within
    `window` seconds is counted, not resent; at most `per_minute` per host."""

    def __init__(self, window: int = 300, per_minute: int = 20):
        self.window, self.per_minute = window, per_minute
        self._last: dict[tuple[str, str], float] = {}
        self._minute: dict[str, list[float]] = {}
        self.suppressed = 0

    def allow(self, host: str, alertname: str, now: float | None = None,
              window: int | None = None) -> bool:
        now = time.time() if now is None else now
        key = (host, alertname)
        if now - self._last.get(key, -1e18) < (self.window if window is None else window):
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
            cutoff = now - max(self.window, 3600)
            self._last = {k: v for k, v in self._last.items() if v >= cutoff}
        return True

    def forget(self, host: str, alertname: str) -> None:
        """A recovered instance may fire again at once when it next breaks."""
        self._last.pop((host, alertname), None)


class Engine:
    """Gate 1 in full: rules + thresholds + recovery + dedup + per-rule counters.

    `process(event)` returns the payload to send to the platform (or None) and
    keeps every count, so a rule that never fires - or fires all day - shows.
    Used by the collector for syslog/traps and by the platform for pulled
    Windows events, so both behave identically."""

    def __init__(self, rules: list[dict] | None = None, dedup_seconds: int = 300,
                 per_host_per_minute: int = 20):
        self.compiled = compile_rules(rules or [])
        self.gate = Gate(dedup_seconds, per_host_per_minute)
        self._hits: dict[tuple, deque] = {}
        self.rule_stats: dict[str, dict] = {}
        self.stats: dict[str, int] = {}
        # Watchdogs: "rule|host|key" -> when a matching line was last seen, and
        # whether the "gone quiet" alert is out. Saved by the collector so a
        # restart does not forget a host that went quiet during it.
        self.watch: dict[str, dict] = {}

    def process_all(self, ev: Event, now: float | None = None) -> list[dict]:
        """Everything this line causes: watchdog recoveries, then its decision."""
        now = time.time() if now is None else now
        out = self._observe(ev, now)
        main = self.process(ev, now)
        return out + ([main] if main else [])

    def _observe(self, ev: Event, now: float) -> list[dict]:
        out = []
        for r, m, h, prog, nm, _rec in self.compiled:
            silence = int(r.get("silence") or 0)
            if silence <= 0:
                continue
            scope, fires, found = _applies(r, m, h, prog, nm, ev)
            if not (scope and fires):
                continue
            vals = _values(ev, found)
            key = _fill(r.get("key") or "", vals)[:120]
            wk = f"{r.get('name', '')}|{ev.host}|{key}"
            w = self.watch.get(wk)
            mins = max(1, silence // 60)
            vals["minutes"] = str(mins)
            name = r.get("alertname") or re.sub(r"\W+", "", r.get("name", "")) or "LogSilence"
            self.watch[wk] = {
                "rule": r.get("name", ""), "host": ev.host, "key": key, "last": now, "silence": silence,
                "alertname": f"{name}:{key}" if key else name,
                "title": (_fill(r.get("title") or "", vals) or f"No '{r.get('name', '')}' logs from "
                          f"{ev.host} for {mins} min")[:300],
                "severity": r.get("severity") if r.get("severity") in SEVERITIES else "warning",
                "ai": r.get("ai") if r.get("ai") in AI_MODES else "auto",
                "source": ev.source, "alerted": bool(w and w.get("alerted"))}
            self._bump(r.get("name", ""), "hits", now)
            if w and w.get("alerted"):                 # logs are back: resolve
                self.watch[wk]["alerted"] = False
                out.append(self._silence_payload(self.watch[wk], "resolved"))
        if len(self.watch) > 5000:
            for k in sorted(self.watch, key=lambda k: self.watch[k]["last"])[:500]:
                self.watch.pop(k, None)
        return out

    def tick(self, now: float | None = None) -> list[dict]:
        """Watchdogs whose host has gone quiet for longer than the rule allows."""
        now = time.time() if now is None else now
        live = {r.get("name", ""): int(r.get("silence") or 0)
                for r, *_ in self.compiled if r.get("silence")}
        out = []
        for wk, w in list(self.watch.items()):
            if w["rule"] not in live:                  # rule deleted or disabled
                self.watch.pop(wk, None)
                continue
            w["silence"] = live[w["rule"]]
            if not w.get("alerted") and now - w["last"] > w["silence"]:
                w["alerted"] = True
                self._count(f"{w.get('source', 'syslog')}_silence")
                self._bump(w["rule"], "sent", now)
                out.append(self._silence_payload(w, "firing"))
        return out

    @staticmethod
    def _silence_payload(w: dict, status: str) -> dict:
        return {"host": w["host"], "title": w["title"], "severity": w["severity"],
                "alertname": w["alertname"], "status": status,
                "description": f"No matching log line from {w['host']} for over "
                               f"{max(1, w['silence'] // 60)} min (watchdog '{w['rule']}')."
                               if status == "firing" else f"Logs from {w['host']} are back.",
                "labels": {"rule": w["rule"], "via": w.get("source", "syslog"), "ai": w["ai"],
                           "watchdog": f"{w['silence']}s", **({"key": w["key"]} if w["key"] else {})}}

    def _bump(self, name: str, what: str, now: float) -> None:
        s = self.rule_stats.setdefault(name, {"hits": 0, "sent": 0, "last": 0})
        s[what] = s.get(what, 0) + 1
        s["last"] = int(now)
        if len(self.rule_stats) > 500:
            self.rule_stats.pop(next(iter(self.rule_stats)))

    def _count(self, k: str, n: int = 1) -> None:
        self.stats[k] = self.stats.get(k, 0) + n

    def process(self, ev: Event, now: float | None = None) -> dict | None:
        now = time.time() if now is None else now
        d = evaluate(self.compiled, ev)
        self._count(f"{ev.source}_received")
        if d.action in ("drop", "record"):
            self._count(f"{ev.source}_{'dropped' if d.action == 'drop' else 'recorded'}")
            if d.action == "record":
                self._bump(d.rule, "hits", now)
            return None
        self._bump(d.rule, "hits", now)
        name = f"{d.alertname}:{d.key}" if d.key else d.alertname
        if d.action == "resolve":
            self.gate.forget(ev.host, name)
            self._hits.pop((d.rule, ev.host, d.group), None)
            self._count(f"{ev.source}_resolved")
            return self._payload(ev, d, name, "resolved")
        if d.count > 1:                         # threshold: N within T seconds
            q = self._hits.setdefault((d.rule, ev.host, d.group), deque())
            q.append(now)
            while q and now - q[0] > d.within:
                q.popleft()
            if len(q) < d.count:
                self._count(f"{ev.source}_pending")
                return None
            q.clear()
            if len(self._hits) > 20000:
                self._hits = {k: v for k, v in self._hits.items() if v}
        if not self.gate.allow(ev.host, name, now, window=d.dedup):
            self._count(f"{ev.source}_suppressed")
            return None
        self._count(f"{ev.source}_forwarded")
        self._bump(d.rule, "sent", now)
        return self._payload(ev, d, name, "firing")

    @staticmethod
    def _payload(ev: Event, d: Decision, name: str, status: str) -> dict:
        labels = {"rule": d.rule, "via": ev.source, "ai": d.ai}
        if d.key:
            labels["key"] = d.key
        if d.count > 1:
            labels["threshold"] = f"{d.count} in {d.within}s"
        if ev.program:
            labels["program"] = ev.program
        for k, v in ev.fields.items():
            if v is not None and len(labels) < 30:
                labels.setdefault(k, str(v)[:200])
        return {"host": ev.host, "title": d.title, "severity": d.severity, "alertname": name,
                "status": status, "description": (ev.message or "")[:3000], "labels": labels}


# --- syslog parsing (RFC 3164 and 5424, tolerant) -----------------------------

_PRI = re.compile(r"^<(\d{1,3})>(.*)$", re.S)
_5424 = re.compile(r"^1 \S+ (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) \S+ (?:-|\[.*?\])\s?(?P<msg>.*)$", re.S)
_3164 = re.compile(r"^(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d |\d{4}-\d\d-\d\dT\S+ )?"
                   r"(?:(?P<host>[\w.:-]+) )?(?P<tag>[\w./@-]{1,48})(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$", re.S)


def parse_syslog(raw: str, sender: str) -> Event:
    """An Event from one syslog datagram/line. The SENDER IP is the host: the
    hostname field in the message is often absent or wrong on network gear.
    `program` and `body` are best effort; `message` stays the whole line, so
    rules written against full lines keep matching."""
    text = raw.strip()
    level = fac = None
    m = _PRI.match(text)
    if m:
        pri = int(m.group(1))
        level, fac, text = pri % 8, pri // 8, m.group(2).lstrip()
    program, body = "", text
    p = _5424.match(text)
    if p:
        program = "" if p.group("app") == "-" else p.group("app")
        body = p.group("msg")
    else:
        p = _3164.match(text)
        # Not a Cisco mnemonic (%LINK-3-...) nor a bare sequence number (000123:).
        if p and not p.group("tag").startswith("%") and not p.group("tag").isdigit():
            program, body = p.group("tag"), p.group("msg")
    return Event(source="syslog", host=sender, message=text[:4000], level=level,
                 fields={"facility": fac}, program=program[:48], body=body[:4000])
