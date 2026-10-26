"""Syslog (514 udp/tcp) and SNMP-trap (162 udp) receivers on the collector.

Gate 1 lives here: every message is matched against the rules the platform
pushed (rules.py, shared with the platform). Only an `alert` decision that also
passes de-duplication and rate-limiting is queued for the platform; everything
else is COUNTED (so the platform can show "12,400 dropped today") and gone.
Raw logs never leave the site - an alert carries the one line that triggered it.

Binding 514/162 needs CAP_NET_BIND_SERVICE, which the systemd unit grants; the
agent itself stays unprivileged.
"""
from __future__ import annotations

import json
import logging
import socketserver
import threading
from collections import Counter
from pathlib import Path

from . import rules, snmp
from .alerts import AlertQueue

log = logging.getLogger("proseth-aiops-agent")


class Filter:
    """Rules + gate + counters. Thread-safe; rules are swapped atomically."""

    def __init__(self, queue: AlertQueue, on_new, cache: Path):
        self.queue, self.on_new, self.cache = queue, on_new, cache
        self._lock = threading.Lock()
        self._compiled = []
        self.gate = rules.Gate()
        self.stats: Counter = Counter()
        try:                                       # last rules survive a restart
            self.set_rules(json.loads(cache.read_text(encoding="utf-8")), persist=False)
        except (OSError, ValueError):
            pass

    def set_rules(self, cfg: dict, persist: bool = True) -> None:
        compiled = rules.compile_rules(cfg.get("rules") or [])
        with self._lock:
            self._compiled = compiled
            self.gate.window = int(cfg.get("dedup_seconds") or 300)
            self.gate.per_minute = int(cfg.get("per_host_per_minute") or 20)
        if persist:
            try:
                self.cache.write_text(json.dumps(cfg), encoding="utf-8")
                self.cache.chmod(0o600)
            except OSError:
                pass
        log.info("Log rules updated: %s active", len(compiled))

    def handle(self, ev: rules.Event) -> None:
        with self._lock:
            compiled = self._compiled
        d = rules.evaluate(compiled, ev)
        self.stats[f"{ev.source}_received"] += 1
        if d.action != "alert":
            self.stats[f"{ev.source}_dropped"] += 1
            return
        with self._lock:
            ok = self.gate.allow(ev.host, d.alertname)
        if not ok:
            self.stats[f"{ev.source}_suppressed"] += 1
            return
        self.stats[f"{ev.source}_forwarded"] += 1
        payload = {"host": ev.host, "title": d.title, "severity": d.severity,
                   "alertname": d.alertname, "status": "firing",
                   "description": ev.message[:3000],
                   "labels": {"rule": d.rule, "via": ev.source,
                              **{k: str(v) for k, v in ev.fields.items() if v is not None}}}
        self.queue.put(ev.source, json.dumps(payload), ev.host)
        self.on_new()

    def snapshot(self) -> dict:
        return dict(self.stats)


def _syslog_udp(filt: Filter):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            data = self.request[0]
            try:
                filt.handle(rules.parse_syslog(data.decode("utf-8", "replace"), self.client_address[0]))
            except Exception:  # noqa: BLE001 - one bad datagram must not stop the listener
                log.exception("syslog datagram")
    return H


def _syslog_tcp(filt: Filter):
    class H(socketserver.StreamRequestHandler):
        def handle(self):
            for raw in self.rfile:                   # newline-framed (RFC 6587 non-transparent)
                line = raw.decode("utf-8", "replace").strip()
                if line:
                    try:
                        filt.handle(rules.parse_syslog(line, self.client_address[0]))
                    except Exception:  # noqa: BLE001
                        log.exception("syslog line")
    return H


def _trap_udp(filt: Filter, communities: set[str]):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            sender = self.client_address[0]
            try:
                d = snmp.decode_trap(self.request[0])
            except snmp.BerError as exc:
                filt.stats["trap_undecodable"] += 1
                log.warning("Trap from %s not decoded: %s", sender, exc)
                return
            if communities and d["community"] not in communities:
                filt.stats["trap_wrong_community"] += 1
                return
            filt.handle(rules.Event(source="trap", host=sender, message=snmp.trap_text(d),
                                    fields={"trap": d["trap"], "snmp": d["version"]}))
    return H


class _UDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start(filt: Filter, *, syslog_port: int | None, trap_port: int | None,
          communities: set[str]) -> list[str]:
    """Start whichever receivers are configured. Never fatal: returns what started."""
    started = []
    plan = []
    if syslog_port:
        plan += [(_UDP, syslog_port, _syslog_udp(filt), f"syslog udp/{syslog_port}"),
                 (_TCP, syslog_port, _syslog_tcp(filt), f"syslog tcp/{syslog_port}")]
    if trap_port:
        plan.append((_UDP, trap_port, _trap_udp(filt, communities), f"snmp-trap udp/{trap_port}"))
    for cls, port, handler, label in plan:
        try:
            srv = cls(("0.0.0.0", port), handler)
        except OSError as exc:
            log.error("Could not listen on %s (%s) - check the unit grants "
                      "CAP_NET_BIND_SERVICE and nothing else holds the port", label, exc)
            continue
        threading.Thread(target=srv.serve_forever, daemon=True, name=label).start()
        started.append(label)
    if started:
        log.info("Receiving: %s", ", ".join(started))
    return started
