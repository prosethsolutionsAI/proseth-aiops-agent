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
from pathlib import Path

from . import rules, snmp
from .alerts import AlertQueue

log = logging.getLogger("proseth-aiops-agent")


class Filter:
    """Gate 1 on the collector: the shared rules.Engine (rules, thresholds,
    recovery, dedup, per-rule counters) plus the queue to the platform.
    Thread-safe; a new rule set replaces the engine's rules but KEEPS its
    counters, threshold windows and dedup memory - a rule edit must not make
    every open threshold start again or every recent alert repeat."""

    TICK_S = 30                                     # watchdog check interval

    def __init__(self, queue: AlertQueue, on_new, cache: Path, *, ticker: bool = True):
        self.queue, self.on_new, self.cache = queue, on_new, cache
        self.watch_file = cache.with_name("watch.json")
        self._lock = threading.Lock()
        self.engine = rules.Engine()
        try:                                       # last rules survive a restart
            self.set_rules(json.loads(cache.read_text(encoding="utf-8")), persist=False)
        except (OSError, ValueError):
            pass
        try:                                       # ...and which hosts are watched
            self.engine.watch = json.loads(self.watch_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        if ticker:
            threading.Thread(target=self._ticker, daemon=True, name="watchdog").start()

    def _ticker(self) -> None:
        import time  # noqa: PLC0415
        while True:
            time.sleep(self.TICK_S)
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - a watchdog must never take the receivers down
                log.exception("watchdog tick failed")

    def tick(self, now: float | None = None) -> int:
        """Send 'gone quiet' alerts, and keep the watch list on disk."""
        with self._lock:
            out = self.engine.tick(now)
            state = json.dumps(self.engine.watch)
        for payload in out:
            self.queue.put(payload["labels"].get("via", "syslog"), json.dumps(payload), payload["host"])
        if out:
            self.on_new()
        try:
            self.watch_file.write_text(state, encoding="utf-8")
            self.watch_file.chmod(0o600)
        except OSError:
            pass
        return len(out)

    def set_rules(self, cfg: dict, persist: bool = True) -> None:
        compiled = rules.compile_rules(cfg.get("rules") or [])
        with self._lock:
            self.engine.compiled = compiled
            self.engine.gate.window = int(cfg.get("dedup_seconds") or 300)
            self.engine.gate.per_minute = int(cfg.get("per_host_per_minute") or 20)
        if self.store is not None and cfg.get("log_retention_days"):
            self.store.retention_days = max(1, min(int(cfg["log_retention_days"]), 3650))
        if persist:
            try:
                self.cache.write_text(json.dumps(cfg), encoding="utf-8")
                self.cache.chmod(0o600)
            except OSError:
                pass
        log.info("Log rules updated: %s active", len(compiled))

    store = None                                     # logstore.LogStore, set by the agent

    def handle(self, ev: rules.Event) -> None:
        if self.store is not None:                   # every line is KEPT here, whatever
            self.store.write(ev)                     # the rules decide to send
        with self._lock:
            out = self.engine.process_all(ev)
        for payload in out:
            self.queue.put(ev.source, json.dumps(payload), ev.host)
        if out:
            self.on_new()

    def count(self, what: str) -> None:
        with self._lock:
            self.engine._count(what)              # noqa: SLF001 - the engine's own tally

    def snapshot(self) -> dict:
        with self._lock:
            out = dict(self.engine.stats)
            # Per rule: hits / sent / last - the platform shows noisy and dead rules.
            out["rules"] = {k: dict(v) for k, v in self.engine.rule_stats.items()}
        return out


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
                filt.count("trap_undecodable")
                log.warning("Trap from %s not decoded: %s", sender, exc)
                return
            if communities and d["community"] not in communities:
                filt.count("trap_wrong_community")
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
