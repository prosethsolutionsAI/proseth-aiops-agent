"""Alert intake: a small listener the customer's monitoring tools post to.

Zabbix, Wazuh, Prometheus Alertmanager - whatever watches this network - is
pointed at `http://<this worker>:9997/alert/<source>`. The agent stores the
body and relays it to the Supervisor over the connection it already has, so
the Supervisor learns something is wrong without ever connecting into this
network. This is the ONE thing on a worker that accepts a connection, which is
why it is off unless an alert secret is configured, and why it should be
firewalled to the monitoring server alone.

## The worker relays, the Supervisor parses

The body is forwarded as it arrived, with the source name from the URL. Every
tool sends a different shape, and those shapes change between releases; doing
the parsing on the Supervisor means supporting a new tool, or a new version of
one, never needs every worker at every customer upgraded first.

## Nothing is lost on a drop

An alert is written to disk BEFORE the monitoring tool is told it was accepted,
and deleted only when the Supervisor acknowledges that it has STORED it. A link
that is down for an hour, a Supervisor restart, an agent restart - the alert is
sent again on the next connection. The Supervisor de-duplicates by id, so a
second delivery is harmless. The queue is bounded: a worker cut off for a week
keeps the newest alerts rather than filling its disk.
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

log = logging.getLogger("proseth-aiops-agent")

# A monitoring payload is a few KB. Anything near this is not an alert, and a
# listener on a customer LAN must not be a way to fill this machine's memory.
MAX_BODY = 256 * 1024
# Newest alerts win past this. A week of a flapping check is still well inside.
MAX_QUEUED = 1000
# An alert sent and not acknowledged within this long is sent again. The
# Supervisor de-duplicates by id, so the cost of a resend is one wasted frame.
RESEND_AFTER = 60

_SOURCE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


class AlertQueue:
    """Alerts waiting for the Supervisor, one JSON file each.

    One file per alert rather than one file for the queue: a write is a single
    atomic rename, there is nothing to rewrite when one is acknowledged, and a
    crash mid-write leaves a stray `.tmp` rather than a corrupt queue.
    """

    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # id -> monotonic time it was last sent. In memory only: after a
        # restart everything on disk is simply sent again.
        self._sent: dict[str, float] = {}

    def put(self, source: str, body: str, remote: str) -> str:
        alert_id = uuid.uuid4().hex
        record = {"id": alert_id, "source": source, "payload": body,
                  "remote": remote, "received_at": time.time()}
        name = f"{time.time_ns():020d}-{alert_id}.json"
        tmp = self.dir / (name + ".tmp")
        with self._lock:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(record, handle)
            os.replace(tmp, self.dir / name)
            self._trim()
        return alert_id

    def _trim(self) -> None:
        files = sorted(self.dir.glob("*.json"))
        excess = len(files) - MAX_QUEUED
        if excess > 0:
            log.warning("Alert queue is full (%s) - dropping the %s oldest. "
                        "Is this worker reaching the Supervisor?",
                        MAX_QUEUED, excess)
            for old in files[:excess]:
                old.unlink(missing_ok=True)

    def due(self) -> list[dict]:
        """Alerts never sent, or sent and not acknowledged for a while."""
        now = time.monotonic()
        out: list[dict] = []
        with self._lock:
            for path in sorted(self.dir.glob("*.json")):
                alert_id = path.stem.split("-", 1)[-1]
                sent = self._sent.get(alert_id)
                if sent is not None and now - sent < RESEND_AFTER:
                    continue
                try:
                    out.append(json.loads(path.read_text(encoding="utf-8")))
                except (OSError, ValueError):
                    # Unreadable is never going to become readable. Say so and
                    # move it aside rather than retrying it for ever.
                    log.warning("Unreadable queued alert %s - removed", path.name)
                    path.unlink(missing_ok=True)
        return out

    def mark_sent(self, alert_id: str) -> None:
        with self._lock:
            self._sent[alert_id] = time.monotonic()

    def reset_sent(self) -> None:
        """A new connection: nothing sent on the old one was necessarily seen."""
        with self._lock:
            self._sent.clear()

    def ack(self, alert_id: str) -> bool:
        if not re.fullmatch(r"[0-9a-f]{32}", alert_id or ""):
            return False
        with self._lock:
            self._sent.pop(alert_id, None)
            for path in self.dir.glob(f"*-{alert_id}.json"):
                path.unlink(missing_ok=True)
                return True
        return False

    def depth(self) -> int:
        return sum(1 for _ in self.dir.glob("*.json"))


def _handler(queue: AlertQueue, secret: str,
             on_new: Callable[[], None]) -> type[BaseHTTPRequestHandler]:
    expected = secret.encode()

    class Handler(BaseHTTPRequestHandler):
        server_version = "proseth-worker"
        sys_version = ""

        def log_message(self, fmt: str, *args) -> None:  # noqa: D401
            # The default writes every request to stderr. One line per refusal
            # is useful; one per accepted alert is in the queue already.
            return

        def _reply(self, code: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _token(self) -> bytes:
            auth = self.headers.get("Authorization") or ""
            if auth.lower().startswith("bearer "):
                return auth[7:].strip().encode()
            return (self.headers.get("X-Proseth-Token") or "").strip().encode()

        def do_GET(self) -> None:  # noqa: N802
            # Lets whoever is configuring Zabbix prove the port is reachable
            # before writing the media type. Says nothing about this machine.
            if self.path.rstrip("/") == "/health":
                self._reply(200, {"ok": True})
            else:
                self._reply(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            remote = self.client_address[0] if self.client_address else ""
            parts = self.path.split("?", 1)[0].strip("/").split("/")
            if len(parts) != 2 or parts[0] != "alert" or not _SOURCE.match(parts[1]):
                self._reply(404, {"error": "POST to /alert/<source>, for "
                                           "example /alert/zabbix"})
                return
            if not hmac.compare_digest(self._token(), expected):
                log.warning("Alert from %s refused: wrong or missing token", remote)
                self._reply(401, {"error": "token not accepted"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length <= 0 or length > MAX_BODY:
                self._reply(413 if length > MAX_BODY else 400,
                            {"error": f"body must be 1..{MAX_BODY} bytes"})
                return
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                alert_id = queue.put(parts[1], body, remote)
            except OSError as exc:
                log.error("Could not store an alert: %s", exc)
                self._reply(503, {"error": "could not store the alert"})
                return
            on_new()
            self._reply(202, {"queued": alert_id})

    return Handler


class AlertListener:
    """The HTTP listener, on its own threads, never on the agent's loop."""

    def __init__(self, port: int, secret: str, queue: AlertQueue,
                 on_new: Callable[[], None], bind: str = "0.0.0.0"):
        self.server = ThreadingHTTPServer((bind, port),
                                          _handler(queue, secret, on_new))
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       name="alert-listener", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()

