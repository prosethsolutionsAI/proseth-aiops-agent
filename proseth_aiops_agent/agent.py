"""The Proseth AIOps collector agent.

Runs as a systemd service on a small Ubuntu box inside a customer's network. It
DIALS OUT to the platform, keeps one WebSocket open, and carries out the jobs it
is given from inside that network. Nothing ever connects TO this machine - the
one exception is the optional alert listener (alerts.py), a LAN port the
customer's own monitoring posts to.

Ported from the Proseth Engineer System worker (copied, not shared).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

from . import alerts, facts, logstore, protocol, receivers
from .jobs import EXECUTOR, HANDLERS

# The ONE place the version is written. The installer reads it with sed and it
# goes up in HELLO. Bump it when the agent or installer changes.
VERSION = "1.2.0"

CONFIG_PATH = Path(os.environ.get("AIOPS_AGENT_CONFIG",
                                  "/etc/proseth-aiops-agent/config.json"))
STATE_DIR = Path(os.environ.get("AIOPS_AGENT_STATE", "/var/lib/proseth-aiops-agent"))

log = logging.getLogger("proseth-aiops-agent")
BACKOFF_START, BACKOFF_MAX = 2, 60


def read_config() -> tuple[dict | None, str]:
    try:
        with open(CONFIG_PATH, encoding="utf-8") as h:
            return json.load(h), ""
    except FileNotFoundError:
        return None, f"no configuration at {CONFIG_PATH} - run `sudo proseth-aiops-setup`"
    except PermissionError:
        return None, f"{CONFIG_PATH} is root-only - run this with sudo to read it"
    except (OSError, ValueError) as exc:
        return None, f"could not read {CONFIG_PATH}: {exc}"


def load_config() -> dict:
    config, problem = read_config()
    if config is None:
        log.error("%s", problem[:1].upper() + problem[1:])
        raise SystemExit(78)
    return config


class _Denied(RuntimeError):
    """The platform refused us. Needs a person, not a retry."""


class Agent:
    def __init__(self, config: dict):
        self.host = str(config.get("platform_host") or "").strip()
        self.port = int(config.get("platform_port") or protocol.DEFAULT_AGENT_PORT)
        self.token = str(config.get("token") or "").strip()
        self.name = str(config.get("collector_name") or "").strip()
        self.tls = bool(config.get("tls", True))
        self.verify_tls = bool(config.get("verify_tls", False))
        self.ca_cert = str(config.get("ca_cert") or "").strip()
        self.websocket = None
        self.stopping = asyncio.Event()
        self.cancelled: set[str] = set()
        self.running: set[str] = set()
        self._restarting = False

        self.alert_secret = str(config.get("alert_secret") or "").strip()
        self.alert_port = int(config.get("alert_port") or protocol.DEFAULT_ALERT_PORT)
        self.alert_queue: alerts.AlertQueue | None = None
        self._alert_wake: asyncio.Event | None = None
        # Syslog / SNMP-trap receivers (opt-in at install). 0 = off.
        self.syslog_port = int(config.get("syslog_port") or 0)
        self.trap_port = int(config.get("trap_port") or 0)
        self.trap_communities = {c for c in (config.get("trap_communities") or []) if c}
        self.filter: receivers.Filter | None = None

        if not self.host or not self.token:
            log.error("Configuration is missing the platform address or the token. "
                      "Run: sudo proseth-aiops-setup")
            raise SystemExit(78)

    @property
    def url(self) -> str:
        return f"{'wss' if self.tls else 'ws'}://{self.host}:{self.port}/api/collectors/gateway"

    # -- alert relay --------------------------------------------------------

    def start_alerts(self) -> None:
        """The queue, the webhook listener (if a secret is set) and the
        syslog / trap receivers (if ports are set). Nothing here is fatal."""
        if not (self.alert_secret or self.syslog_port or self.trap_port):
            return
        loop = asyncio.get_running_loop()
        self._alert_wake = asyncio.Event()

        def wake() -> None:
            try:
                loop.call_soon_threadsafe(self._alert_wake.set)
            except RuntimeError:
                pass
        try:
            self.alert_queue = alerts.AlertQueue(STATE_DIR / "alerts")
        except OSError as exc:
            log.error("Alert queue unavailable (%s) - alerts cannot be relayed", exc)
            return
        if self.alert_secret:
            try:
                alerts.AlertListener(self.alert_port, self.alert_secret,
                                     self.alert_queue, wake).start()
                log.info("Accepting webhook alerts on :%s (%s queued)", self.alert_port,
                         self.alert_queue.depth())
            except OSError as exc:
                log.error("Webhook listener could not start on :%s (%s)", self.alert_port, exc)
        if self.syslog_port or self.trap_port:
            self.filter = receivers.Filter(self.alert_queue, wake, STATE_DIR / "rules.json")
            # Every received line is KEPT at the site (90 days, oldest first when
            # the disk is short); the platform can search it on demand.
            try:
                logstore.STORE = logstore.LogStore(STATE_DIR / "logs")
                self.filter.store = logstore.STORE
                threading.Thread(target=self._housekeep, daemon=True, name="logstore").start()
            except OSError as exc:
                log.error("Raw log store unavailable (%s) - alerting continues without it", exc)
            receivers.start(self.filter, syslog_port=self.syslog_port or None,
                            trap_port=self.trap_port or None,
                            communities=self.trap_communities)

    @staticmethod
    def _housekeep() -> None:
        while True:
            time.sleep(3600)
            try:
                if logstore.STORE is not None:
                    logstore.STORE.housekeep()
            except Exception:  # noqa: BLE001 - housekeeping must never stop the agent
                log.exception("log store housekeeping failed")

    async def relay_alerts(self) -> None:
        q = self.alert_queue
        if q is None or self._alert_wake is None:
            return
        q.reset_sent()
        while True:
            for rec in q.due():
                if not await self.send(protocol.ALERT, id=rec["id"],
                                       source=rec.get("source", ""),
                                       payload=rec.get("payload", ""),
                                       remote=rec.get("remote", ""),
                                       received_at=rec.get("received_at")):
                    return
                q.mark_sent(rec["id"])
            self._alert_wake.clear()
            try:
                await asyncio.wait_for(self._alert_wake.wait(), timeout=alerts.RESEND_AFTER)
            except asyncio.TimeoutError:
                pass

    # -- the loop -----------------------------------------------------------

    async def run(self) -> None:
        self.start_alerts()
        backoff = BACKOFF_START
        while not self.stopping.is_set():
            try:
                await self.session()
                backoff = BACKOFF_START
            except _Denied as exc:
                log.error("The platform refused this collector: %s", exc)
                log.error("Fix the token with `sudo proseth-aiops-setup`, then: "
                          "sudo systemctl restart proseth-aiops-agent")
                backoff = BACKOFF_MAX
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                log.warning("Disconnected from %s:%s (%s). Retrying in %ss.",
                            self.host, self.port, exc, backoff)
            if self.stopping.is_set():
                break
            try:
                await asyncio.wait_for(self.stopping.wait(), timeout=backoff)
            except asyncio.TimeoutError:
                pass
            backoff = min(BACKOFF_MAX, backoff * 2)

    async def session(self) -> None:
        import websockets  # noqa: PLC0415

        ssl_context = None
        if self.tls:
            import ssl  # noqa: PLC0415
            ssl_context = ssl.create_default_context()
            if self.ca_cert:
                # PINNED: trust only the platform's own CA (fetched at install).
                # The chain is verified; the name is not, because the platform is
                # reached by IP - public or private - and a CA only this platform
                # holds is what authenticates it.
                try:
                    ssl_context = ssl.create_default_context(cafile=self.ca_cert)
                except OSError as exc:
                    log.error("Could not read the platform CA at %s: %s", self.ca_cert, exc)
                    raise SystemExit(78) from exc
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_REQUIRED
            elif not self.verify_tls:
                log.warning("TLS without a pinned CA: encrypted, NOT authenticated. "
                            "Re-run `sudo proseth-aiops-setup` to fetch the CA.")
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

        log.info("Connecting to %s", self.url)
        async with websockets.connect(self.url, ssl=ssl_context, ping_interval=30,
                                      ping_timeout=30, close_timeout=5,
                                      max_size=32 * 1024 * 1024) as socket:
            self.websocket = socket
            await self.send(protocol.HELLO, token=self.token, version=VERSION,
                            protocol=protocol.PROTOCOL_VERSION, name=self.name,
                            facts=facts.collect())
            raw = await asyncio.wait_for(socket.recv(), timeout=20)
            frame = protocol.parse(raw)
            if frame.get("t") == protocol.DENIED:
                raise _Denied(frame.get("reason") or "no reason given")
            if frame.get("t") != protocol.WELCOME:
                raise RuntimeError(f"Unexpected first frame: {frame.get('t')}")
            log.info("Connected as '%s' (collector %s)",
                     frame.get("name") or self.name, frame.get("collector_id"))
            interval = int(frame.get("heartbeat") or protocol.HEARTBEAT_SECONDS)
            beat = asyncio.create_task(self.heartbeat(interval))
            relay = asyncio.create_task(self.relay_alerts())
            try:
                async for raw in socket:
                    await self.handle(protocol.parse(raw))
            finally:
                beat.cancel()
                relay.cancel()
                self.websocket = None

    async def heartbeat(self, interval: int) -> None:
        while True:
            await asyncio.sleep(interval)
            payload = await asyncio.get_running_loop().run_in_executor(None, facts.collect)
            if not await self.send(protocol.HEARTBEAT, facts=payload, ingest=self.ingest()):
                return

    def ingest(self) -> dict:
        """What the receivers saw: received / dropped / suppressed / forwarded."""
        out = self.filter.snapshot() if self.filter is not None else {}
        out["listening"] = {"webhook": bool(self.alert_secret), "syslog": self.syslog_port,
                            "trap": self.trap_port}
        out["queued"] = self.alert_queue.depth() if self.alert_queue is not None else 0
        if logstore.STORE is not None:
            out["logstore"] = logstore.STORE.stats()
        return out

    async def send(self, kind: str, **fields) -> bool:
        socket = self.websocket
        if socket is None:
            return False
        try:
            await socket.send(protocol.frame(kind, **fields))
            return True
        except Exception:  # noqa: BLE001
            return False

    async def handle(self, frame: dict) -> None:
        kind = frame.get("t")
        if kind == protocol.PING:
            await self.send(protocol.PONG, ts=frame.get("ts"))
        elif kind == protocol.JOB:
            asyncio.create_task(self.run_job(frame))
        elif kind == protocol.CANCEL:
            job_id = str(frame.get("job") or "")
            if job_id in self.running:
                self.cancelled.add(job_id)
        elif kind == protocol.ALERT_ACK:
            if self.alert_queue is not None:
                self.alert_queue.ack(str(frame.get("id") or ""))
        elif kind == protocol.CONFIG:
            if self.filter is not None:
                self.filter.set_rules(frame)
        elif kind == protocol.RESTART:
            log.info("Restart requested - exiting for systemd to bring us back")
            self._restarting = True
            self.stop()
        elif kind == protocol.UPGRADE:
            await self.upgrade()
        elif kind == protocol.DENIED:
            raise _Denied(frame.get("reason") or "no reason given")

    async def upgrade(self) -> None:
        """Run the updater (installed by install.sh, granted one sudoers line)."""
        import asyncio.subprocess  # noqa: PLC0415
        log.info("Upgrade requested")
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo", "-n", "/usr/local/sbin/proseth-aiops-selfupdate",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            out, _ = await proc.communicate()
            text = (out or b"").decode("utf-8", "replace")[-400:]
            if proc.returncode == 0:
                log.info("Upgrade started; the service will restart")
            else:
                log.error("Upgrade failed (exit %s): %s", proc.returncode, text)
                await self.send(protocol.HEARTBEAT, facts=facts.collect(),
                                upgrade_error=text)
        except OSError as exc:
            log.error("Could not start the upgrade: %s", exc)

    async def run_job(self, frame: dict) -> None:
        job_id = str(frame.get("job") or "")
        kind = str(frame.get("kind") or "")
        payload = frame.get("payload") or {}
        handler = HANDLERS.get(kind)
        if handler is None:
            await self.send(protocol.RESULT, job=job_id, result={
                "ok": False, "error": f"This collector does not know the job kind "
                f"'{kind}'. It is probably older than the platform - upgrade it."})
            return
        self.running.add(job_id)
        loop = asyncio.get_running_loop()

        def emit(stream: str, text: str) -> None:
            try:
                asyncio.run_coroutine_threadsafe(
                    self.send(protocol.OUTPUT, job=job_id, stream=stream, text=text), loop)
            except RuntimeError:
                pass

        def should_stop() -> bool:
            return job_id in self.cancelled or self.stopping.is_set()

        log.info("Job %s: %s", job_id, kind)
        try:
            result = await loop.run_in_executor(EXECUTOR, handler, payload, emit, should_stop)
        except Exception as exc:  # noqa: BLE001
            log.exception("Job %s raised", job_id)
            result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        finally:
            self.running.discard(job_id)
            self.cancelled.discard(job_id)
        await self.send(protocol.RESULT, job=job_id, result=result or {})

    def stop(self) -> None:
        self.stopping.set()
        socket = self.websocket
        if socket is not None:
            try:
                asyncio.create_task(socket.close())
            except RuntimeError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(prog="proseth-aiops-agent")
    parser.add_argument("--config")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--alert-secret", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)-8s %(message)s")
    if args.config:
        global CONFIG_PATH
        CONFIG_PATH = Path(args.config)

    if args.check:
        info = facts.collect()
        print(f"proseth-aiops-agent {VERSION}")
        print(f"  host    : {info.get('hostname')}   {info.get('distro')}")
        config, problem = read_config()
        if config is None:
            print(f"  config  : {problem}")
        else:
            print(f"  collector: {config.get('collector_name')}")
            print(f"  connects : {config.get('platform_host')}:{config.get('platform_port')}"
                  + ("  (TLS)" if config.get("tls", True) else ""))
            print(f"  token    : {'set' if config.get('token') else 'MISSING'}")
            print(f"  alerts   : {'on :' + str(config.get('alert_port') or protocol.DEFAULT_ALERT_PORT) if config.get('alert_secret') else 'off'}")
        return 0

    if args.alert_secret:
        config, problem = read_config()
        if config is None:
            print(problem)
            return 1
        secret = config.get("alert_secret") or ""
        print(secret or "Alert intake is off. Turn it on: sudo proseth-aiops-setup")
        return 0 if secret else 1

    agent = Agent(load_config())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, agent.stop)
        except NotImplementedError:
            pass
    log.info("proseth-aiops-agent %s starting", VERSION)
    try:
        loop.run_until_complete(agent.run())
    except KeyboardInterrupt:
        pass
    finally:
        EXECUTOR.shutdown(wait=False)
        loop.close()
    if getattr(agent, "_restarting", False):
        os._exit(75)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
