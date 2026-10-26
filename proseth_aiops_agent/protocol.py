"""The wire protocol between the platform and a collector agent.

**Copied verbatim into the agent** (agent/proseth_aiops_agent/protocol.py) - the
one file on both sides. Standard library only. Change both together; the
self-test fails if they differ.

The agent DIALS OUT and keeps one WebSocket open; nothing ever connects into a
customer network. Every frame is one JSON object with a `t` field.

  agent -> platform                     platform -> agent
    hello      authenticate               welcome    accepted
    heartbeat  health + facts             ping       latency probe
    pong       latency reply              job        do this
    output     a line of job output       cancel     stop that job
    result     job finished               upgrade    fetch the release, reinstall
    alert      a monitoring alert         restart    exit; systemd brings it back
                                          alert_ack  that alert is STORED
                                          denied     refused (bad token...)

Alerts are stored by the platform BEFORE alert_ack is sent; the agent keeps
its on-disk copy until then, so a crash anywhere loses nothing.
"""
from __future__ import annotations

import json
from typing import Any

PROTOCOL_VERSION = 1
# Deliberately different from the Proseth Engineer System's ports, so both
# agents can live on one machine at a customer without colliding.
DEFAULT_AGENT_PORT = 9443
DEFAULT_ALERT_PORT = 9917
HEARTBEAT_SECONDS = 20
TOKEN_PREFIX = "pax_"

HELLO, HEARTBEAT, PONG, OUTPUT, RESULT, ALERT = (
    "hello", "heartbeat", "pong", "output", "result", "alert")
WELCOME, PING, JOB, CANCEL, UPGRADE, RESTART, ALERT_ACK, DENIED = (
    "welcome", "ping", "job", "cancel", "upgrade", "restart", "alert_ack", "denied")

# Job kinds. Each runs INSIDE the customer network.
JOB_SSH = "ssh"            # a bash script on a Linux host, over SSH
JOB_WINRM = "winrm"        # a PowerShell script on a Windows host, over WinRM
JOB_NETMIKO = "netmiko"    # read-only CLI on a network device
JOB_PROBE = "probe"        # connect + facts
JOB_SHELL = "shell"        # on the collector itself
JOB_KINDS = (JOB_SSH, JOB_WINRM, JOB_NETMIKO, JOB_PROBE, JOB_SHELL)


def frame(frame_type: str, /, **fields: Any) -> str:
    """Positional-only type, so frame(JOB, kind=...) cannot collide with it."""
    return json.dumps({"t": frame_type, **fields}, separators=(",", ":"))


def parse(raw: str | bytes) -> dict:
    """A frame, or {} for anything unreadable. Never raises."""
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) and isinstance(data.get("t"), str) else {}


def split_token(token: str) -> tuple[str, str]:
    """`pax_<public_id>_<secret>` -> (public_id, secret), or ("", "")."""
    text = (token or "").strip()
    if not text.startswith(TOKEN_PREFIX):
        return "", ""
    parts = text[len(TOKEN_PREFIX):].split("_", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return "", ""
    return parts[0], parts[1]


def build_token(public_id: str, secret: str) -> str:
    return f"{TOKEN_PREFIX}{public_id}_{secret}"
