"""What a collector does: reach a machine inside the customer network and run
ONE diagnostic or fix, streaming the output back.

Ported from the Proseth Engineer System worker (copied, trimmed to what AIOps
needs: ssh, winrm, a read-only network CLI, probe, and a shell on the collector
itself - no ansible/terraform/discover). The platform decides WHAT runs and
whether a change is allowed; this decides nothing.

Rules every handler keeps: stream don't collect; never echo a secret; never
invent a target; a cancelled job stops.
"""
from __future__ import annotations

import io
import os
import subprocess
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

Emit = Callable[[str, str], None]
ShouldStop = Callable[[], bool]

EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="job")
CAPTURE_PREFIX = "PROSETH_CAPTURE:"


def _harvest(line: str, captures: dict) -> bool:
    s = line.strip()
    if not s.startswith(CAPTURE_PREFIX):
        return False
    name, _, value = s[len(CAPTURE_PREFIX):].partition("=")
    if name.strip():
        captures[name.strip()] = value.strip()
    return True


def _auth_hint(target: dict) -> str:
    who, where = target.get("username") or "that account", target.get("address")
    if target.get("private_key"):
        return (f"{where} refused the key for '{who}'. Check the public half is in "
                "that user's authorized_keys.")
    return (f"{where} refused the password for '{who}'. Check the username and that "
            "sshd allows password authentication.")


# --------------------------------------------------------------------- shell

def run_shell(payload: dict, emit: Emit, should_stop: ShouldStop) -> dict:
    """A bash script on the collector itself (built-in checks, discovery)."""
    script = payload.get("script") or ""
    if not script.strip():
        return {"ok": False, "error": "No script was supplied."}
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False,
                                     encoding="utf-8") as h:
        h.write(script)
        path = h.name
    try:
        os.chmod(path, 0o700)
        proc = subprocess.Popen(["/bin/bash", path], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                errors="replace", bufsize=1)
        started = time.monotonic()
        timeout = int(payload.get("timeout") or 900)
        for line in proc.stdout:  # type: ignore[union-attr]
            emit("stdout", line.rstrip("\r\n"))
            if should_stop():
                proc.kill()
                return {"ok": False, "error": "Cancelled."}
            if time.monotonic() - started > timeout:
                proc.kill()
                return {"ok": False, "error": f"Timed out after {timeout}s."}
        proc.wait(timeout=30)
        code = proc.returncode or 0
        return {"ok": code == 0, "exit_code": code,
                "error": "" if code == 0 else f"Exited with {code}."}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# ----------------------------------------------------------------------- ssh

def _ssh_client(target: dict):
    import paramiko  # noqa: PLC0415

    address = str(target.get("address") or "").strip()
    if not address:
        raise ValueError("The job did not say which host to connect to.")
    pkey = None
    if target.get("private_key"):
        last = None
        for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
            try:
                pkey = cls.from_private_key(io.StringIO(target["private_key"]),
                                            password=target.get("passphrase") or None)
                break
            except Exception as exc:  # noqa: BLE001
                last = exc
        if pkey is None:
            raise ValueError(f"That private key could not be read ({last}).")
    client = paramiko.SSHClient()
    # Trust on first use: the collector is INSIDE the customer network, and a
    # management LAN with no recorded host keys would otherwise refuse everything.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=address, port=int(target.get("port") or 22),
                   username=target.get("username") or "",
                   password=target.get("password") or None, pkey=pkey,
                   timeout=20, banner_timeout=20, auth_timeout=20,
                   look_for_keys=False, allow_agent=False)
    return client


def run_ssh(payload: dict, emit: Emit, should_stop: ShouldStop) -> dict:
    """Pipe a script into bash on a remote host. Nothing is left on the target."""
    import paramiko  # noqa: PLC0415

    target = payload.get("target") or {}
    script = payload.get("script") or ""
    if not script.strip():
        return {"ok": False, "error": "No script was supplied."}
    captures: dict[str, str] = {}
    try:
        client = _ssh_client(target)
    except paramiko.AuthenticationException:
        return {"ok": False, "error": _auth_hint(target)}
    except (paramiko.SSHException, OSError) as exc:
        return {"ok": False, "error":
                f"Could not reach {target.get('address')} from this collector: {exc}"}
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    timeout = int(payload.get("timeout") or 900)
    try:
        chan = client.get_transport().open_session()
        chan.settimeout(timeout)
        chan.set_combine_stderr(True)
        chan.exec_command("bash -s")
        chan.sendall(script.encode("utf-8"))
        chan.shutdown_write()
        # The deadline is enforced in the loop: the polls below are non-blocking,
        # so settimeout alone never fires on a command that neither prints nor
        # exits - which once wedged the whole executor on a live worker.
        deadline = time.monotonic() + timeout
        buf = b""
        while True:
            if should_stop():
                chan.close()
                return {"ok": False, "error": "Cancelled."}
            if time.monotonic() > deadline:
                chan.close()
                return {"ok": False, "error":
                        f"No output and no exit after {timeout}s - the command is "
                        "still running and was abandoned. Check the host by hand."}
            if chan.recv_ready():
                chunk = chan.recv(8192)
                if not chunk:
                    break
                buf += chunk
                *lines, buf = buf.split(b"\n")
                for raw in lines:
                    line = raw.decode("utf-8", "replace").rstrip("\r")
                    if not _harvest(line, captures):
                        emit("stdout", line)
            elif chan.exit_status_ready():
                break
            else:
                time.sleep(0.05)
        while chan.recv_ready():
            buf += chan.recv(8192)
        for raw in buf.split(b"\n"):
            line = raw.decode("utf-8", "replace").rstrip("\r")
            if line and not _harvest(line, captures):
                emit("stdout", line)
        code = chan.recv_exit_status()
        return {"ok": code == 0, "exit_code": code, "captures": captures,
                "error": "" if code == 0 else f"The script exited with status {code}."}
    finally:
        client.close()


LINUX_FACTS = r"""
echo "hostname=$(hostname -f 2>/dev/null || hostname)"
echo "kernel=$(uname -r)"
. /etc/os-release 2>/dev/null && echo "distro=$NAME" && echo "version=$VERSION_ID"
echo "cpus=$(nproc 2>/dev/null)"
echo "memory_mb=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null)"
echo "disk_free_gb=$(df -BG / 2>/dev/null | awk 'NR==2 {gsub("G","",$4); print $4}')"
echo "docker=$(command -v docker >/dev/null 2>&1 && echo yes || echo no)"
echo "sudo_nopasswd=$(sudo -n true 2>/dev/null && echo yes || echo no)"
"""


def run_probe(payload: dict, emit: Emit, should_stop: ShouldStop) -> dict:
    """Prove a host is reachable FROM THIS COLLECTOR and record what it is."""
    os_type = str((payload.get("target") or {}).get("os_type") or "linux")
    emit("stdout", f"Reaching {(payload.get('target') or {}).get('address')} ...")
    if os_type == "windows":
        collected: list[str] = []
        res = run_winrm({**payload, "script":
                         "@('hostname='+$env:COMPUTERNAME),"
                         "('os='+(Get-CimInstance Win32_OperatingSystem).Caption)"
                         " | ForEach-Object { Write-Output $_ }"},
                        lambda s, t: collected.append(t) or emit(s, t), should_stop)
    else:
        collected = []
        res = run_ssh({**payload, "script": LINUX_FACTS},
                      lambda s, t: collected.append(t) or emit(s, t), should_stop)
    if not res.get("ok"):
        return res
    facts: dict = {}
    for line in collected:
        k, sep, v = line.partition("=")
        if sep and k.strip() and v.strip() and " " not in k.strip():
            facts[k.strip()] = v.strip()
    for k in ("cpus", "memory_mb", "disk_free_gb"):
        if k in facts:
            try:
                facts[k] = int(facts[k])
            except ValueError:
                pass
    return {**res, "facts": facts}


# ------------------------------------------------------------------- netmiko

def run_netmiko(payload: dict, emit: Emit, should_stop: ShouldStop) -> dict:
    """Run READ-ONLY CLI on a network device (show/display). AIOps never pushes
    config from here - a change on a device is proposed as text and a human
    applies it. `mode` is always 'show'."""
    try:
        from netmiko import ConnectHandler  # noqa: PLC0415
    except ImportError:
        return {"ok": False, "error": "netmiko is not installed on this collector."}
    device = payload.get("device") or {}
    commands = payload.get("commands") or []
    if not commands:
        return {"ok": False, "error": "No commands were supplied."}
    params = {"device_type": device.get("driver") or "cisco_ios",
              "host": device.get("address"), "port": int(device.get("port") or 22),
              "username": device.get("username") or "", "password": device.get("password") or "",
              "conn_timeout": 30, "fast_cli": False}
    if not params["host"]:
        return {"ok": False, "error": "The job did not say which device to reach."}
    emit("stdout", f"Connecting to {params['host']} as {params['device_type']}")
    try:
        with ConnectHandler(**params) as conn:
            chunks = []
            for command in commands:
                if should_stop():
                    return {"ok": False, "error": "Cancelled."}
                text = conn.send_command(command, read_timeout=120)
                chunks.append(text or "")
                for line in (text or "").splitlines():
                    emit("stdout", line)
            return {"ok": True, "output": "\n".join(chunks)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}",
                "hint": "Check the device is reachable from this collector and the "
                        "credentials are right."}


# --------------------------------------------------------------------- winrm

_PS_BOOTSTRAP = ("$ErrorActionPreference='Stop';"
                 "$b=[Console]::In.ReadToEnd();"
                 "$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b.Trim()));"
                 "& ([ScriptBlock]::Create($s))")


def _winrm_session(target: dict):
    try:
        from winrm.protocol import Protocol  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError("pywinrm is not installed on this collector.") from exc
    address = str(target.get("address") or "").strip()
    if not address:
        raise ValueError("The job did not say which host to connect to.")
    if not target.get("password"):
        raise ValueError("Windows hosts need a password - WinRM has no key login.")
    port = int(target.get("port") or 5985)
    https = port == 5986 or bool(target.get("https"))
    user, domain = str(target.get("username") or ""), str(target.get("domain") or "")
    if domain and "\\" not in user and "@" not in user:
        user = f"{domain}\\{user}"
    return Protocol(endpoint=f"{'https' if https else 'http'}://{address}:{port}/wsman",
                    transport="ntlm", username=user, password=target.get("password"),
                    server_cert_validation="ignore", message_encryption="auto",
                    read_timeout_sec=70, operation_timeout_sec=60), user


def _clixml_errors(raw: str) -> list[str]:
    import re  # noqa: PLC0415
    if "#< CLIXML" not in raw:
        return [l for l in raw.splitlines() if l.strip()]
    out = []
    for m in re.finditer(r'<S S="Error">(.*?)</S>', raw, re.S):
        text = (m.group(1).replace("_x000D_", "").replace("_x000A_", "\n")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&"))
        out.extend(t for t in text.splitlines() if t.strip())
    return out


def run_winrm(payload: dict, emit: Emit, should_stop: ShouldStop) -> dict:
    """Run a PowerShell script on a Windows host, script on stdin as base64."""
    import base64  # noqa: PLC0415

    target = payload.get("target") or {}
    script = payload.get("script") or ""
    if not script.strip():
        return {"ok": False, "error": "No script was supplied."}
    timeout = int(payload.get("timeout") or 900)
    try:
        proto, _ = _winrm_session(target)
    except (RuntimeError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}
    captures: dict[str, str] = {}
    shell_id = command_id = None
    try:
        shell_id = proto.open_shell(codepage=65001, noprofile=True)
        command_id = proto.run_command(
            shell_id, "powershell.exe",
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand",
             base64.b64encode(_PS_BOOTSTRAP.encode("utf-16-le")).decode("ascii")])
        body = base64.b64encode(script.encode("utf-8"))
        chunk = 96 * 1024
        for i in range(0, len(body), chunk):
            proto.send_command_input(shell_id, command_id, body[i:i + chunk],
                                     end=i + chunk >= len(body))
        poll = getattr(proto, "get_command_output_raw", None) or \
            getattr(proto, "_raw_get_command_output")
        deadline = time.monotonic() + timeout
        buf, errbuf, code, done = "", "", 0, False
        while not done:
            if should_stop():
                return {"ok": False, "error": "Cancelled."}
            if time.monotonic() > deadline:
                return {"ok": False, "error": f"No exit after {timeout}s - abandoned."}
            try:
                out, err, code, done = poll(shell_id, command_id)
            except Exception as exc:  # noqa: BLE001
                if "OperationTimeout" in type(exc).__name__ or "2150858793" in str(exc):
                    continue
                raise
            buf += out.decode("utf-8", "replace")
            errbuf += err.decode("utf-8", "replace")
            *lines, buf = buf.split("\n")
            for line in lines:
                line = line.rstrip("\r")
                if not _harvest(line, captures):
                    emit("stdout", line)
        for line in buf.splitlines():
            if line.strip() and not _harvest(line, captures):
                emit("stdout", line)
        errors = _clixml_errors(errbuf)
        for line in errors[:40]:
            emit("stdout", f"!! {line}")
        ok = code == 0
        return {"ok": ok, "exit_code": code, "captures": captures,
                "error": "" if ok else (f"{errors[0][:300]} (exit {code})" if errors
                                        else f"Exited with {code}.")}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        try:
            if shell_id and command_id:
                proto.cleanup_command(shell_id, command_id)
            if shell_id:
                proto.close_shell(shell_id)
        except Exception:  # noqa: BLE001
            pass


# ------------------------------------------------------------------- checks
#
# Network checks the platform schedules: many in ONE job, run in parallel, so a
# site with 200 assets is one frame a minute rather than 200. Read-only by
# construction - ping, a TCP connect, an HTTP GET, an SNMP GET.

def _check_ping(c: dict) -> dict:
    t0 = time.monotonic()
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", str(int(c.get("timeout") or 2)),
                            c["target"]], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "message": f"ping could not run: {exc}"}
    ms = round((time.monotonic() - t0) * 1000)
    if r.returncode == 0:
        import re  # noqa: PLC0415
        m = re.search(r"time[=<]([\d.]+)", r.stdout)
        return {"ok": True, "value": float(m.group(1)) if m else ms, "message": "reply"}
    return {"ok": False, "message": "no reply"}


def _check_tcp(c: dict) -> dict:
    import socket  # noqa: PLC0415
    t0 = time.monotonic()
    try:
        with socket.create_connection((c["target"], int(c["port"])), timeout=float(c.get("timeout") or 3)):
            pass
    except OSError as exc:
        return {"ok": False, "message": f"port {c['port']} closed ({exc.__class__.__name__})"}
    return {"ok": True, "value": round((time.monotonic() - t0) * 1000), "message": f"port {c['port']} open"}


def _check_http(c: dict) -> dict:
    import ssl  # noqa: PLC0415
    import urllib.error  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415
    url = c["url"]
    ctx = ssl.create_default_context()
    if not c.get("verify_tls", True):
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    t0 = time.monotonic()
    out: dict = {}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "proseth-aiops-collector"})
        with urllib.request.urlopen(req, timeout=float(c.get("timeout") or 10), context=ctx) as r:
            status = r.status
            body = r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, body = exc.code, ""
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        return {"ok": False, "message": f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"[:300]}
    out["value"] = round((time.monotonic() - t0) * 1000)
    out["status"] = status
    if url.startswith("https://"):
        try:
            import socket  # noqa: PLC0415
            from urllib.parse import urlparse  # noqa: PLC0415
            u = urlparse(url)
            raw_ctx = ssl.create_default_context()
            raw_ctx.check_hostname, raw_ctx.verify_mode = False, ssl.CERT_NONE
            # A second, non-verifying connection: the certificate is read even
            # when it has expired - which is exactly the case worth reporting.
            with socket.create_connection((u.hostname, u.port or 443), timeout=5) as s, \
                    raw_ctx.wrap_socket(s, server_hostname=u.hostname) as ss:
                der = ss.getpeercert(binary_form=True)
        except Exception:  # noqa: BLE001
            der = None
        if der is not None:
            out["cert_days"] = _cert_days(der)
    want = c.get("expect_status") or [200, 201, 202, 204, 301, 302, 303, 307, 308]
    if status not in want:
        return {**out, "ok": False, "message": f"HTTP {status}"}
    if c.get("expect_text") and c["expect_text"] not in body:
        return {**out, "ok": False, "message": f"page does not contain '{c['expect_text']}'"}
    return {**out, "ok": True, "message": f"HTTP {status}"}


def _cert_days(der: bytes) -> int | None:
    """Days until the certificate's notAfter, read straight from the DER."""
    import re  # noqa: PLC0415
    from datetime import datetime, timezone  # noqa: PLC0415
    # notAfter is the second UTCTime/GeneralizedTime in the validity sequence.
    times = re.findall(rb"\x17\x0d(\d{12}Z)|\x18\x0f(\d{14}Z)", der)
    if len(times) < 2:
        return None
    utc, gen = times[1]
    try:
        if utc:
            dt = datetime.strptime(utc.decode(), "%y%m%d%H%M%SZ")
        else:
            dt = datetime.strptime(gen.decode(), "%Y%m%d%H%M%SZ")
    except ValueError:
        return None
    return (dt.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days


def _check_snmp_if(c: dict) -> dict:
    """ifOperStatus for the listed ifIndexes (or a sysUpTime reachability check)."""
    from . import snmp  # noqa: PLC0415
    idx = c.get("if_indexes") or []
    oids = ["1.3.6.1.2.1.1.3.0"] + [f"1.3.6.1.2.1.2.2.1.8.{i}" for i in idx] + \
           [f"1.3.6.1.2.1.2.2.1.2.{i}" for i in idx]
    try:
        vals = snmp.get(c["target"], c.get("community") or "public", oids,
                        port=int(c.get("port") or 161), timeout=float(c.get("timeout") or 3))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "message": f"SNMP did not answer ({type(exc).__name__})"}
    down = []
    for i in idx:
        st = vals.get(f"1.3.6.1.2.1.2.2.1.8.{i}")
        if st and st != "1":
            down.append(vals.get(f"1.3.6.1.2.1.2.2.1.2.{i}") or f"ifIndex {i}")
    uptime = vals.get("1.3.6.1.2.1.1.3.0")
    out = {"uptime_ticks": int(uptime) if uptime and uptime.isdigit() else None}
    if down:
        return {**out, "ok": False, "message": "down: " + ", ".join(down)}
    return {**out, "ok": True, "value": len(idx), "message": f"{len(idx)} interface(s) up"}


_CHECKS = {"ping": _check_ping, "tcp": _check_tcp, "http": _check_http, "snmp_if": _check_snmp_if}


def run_checks(payload: dict, emit: Emit, should_stop: ShouldStop) -> dict:
    checks = payload.get("checks") or []
    results: list[dict] = []

    def one(c: dict) -> dict:
        fn = _CHECKS.get(c.get("kind", ""))
        if fn is None:
            return {"id": c.get("id"), "ok": False, "message": f"unknown check '{c.get('kind')}'"}
        try:
            return {"id": c.get("id"), **fn(c)}
        except Exception as exc:  # noqa: BLE001
            return {"id": c.get("id"), "ok": False, "message": f"{type(exc).__name__}: {exc}"[:300]}

    with ThreadPoolExecutor(max_workers=min(32, max(1, len(checks)))) as pool:
        for r in pool.map(one, checks):
            results.append(r)
    return {"ok": True, "results": results}


def run_logsearch(payload: dict, emit: Emit, should_stop: ShouldStop) -> dict:
    from .logstore import run_logsearch as _search  # noqa: PLC0415
    return _search(payload, emit, should_stop)


HANDLERS = {"shell": run_shell, "ssh": run_ssh, "winrm": run_winrm,
            "netmiko": run_netmiko, "probe": run_probe, "checks": run_checks,
            "logsearch": run_logsearch}
