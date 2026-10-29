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
import re
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
    # An API check (1.2.4): method, headers - incl. the Authorization the
    # platform puts in for THIS run only (never stored here) - and a body.
    headers = {"User-Agent": "proseth-aiops-collector", **{str(k): str(v) for k, v in (c.get("headers") or {}).items()}}
    data = c.get("body")
    method = str(c.get("method") or ("POST" if data else "GET")).upper()
    try:
        req = urllib.request.Request(url, headers=headers, method=method,
                                     data=data.encode() if isinstance(data, str) and data else None)
        with urllib.request.urlopen(req, timeout=float(c.get("timeout") or 10), context=ctx) as r:
            status = r.status
            body = r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            body = exc.read(65536).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            body = ""
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


# --- full SNMP poll of a network device (1.2.5) ------------------------------------
# Ported from the PSCyber collector's poller, on this agent's own BER code (no
# net-snmp needed at the site): system info, CPU / memory per vendor, and every
# interface's state, speed, counters and errors. The platform works out rates.

_IF_STATUS = {"1": "up", "2": "down", "3": "testing", "5": "dormant", "6": "notPresent", "7": "lowerLayerDown"}


def _num(v):
    try:
        return float(str(v).split()[0])
    except (TypeError, ValueError, IndexError):
        return None


def _avg(vals) -> float | None:
    xs = [x for x in (_num(v) for v in vals) if x is not None]
    return round(sum(xs) / len(xs), 1) if xs else None


def _snmp_family(oid: str, mib: str) -> str:
    if mib and mib != "auto":
        return mib
    for prefix, fam in (("1.3.6.1.4.1.12356.106.", "fortiswitch"), ("1.3.6.1.4.1.12356.", "fortigate"),
                        ("1.3.6.1.4.1.9.", "cisco"), ("1.3.6.1.4.1.2636.", "juniper"),
                        ("1.3.6.1.4.1.25461.", "paloalto"), ("1.3.6.1.4.1.2011.", "huawei")):
        if oid.startswith(prefix):
            return fam
    return "standard"


def _snmp_vendor(G, W, oid: str, mib: str) -> dict:
    """CPU / memory / disk / sessions: the vendor's own MIB first, then the standard ones."""
    out: dict = {"sources": {}}
    fam = _snmp_family(oid, mib)
    out["family"] = fam

    def fortiswitch():
        b = "1.3.6.1.4.1.12356.106.4.1."
        g = G([b + "2.0", b + "3.0", b + "4.0", b + "5.0", b + "6.0"])
        cpu, mem, cap = _num(g.get(b + "2.0")), _num(g.get(b + "3.0")), _num(g.get(b + "4.0"))
        if cpu is not None:
            out["cpu"], out["sources"]["cpu"] = cpu, "FORTINET-FORTISWITCH-MIB"
        if mem is not None:
            out["mem"] = mem if mem <= 100 else (round(100 * mem / cap, 1) if cap else None)
            if cap:
                out["mem_total"] = int(cap) * 1024
        used, dcap = _num(g.get(b + "5.0")), _num(g.get(b + "6.0"))
        if used is not None and dcap:
            out["disk"] = round(100 * used / dcap, 1)

    if fam == "fortiswitch":
        fortiswitch()
    elif fam == "huawei":
        cpu = [x for x in (_num(v) for v in W("1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5").values()) if x]
        mem = [x for x in (_num(v) for v in W("1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7").values()) if x]
        if cpu:
            out["cpu"], out["sources"]["cpu"] = max(cpu), "HUAWEI-ENTITY-EXTENT-MIB"
        if mem:
            out["mem"], out["sources"]["mem"] = max(mem), "HUAWEI-ENTITY-EXTENT-MIB"
    elif fam == "fortigate":
        b = "1.3.6.1.4.1.12356.101.4.1."
        g = G([b + "3.0", b + "4.0", b + "5.0", b + "6.0", b + "7.0", b + "8.0", b + "1.0", "1.3.6.1.4.1.12356.100.1.1.1.0"])
        cpu, mem = _num(g.get(b + "3.0")), _num(g.get(b + "4.0"))
        if cpu is not None:
            out["cpu"], out["sources"]["cpu"] = cpu, "FORTINET-FORTIGATE-MIB"
        if mem is not None:
            out["mem"], out["sources"]["mem"] = mem, "FORTINET-FORTIGATE-MIB"
            if _num(g.get(b + "5.0")):
                out["mem_total"] = int(_num(g[b + "5.0"])) * 1024
        used, cap = _num(g.get(b + "6.0")), _num(g.get(b + "7.0"))
        if used is not None and cap:
            out["disk"] = round(100 * used / cap, 1)
        if _num(g.get(b + "8.0")) is not None:
            out["sessions"] = int(_num(g[b + "8.0"]))
        out["firmware"] = g.get(b + "1.0") or None
        out["serial"] = g.get("1.3.6.1.4.1.12356.100.1.1.1.0") or None
        if out.get("cpu") is None and out.get("mem") is None:
            fortiswitch()
    elif fam == "cisco":
        cpu = _avg(W("1.3.6.1.4.1.9.9.109.1.1.1.1.8").values()) or _avg(W("1.3.6.1.4.1.9.9.109.1.1.1.1.5").values())
        if cpu is not None:
            out["cpu"], out["sources"]["cpu"] = cpu, "CISCO-PROCESS-MIB"
        used, free = W("1.3.6.1.4.1.9.9.48.1.1.1.5"), W("1.3.6.1.4.1.9.9.48.1.1.1.6")
        u, f_ = _num(used.get("1")), _num(free.get("1"))
        if u is not None and f_ is not None and u + f_ > 0:
            out["mem"], out["sources"]["mem"] = round(100 * u / (u + f_), 1), "CISCO-MEMORY-POOL-MIB"
            out["mem_total"] = int(u + f_)
    elif fam == "juniper":
        cpu = [x for x in (_num(v) for v in W("1.3.6.1.4.1.2636.3.1.13.1.8").values()) if x]
        buf = [x for x in (_num(v) for v in W("1.3.6.1.4.1.2636.3.1.13.1.11").values()) if x]
        if cpu:
            out["cpu"], out["sources"]["cpu"] = max(cpu), "JUNIPER-MIB"
        if buf:
            out["mem"], out["sources"]["mem"] = max(buf), "JUNIPER-MIB"
    elif fam == "paloalto":
        g = G(["1.3.6.1.4.1.25461.2.1.2.3.3.0"])
        if _num(g.get("1.3.6.1.4.1.25461.2.1.2.3.3.0")) is not None:
            out["sessions"] = int(_num(g["1.3.6.1.4.1.25461.2.1.2.3.3.0"]))
    if out.get("cpu") is None:                         # standard: HOST-RESOURCES, then UCD (Linux)
        loads = W("1.3.6.1.2.1.25.3.3.1.2")
        cpu = _avg(loads.values())
        if loads:
            out["cpu_cores"] = len(loads)
        if cpu is None:
            idle = _num(G(["1.3.6.1.4.1.2021.11.11.0"]).get("1.3.6.1.4.1.2021.11.11.0"))
            if idle is not None:
                cpu, out["sources"]["cpu"] = round(100 - idle, 1), "UCD-SNMP-MIB"
        else:
            out["sources"]["cpu"] = "HOST-RESOURCES-MIB"
        out["cpu"] = cpu
    if out.get("mem") is None:
        u = G(["1.3.6.1.4.1.2021.4.5.0", "1.3.6.1.4.1.2021.4.6.0", "1.3.6.1.4.1.2021.4.14.0", "1.3.6.1.4.1.2021.4.15.0"])
        total = _num(u.get("1.3.6.1.4.1.2021.4.5.0"))
        if total:                                      # Linux: used = total - free - buffers - cache
            used = total - sum(_num(u.get(k)) or 0 for k in ("1.3.6.1.4.1.2021.4.6.0", "1.3.6.1.4.1.2021.4.14.0", "1.3.6.1.4.1.2021.4.15.0"))
            out["mem"], out["sources"]["mem"] = round(100 * max(0.0, used) / total, 1), "UCD-SNMP-MIB"
            out["mem_total"] = int(total) * 1024
        else:
            st = W("1.3.6.1.2.1.25.2.3.1")
            for idx in {k.split(".", 1)[1] for k in st if k.startswith("2.")}:
                if st.get(f"2.{idx}") == "1.3.6.1.2.1.25.2.1.2":   # hrStorageRam
                    size, used, unit = _num(st.get(f"5.{idx}")), _num(st.get(f"6.{idx}")), _num(st.get(f"4.{idx}")) or 1
                    if size:
                        out["mem"], out["sources"]["mem"] = round(100 * (used or 0) / size, 1), "HOST-RESOURCES-MIB"
                        out["mem_total"] = int(size * unit)
                    break
    return out


# --- hardware health (1.2.7): temperature, fans, power supplies, modules, UPS ---
# One shape for every vendor: {kind, name, state ok|warning|critical, value, unit}.
# Read from the vendor's own environment MIB where it has one, then the standard
# ENTITY-SENSOR / HOST-RESOURCES / UPS MIBs (ESXi, Linux snmpd, UPS cards). A
# table the device does not have is simply empty - never a failed poll.

_CISCO_ENV = {"1": "ok", "2": "warning", "3": "critical", "4": "critical", "5": None, "6": "critical"}


def _hw_add(out: list, kind: str, name: str, state, value=None, unit: str = "") -> None:
    if state is None or len(out) >= 64:
        return
    out.append({"kind": kind, "name": (name or kind)[:60], "state": state,
                "value": round(value, 1) if isinstance(value, float) else value, "unit": unit})


def _snmp_hardware(W, G, fam: str) -> list:
    hw: list = []

    def rows(base: str) -> dict[str, dict[str, str]]:
        """A table walked once, as {index: {column: value}}."""
        t: dict[str, dict[str, str]] = {}
        for k, v in W(base).items():
            col, _, idx = k.partition(".")
            if idx:
                t.setdefault(idx, {})[col] = v
        return t
    if fam == "cisco":                                          # CISCO-ENVMON-MIB
        for r in rows("1.3.6.1.4.1.9.9.13.1.3.1").values():
            _hw_add(hw, "temp", r.get("2", ""), _CISCO_ENV.get(r.get("6", "")), _num(r.get("3")), "°C")
        for r in rows("1.3.6.1.4.1.9.9.13.1.4.1").values():
            _hw_add(hw, "fan", r.get("2", ""), _CISCO_ENV.get(r.get("3", "")))
        for r in rows("1.3.6.1.4.1.9.9.13.1.5.1").values():
            _hw_add(hw, "psu", r.get("2", ""), _CISCO_ENV.get(r.get("3", "")))
    elif fam in ("fortigate", "fortiswitch"):                   # FORTINET-FORTIGATE-MIB fgHwSensors
        for r in rows("1.3.6.1.4.1.12356.101.4.3.2.1").values():
            nm = r.get("2", "")
            kind = "fan" if "fan" in nm.lower() else "psu" if re.search(r"ps\d|psu|power", nm, re.I) else "temp" if re.search(r"temp|°|dts|cpu", nm, re.I) else "sensor"
            _hw_add(hw, kind, nm, "critical" if r.get("4") == "1" else "ok", _num(r.get("3")), "°C" if kind == "temp" else "")
    elif fam == "juniper":                                      # JUNIPER-MIB jnxOperatingTable
        for r in rows("1.3.6.1.4.1.2636.3.1.13.1").values():
            nm, st = r.get("5", ""), r.get("6", "")
            low = nm.lower()
            kind = "fan" if "fan" in low else "psu" if "power" in low or "pem" in low or "psu" in low else "module"
            state = {"2": "ok", "3": "ok", "5": "warning", "6": "critical", "7": "ok", "4": "warning"}.get(st)
            if kind == "module" and not re.search(r"fpc|routing engine|pic|card|module", low):
                continue
            _hw_add(hw, kind, nm, state)
            t = _num(r.get("7"))
            if t and kind in ("module",) and t > 0:
                _hw_add(hw, "temp", nm, "critical" if t >= 75 else "warning" if t >= 65 else "ok", t, "°C")
    elif fam == "huawei":                                       # HUAWEI-ENTITY-EXTENT-MIB
        temps = W("1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11")
        for idx, v in list(temps.items())[:16]:
            t = _num(v)
            if t and t > 0:
                _hw_add(hw, "temp", f"board {idx}", "critical" if t >= 75 else "warning" if t >= 65 else "ok", t, "°C")
        for idx, v in W("1.3.6.1.4.1.2011.5.25.31.1.1.10.1.7").items():
            _hw_add(hw, "fan", f"fan {idx}", {"1": "ok", "2": "critical"}.get(v))
    if not hw:                                                  # ENTITY-SENSOR-MIB (standard)
        names = {k: v for k, v in W("1.3.6.1.2.1.47.1.1.1.1.7").items()}
        for idx, r in list(rows("1.3.6.1.2.1.99.1.1.1").items())[:64]:
            typ, val, scale, prec, op = r.get("1"), _num(r.get("4")), r.get("2"), _num(r.get("3")) or 0, r.get("5")
            kind = {"8": "temp", "10": "fan", "3": "psu", "4": "psu", "5": "psu", "6": "psu"}.get(typ or "")
            if kind is None:
                continue
            if val is not None and prec:
                val = val / (10 ** prec)
            if val is not None and scale == "8":               # milli
                val = val / 1000
            state = {"1": "ok", "2": "critical", "3": "critical"}.get(op or "", "ok")
            if kind == "temp" and state == "ok" and val is not None:
                state = "critical" if val >= 80 else "warning" if val >= 70 else "ok"
            _hw_add(hw, kind, names.get(idx, f"sensor {idx}"), state, val, "°C" if kind == "temp" else "rpm" if kind == "fan" else "")
    if not hw:                                                  # HOST-RESOURCES hrDevice (ESXi, servers)
        for r in list(rows("1.3.6.1.2.1.25.3.2.1").values())[:48]:
            st = {"2": "ok", "3": "warning", "5": "critical"}.get(r.get("5", ""))
            nm = r.get("3", "")
            if st and st != "ok" or (st == "ok" and re.search(r"power|fan|temp|raid|disk|controller", nm, re.I)):
                _hw_add(hw, "device", nm, st)
    # A UPS: UPS-MIB (RFC 1628), then APC PowerNet.
    ups = G(["1.3.6.1.2.1.33.1.2.1.0", "1.3.6.1.2.1.33.1.2.4.0", "1.3.6.1.2.1.33.1.4.1.0",
             "1.3.6.1.4.1.318.1.1.1.2.1.1.0", "1.3.6.1.4.1.318.1.1.1.2.2.1.0", "1.3.6.1.4.1.318.1.1.1.4.1.1.0"])
    bat, charge, src = ups.get("1.3.6.1.2.1.33.1.2.1.0"), _num(ups.get("1.3.6.1.2.1.33.1.2.4.0")), ups.get("1.3.6.1.2.1.33.1.4.1.0")
    if bat is None and ups.get("1.3.6.1.4.1.318.1.1.1.2.1.1.0") is not None:     # APC: 2 normal, 3 low
        bat = {"2": "2", "3": "3"}.get(ups.get("1.3.6.1.4.1.318.1.1.1.2.1.1.0"), "1")
        charge = _num(ups.get("1.3.6.1.4.1.318.1.1.1.2.2.1.0"))
        src = {"2": "3", "3": "5"}.get(ups.get("1.3.6.1.4.1.318.1.1.1.4.1.1.0") or "", src)
    if bat is not None:
        _hw_add(hw, "battery", "UPS battery", {"2": "ok", "3": "warning", "4": "critical"}.get(bat, "warning"), charge, "%")
    if src is not None:
        _hw_add(hw, "power", "UPS output", "ok" if src == "3" else "critical" if src == "5" else "warning", None, "")
    return hw


def _snmp_interfaces(W, limit: int = 512) -> list:
    t, x = W("1.3.6.1.2.1.2.2.1"), W("1.3.6.1.2.1.31.1.1.1")
    idxs = sorted({int(k.split(".", 1)[1]) for k in t if k.startswith("2.") and k.split(".", 1)[1].isdigit()})[:limit]
    out = []
    for i in idxs:
        hc_in, hc_out = x.get(f"6.{i}"), x.get(f"10.{i}")
        hc = hc_in is not None and hc_out is not None
        high = _num(x.get(f"15.{i}"))
        speed = int(high) if high else (int(_num(t.get(f"5.{i}")) or 0) // 1_000_000) or None

        def iv(v):
            n = _num(v)
            return int(n) if n is not None else None
        out.append({"i": i, "name": x.get(f"1.{i}") or t.get(f"2.{i}") or f"if{i}", "alias": x.get(f"18.{i}") or "",
                    "speed_mbps": speed, "admin": _IF_STATUS.get(t.get(f"7.{i}", ""), t.get(f"7.{i}", "")),
                    "oper": _IF_STATUS.get(t.get(f"8.{i}", ""), t.get(f"8.{i}", "")), "hc": hc,
                    "in": iv(hc_in if hc else t.get(f"10.{i}")), "out": iv(hc_out if hc else t.get(f"16.{i}")),
                    "in_err": iv(t.get(f"14.{i}")), "out_err": iv(t.get(f"20.{i}")), "in_disc": iv(t.get(f"13.{i}"))})
    return out


def _check_snmp_poll(c: dict) -> dict:
    """The whole device: sysDescr/Name/Location/uptime, vendor CPU and memory, every interface."""
    from . import snmp, snmp_cli  # noqa: PLC0415
    host, com = c["target"], c.get("community") or "public"
    port, to = int(c.get("port") or 161), float(c.get("timeout") or 2)
    v3 = c.get("v3")
    sess = None
    if v3:
        # SNMPv3: net-snmp's tools (privacy needs AES, not in the standard library).
        if not snmp_cli.available():
            return {"ok": False, "message": "SNMPv3 needs net-snmp's tools on this collector: run 'sudo apt-get install snmp' "
                                            "(or re-run the installer)"}
        sess = snmp_cli.Session(host, port, v3, to)

    def G(oids):
        try:
            return sess.get(oids) if sess else snmp.get_raw(host, com, oids, port=port, timeout=to)
        except Exception:  # noqa: BLE001 - one missing table must not fail the poll
            return {}

    def W(base):
        try:
            return sess.walk(base) if sess else snmp.walk(host, com, base, port=port, timeout=to)
        except Exception:  # noqa: BLE001
            return {}
    try:
        return _snmp_poll_with(G, W, sess, host, com, port, to, c)
    finally:
        if sess:
            sess.close()


def _snmp_poll_with(G, W, sess, host, com, port, to, c) -> dict:
    from . import snmp  # noqa: PLC0415
    sysd = {"descr": "1.3.6.1.2.1.1.1.0", "object_id": "1.3.6.1.2.1.1.2.0", "uptime": "1.3.6.1.2.1.1.3.0",
            "name": "1.3.6.1.2.1.1.5.0", "location": "1.3.6.1.2.1.1.6.0"}
    try:
        g = sess.get(list(sysd.values())) if sess else snmp.get_raw(host, com, list(sysd.values()), port=port, timeout=to)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "message": (str(exc) if sess else f"SNMP did not answer ({type(exc).__name__}) - check SNMP is on "
                                         "for this collector's address, the community matches and UDP 161 is open")}
    if not g:
        return {"ok": False, "message": "the device answered with no system information"}
    s = {k: g.get(v) for k, v in sysd.items()}
    up = _num(s["uptime"])
    res = {"ok": True, "sys": {"descr": (s["descr"] or "")[:300], "object_id": s["object_id"] or "",
                               "name": s["name"] or "", "location": s["location"] or ""},
           "uptime_s": int(up) // 100 if up is not None else None}
    res.update(_snmp_vendor(G, W, s["object_id"] or "", c.get("mib") or "auto"))
    try:
        res["hw"] = _snmp_hardware(W, G, res.get("family") or "standard")
    except Exception:  # noqa: BLE001 - hardware is extra; it must never fail the poll
        res["hw"] = []
    res["ifaces"] = _snmp_interfaces(W)
    watch = set(c.get("watch") or [])
    down = [f["name"] for f in res["ifaces"] if f["name"] in watch and f["admin"] == "up" and f["oper"] != "up"]
    upn = sum(1 for f in res["ifaces"] if f["oper"] == "up")
    res["value"] = upn
    res["message"] = (f"watched interface(s) down: {', '.join(down)}" if down
                      else f"{upn}/{len(res['ifaces'])} interfaces up")
    res["watch_down"] = down
    return res


def _ping_series(target: str, count: int) -> dict:
    """`count` pings 0.2 s apart: loss %, average latency, jitter (mdev)."""
    import re  # noqa: PLC0415
    try:
        r = subprocess.run(["ping", "-n", "-c", str(count), "-i", "0.2", "-W", "2", target],
                           capture_output=True, text=True, timeout=count * 2 + 10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"target": target, "loss": 100.0, "error": str(exc)}
    m = re.search(r"([\d.]+)% packet loss", r.stdout)
    loss = float(m.group(1)) if m else 100.0
    rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", r.stdout)
    out = {"target": target, "loss": loss}
    if rtt:
        out.update(latency=float(rtt.group(2)), jitter=float(rtt.group(4)))
    return out


def _check_link(c: dict) -> dict:
    """An INTERNET / WAN LINK: several pings to several targets (an ISP's own
    gateway, 1.1.1.1, 8.8.8.8 ...). One public target flaps on its own, so the
    link is judged on its BEST target: down only when NONE answers; latency,
    jitter and loss are the best target's."""
    targets = [t for t in (c.get("targets") or []) if t][:4] or [c.get("target")]
    count = max(3, min(20, int(c.get("count") or 10)))
    series = [_ping_series(t, count) for t in targets if t]
    alive = [s for s in series if s.get("loss", 100) < 100]
    if not alive:
        return {"ok": False, "message": "no reply from " + ", ".join(s["target"] for s in series),
                "loss": 100.0, "targets": series}
    best = min(alive, key=lambda s: (s["loss"], s.get("latency", 1e9)))
    return {"ok": True, "value": best.get("latency"), "loss": best["loss"], "jitter": best.get("jitter"),
            "message": f"{best['target']}: {best.get('latency', 0):.1f} ms, loss {best['loss']:.0f}%, "
                       f"jitter {best.get('jitter', 0):.1f} ms", "targets": series}


_CHECKS = {"ping": _check_ping, "tcp": _check_tcp, "http": _check_http, "snmp_if": _check_snmp_if,
           "link": _check_link, "snmp_poll": _check_snmp_poll}


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
