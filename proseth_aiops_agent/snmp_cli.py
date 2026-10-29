"""SNMPv3 through net-snmp's tools (snmpget / snmpbulkwalk) - the PSCyber collector's way.

The built-in BER code (snmp.py) does v2c with the standard library only; v3's
privacy (AES / DES) is not in the standard library, so a v3 device is polled
with net-snmp. Secrets are never on a command line (any user on the box can
read the process list): each poll writes a private snmp.conf (0600, inside a
0700 temporary directory removed afterwards) and points the tools at it.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

LEVELS = ("noAuthNoPriv", "authNoPriv", "authPriv")
AUTH = ("MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512")
PRIV = ("DES", "AES", "AES-192", "AES-256")
_MISSING = ("No Such Object", "No Such Instance", "No more variables")


def available() -> bool:
    return bool(shutil.which("snmpget") and shutil.which("snmpbulkwalk"))


def _conf(cred: dict, d: str) -> str:
    level = cred.get("level") if cred.get("level") in LEVELS else "authPriv"
    lines = ["mibs :", f"persistentDir {d}", "showMibErrors no", "defVersion 3",
             f"defSecurityName {cred.get('user', '')}", f"defSecurityLevel {level}"]
    if level in ("authNoPriv", "authPriv"):
        lines += [f"defAuthType {cred.get('auth_proto') if cred.get('auth_proto') in AUTH else 'SHA'}",
                  f"defAuthPassphrase {cred.get('auth', '')}"]
    if level == "authPriv":
        lines += [f"defPrivType {cred.get('priv_proto') if cred.get('priv_proto') in PRIV else 'AES'}",
                  f"defPrivPassphrase {cred.get('priv', '')}"]
    return "\n".join(lines) + "\n"


def _parse(text: str) -> dict:
    """net-snmp '-On -Oe -Oq -Ot -Oa -OU' output -> {oid without leading dot: value}."""
    out: dict = {}
    open_str = None
    for line in text.splitlines():
        if open_str is not None:                    # a multi-line string (sysDescr often is)
            closed = line.rstrip().endswith('"')
            out[open_str] = (out[open_str] + " " + line.strip().rstrip('"')).strip()
            if closed:
                open_str = None
            continue
        if not line.startswith("."):
            continue
        oid, _, val = line.partition(" ")
        val = val.strip()
        if any(m in val for m in _MISSING):
            continue
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1]
        elif val.startswith('"'):
            val, open_str = val[1:], oid[1:]
        out[oid[1:]] = val.lstrip(".") if val.startswith(".1.") else val
    return out


class Session:
    """One device, one poll: a private config directory for its length."""

    def __init__(self, host: str, port: int, cred: dict, timeout: float = 2.0):
        self.target = f"udp:{host}:{int(port or 161)}"
        self.timeout = max(1, int(timeout))
        self.dir = tempfile.mkdtemp(prefix="aiops-snmp-")            # 0700
        fd = os.open(os.path.join(self.dir, "snmp.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(_conf(cred, self.dir))
        self.env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SNMPCONFPATH": self.dir, "MIBS": "",
                    "MIBDIRS": self.dir, "HOME": self.dir}

    def close(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def _run(self, tool: str, args: list, timeout: int = 30) -> str:
        cmd = [tool, "-On", "-Oe", "-Oq", "-Ot", "-Oa", "-OU", "-t", str(self.timeout), "-r", "1", self.target, *args]
        p = subprocess.run(cmd, env=self.env, capture_output=True, text=True, timeout=timeout, errors="replace")
        if p.returncode != 0 and not p.stdout.strip():
            err = (p.stderr or "").strip().splitlines()
            raise RuntimeError(why(err[-1] if err else f"{tool} failed"))
        return p.stdout

    def get(self, oids: list[str]) -> dict:
        return _parse(self._run("snmpget", ["." + o.lstrip(".") for o in oids]))

    def walk(self, base: str) -> dict:
        base = base.lstrip(".")
        try:
            out = self._run("snmpbulkwalk", ["-Cr30", "." + base], timeout=60)
        except RuntimeError:
            return {}
        return {k[len(base) + 1:]: v for k, v in _parse(out).items() if k.startswith(base + ".")}


def why(err: str) -> str:
    e = err.lower()
    if "timeout" in e:
        return ("no answer on UDP 161 - check SNMP is enabled for this collector's address, the v3 user matches, "
                "and no firewall blocks it")
    if "authentication" in e or "unknown user" in e:
        return "the device refused the SNMPv3 user or its passwords"
    if "decryption" in e:
        return "the SNMPv3 privacy (encryption) password or protocol does not match the device"
    return err[:250]
