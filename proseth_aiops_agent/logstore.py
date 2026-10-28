"""The raw logs, kept AT THE SITE - every syslog line and trap the collector
receives, whatever gate 1 decided about it.

The collector still decides alone what becomes an alert (receivers.Filter);
this is the record behind it, for the day someone asks "what did that switch
say just before it went down?". It never leaves the site on its own: the
platform can SEARCH it on demand (job `logsearch`, audited there), and gets only
the matching lines back.

One file per day, `YYYY-MM-DD.jsonl` (one JSON object per line), gzipped once
the day is over - logs compress ~10x. Kept `retention_days` (90), and when the
disk gets tight the OLDEST day goes first, so the newest logs are never the
ones lost. Standard library only.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

STORE: "LogStore | None" = None          # set by the agent; the search job reads it

_DAY = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl(\.gz)?$")


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


class LogStore:
    def __init__(self, root: Path, *, retention_days: int = 90, min_free_gb: float = 2.0,
                 max_gb: float | None = None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)                     # raw logs: the agent's eyes only
        except OSError:
            pass
        self.retention_days, self.min_free_gb, self.max_gb = retention_days, min_free_gb, max_gb
        self._lock = threading.Lock()
        self._fh = None
        self._fh_day = ""
        self.written = 0
        self.evicted_days: list[str] = []                 # removed early for space (shown)
        self._stats: dict = {}
        self.housekeep()

    # ------------------------------------------------------------------ write
    def write(self, ev, now: float | None = None) -> None:
        """One received event. Never raises - a full disk must not stop alerting."""
        now = time.time() if now is None else now
        rec = {"t": round(now, 3), "h": ev.host, "s": ev.source, "p": ev.program or "",
               "l": ev.level, "m": (ev.message or "")[:8000]}
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n"
        try:
            with self._lock:
                day = _day(now)
                if self._fh is None or day != self._fh_day:
                    if self._fh is not None:
                        self._fh.close()
                    self._fh = open(self.root / f"{day}.jsonl", "a", encoding="utf-8")
                    self._fh_day = day
                self._fh.write(line)
                self._fh.flush()
                self.written += 1
        except OSError:
            pass

    # ------------------------------------------------------------ housekeeping
    def _days(self) -> list[tuple[str, Path]]:
        out = []
        for p in self.root.iterdir():
            m = _DAY.match(p.name)
            if m:
                out.append((m.group(1), p))
        return sorted(out)

    def housekeep(self, now: float | None = None) -> dict:
        """Compress finished days, drop days past retention, and - when the disk
        is short or the store is over its cap - the oldest days first."""
        now = time.time() if now is None else now
        today = _day(now)
        cutoff = _day(now - self.retention_days * 86400)
        with self._lock:
            for day, p in self._days():
                if day < cutoff:
                    p.unlink(missing_ok=True)
                elif day < today and p.suffix == ".jsonl":
                    gz = p.with_name(p.name + ".gz")
                    try:
                        with open(p, "rb") as src, gzip.open(gz, "wb", compresslevel=6) as dst:
                            shutil.copyfileobj(src, dst)
                        p.unlink()
                    except OSError:
                        gz.unlink(missing_ok=True)
            while True:
                days = [(d, p) for d, p in self._days() if d < today]
                if not days:
                    break
                total = sum(p.stat().st_size for _, p in self._days())
                free = shutil.disk_usage(self.root).free
                short = free < self.min_free_gb * 1024 ** 3
                over = self.max_gb is not None and total > self.max_gb * 1024 ** 3
                if not (short or over):
                    break
                day, p = days[0]                             # overwrite the oldest
                p.unlink(missing_ok=True)
                self.evicted_days = (self.evicted_days + [day])[-30:]
            files = self._days()
            self._stats = {
                "days": len(files), "bytes": sum(p.stat().st_size for _, p in files),
                "oldest": files[0][0] if files else "", "newest": files[-1][0] if files else "",
                "retention_days": self.retention_days, "evicted_days": list(self.evicted_days),
                "free_gb": round(shutil.disk_usage(self.root).free / 1024 ** 3, 1)}
        return self._stats

    def stats(self) -> dict:
        return {**self._stats, "written": self.written}

    # ----------------------------------------------------------------- search
    def search(self, q: dict, should_stop=lambda: False) -> dict:
        """Newest first. q: since/until (epoch s), host, text (case-insensitive
        substring), regex, program, source, max_level, limit (<= 2000)."""
        since = float(q.get("since") or 0)
        until = float(q.get("until") or time.time() + 60)
        host = (q.get("host") or "").strip()
        text = (q.get("text") or "").lower()
        rx = re.compile(q["regex"], re.IGNORECASE) if q.get("regex") else None
        prog = (q.get("program") or "").lower()
        src = q.get("source") or ""
        lvl = q.get("max_level")
        limit = max(1, min(int(q.get("limit") or 200), 2000))
        budget = time.time() + float(q.get("budget_s") or 25)
        lines: list[dict] = []
        scanned = files = 0
        truncated = False
        first_day, last_day = _day(since) if since else "0000", _day(until)
        with self._lock:
            if self._fh is not None:
                self._fh.flush()
            days = [(d, p) for d, p in self._days() if first_day <= d <= last_day]
        for _day_name, p in reversed(days):
            files += 1
            opener = gzip.open if p.suffix == ".gz" else open
            try:
                with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
                    day_hits = []
                    for raw in fh:
                        scanned += 1
                        if scanned % 5000 == 0 and (time.time() > budget or should_stop()):
                            truncated = True
                            break
                        if text and text not in raw.lower():
                            continue
                        try:
                            r = json.loads(raw)
                        except ValueError:
                            continue
                        if not (since <= r.get("t", 0) <= until):
                            continue
                        if host and host != r.get("h") and host not in str(r.get("h")):
                            continue
                        if prog and prog not in (r.get("p") or "").lower():
                            continue
                        if src and src != r.get("s"):
                            continue
                        if lvl is not None and (r.get("l") is None or r["l"] > int(lvl)):
                            continue
                        if rx is not None and not rx.search(r.get("m") or ""):
                            continue
                        day_hits.append(r)
                    # Within a file the lines are oldest-first; newest first overall.
                    lines.extend(reversed(day_hits))
            except OSError:
                continue
            if len(lines) >= limit or truncated:
                break
        if len(lines) > limit:
            lines, truncated = lines[:limit], True
        return {"ok": True, "lines": lines, "files": files, "scanned": scanned,
                "truncated": truncated, "oldest": days[0][0] if days else ""}


def run_logsearch(payload: dict, emit, should_stop) -> dict:
    """Job handler: search the raw logs kept on this collector."""
    if STORE is None:
        return {"ok": False, "error": "This collector keeps no logs (syslog and traps are off)."}
    try:
        return STORE.search(payload, should_stop)
    except re.error as exc:
        return {"ok": False, "error": f"Invalid regex: {exc}"}
