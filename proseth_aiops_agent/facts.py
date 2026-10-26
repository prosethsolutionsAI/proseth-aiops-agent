"""What this machine is, and how hard it is working.

Read straight out of `/proc` rather than through `psutil`, for one reason worth
stating: this agent is installed on somebody else's server, often one that is
already carrying production work. Every dependency is something to install,
something to keep patched, and something that can fail to build on an older
Ubuntu at the exact moment an engineer is trying to get a site online. The whole
of what is needed here is four files and `statvfs`.

The numbers go to the supervisor on every heartbeat, which is what makes the
dashboard able to answer "is this worker healthy enough to run a build on"
before somebody starts one.
"""
from __future__ import annotations

import os
import shutil
import socket
import time

# CPU percentage needs two samples. The first heartbeat after start has nothing
# to compare against, so it reports None rather than a fabricated 0.
_last_cpu: tuple[float, float] | None = None

# Tools a job might need. Reported so the supervisor can say "this worker has no
# terraform" when somebody picks it for a cloud stack, rather than failing three
# minutes into the run.
TOOLS = ("ansible-playbook", "ansible", "terraform", "kubectl", "helm",
         "ssh", "git", "python3")


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def cpu_percent() -> float | None:
    """Busy time since the last call, as a percentage.

    `/proc/stat`'s first line is cumulative jiffies since boot, so a single read
    tells you the average since the machine started - which is never what
    anybody wants. The delta between two reads is the interesting number, and
    since this is called once per heartbeat it works out as a 20-second average.
    """
    global _last_cpu
    line = _read("/proc/stat").split("\n", 1)[0]
    if not line.startswith("cpu "):
        return None
    try:
        values = [float(v) for v in line.split()[1:]]
    except ValueError:
        return None
    if len(values) < 4:
        return None

    total = sum(values)
    # user + nice + system + irq + softirq + steal, i.e. everything but idle
    # and iowait. iowait counts as "not busy" on purpose: a worker blocked on a
    # slow disk is not short of CPU, and reporting it as 90% busy would send
    # somebody looking in the wrong place.
    idle = values[3] + (values[4] if len(values) > 4 else 0.0)

    previous, _last_cpu = _last_cpu, (total, idle)
    if previous is None:
        return None
    total_delta = total - previous[0]
    idle_delta = idle - previous[1]
    if total_delta <= 0:
        return None
    return round(max(0.0, min(100.0, (1 - idle_delta / total_delta) * 100)), 1)


def memory() -> dict:
    """Used memory as the kernel means it - MemAvailable, not free.

    `MemFree` on Linux looks alarming and means very little, because the kernel
    fills spare memory with cache it will give back on demand. `MemAvailable` is
    the kernel's own estimate of what a new process could actually get, and it
    is the number that answers "can this worker run a build".
    """
    info: dict[str, int] = {}
    for line in _read("/proc/meminfo").splitlines():
        key, _, rest = line.partition(":")
        try:
            info[key.strip()] = int(rest.strip().split()[0])  # kB
        except (ValueError, IndexError):
            continue

    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", info.get("MemFree", 0))
    if total <= 0:
        return {}
    used = max(0, total - available)
    return {
        "memory_total_mb": round(total / 1024),
        "memory_available_mb": round(available / 1024),
        "memory_percent": round(used / total * 100, 1),
    }


def disk(path: str = "/") -> dict:
    """Space on the filesystem the work actually happens on.

    Reported against the root by default, because that is where terraform
    providers, container images and Ansible collections land. A worker that has
    run out of room there fails every job with an error that never mentions
    disk.
    """
    try:
        st = os.statvfs(path)
    except OSError:
        return {}
    total = st.f_blocks * st.f_frsize
    # f_bavail, not f_bfree: the blocks reserved for root are not available to
    # the agent, which does not run as root.
    free = st.f_bavail * st.f_frsize
    if total <= 0:
        return {}
    return {
        "disk_total_gb": round(total / 1024 ** 3, 1),
        "disk_free_gb": round(free / 1024 ** 3, 1),
        "disk_percent": round((total - free) / total * 100, 1),
    }


def distro() -> dict:
    out: dict[str, str] = {}
    for line in _read("/etc/os-release").splitlines():
        key, _, value = line.partition("=")
        if key in ("NAME", "VERSION_ID", "PRETTY_NAME", "ID"):
            out[key.lower()] = value.strip().strip('"')
    return out


def tools() -> list[str]:
    """What is installed and on PATH. The basis of "this worker cannot do that"."""
    return [name for name in TOOLS if shutil.which(name)]


def uptime_seconds() -> int | None:
    try:
        return int(float(_read("/proc/uptime").split()[0]))
    except (ValueError, IndexError):
        return None


def job_slots() -> dict:
    """How many jobs are running, out of how many can be.

    ## Why the heartbeat has to carry this

    The heartbeat runs on asyncio's default executor; jobs run on a separate
    four-thread pool. So an agent whose pool is completely wedged goes on
    answering heartbeats, reporting 0.3% CPU and plenty of memory, and shows
    up as a healthy green worker - while every job sent to it queues for ever.

    That happened here: three `ssh` jobs with no wall-clock deadline held the
    pool, and the Supervisor cheerfully dispatched more into a queue nobody
    was draining. The deadline is fixed, but a health signal that cannot
    report "I am full" would let the next cause of the same symptom hide just
    as well.
    """
    from .jobs import EXECUTOR  # noqa: PLC0415 - avoids an import cycle

    busy = len([t for t in getattr(EXECUTOR, "_threads", ()) if t.is_alive()])
    capacity = EXECUTOR._max_workers  # noqa: SLF001 - no public accessor
    queued = EXECUTOR._work_queue.qsize()  # noqa: SLF001
    return {
        # Threads are created lazily, so "alive" counts those ever started -
        # the queue depth is the honest signal that work is backing up.
        "job_threads": busy,
        "job_capacity": capacity,
        "jobs_queued": queued,
    }


def collect() -> dict:
    """One heartbeat's worth of facts."""
    info = distro()
    facts: dict = {
        "hostname": socket.gethostname(),
        "distro": info.get("pretty_name") or info.get("name") or "",
        "distro_id": info.get("id", ""),
        "version": info.get("version_id", ""),
        "cpus": os.cpu_count() or 0,
        "tools": tools(),
        "uptime_seconds": uptime_seconds(),
        "collected_at": time.time(),
    }
    value = cpu_percent()
    if value is not None:
        facts["cpu_percent"] = value
    try:
        facts["load_1"] = round(os.getloadavg()[0], 2)
    except OSError:
        pass
    facts.update(memory())
    facts.update(disk())
    try:
        facts.update(job_slots())
    except Exception:  # noqa: BLE001
        # Never let reporting break the heartbeat: a worker that stops
        # heartbeating looks offline, which is a worse lie than missing a
        # queue depth.
        pass
    return facts
