# runner/metrics.py
"""Collect system metrics for heartbeat reporting."""
from __future__ import annotations

# Prime CPU sampling so the first collect_metrics() call returns useful data
try:
    import psutil as _psutil
    _psutil.cpu_percent(interval=None)
except ImportError:
    pass


def collect_metrics() -> dict:
    """Return CPU, memory, and disk metrics for the heartbeat payload."""
    try:
        import psutil
    except ImportError:
        return {}

    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    import platform
    return {
        "cpuPercent": cpu,
        "memoryUsedGb": round(mem.used / (1024**3), 2),
        "memoryTotalGb": round(mem.total / (1024**3), 2),
        "diskUsedGb": round(disk.used / (1024**3), 2),
        "diskTotalGb": round(disk.total / (1024**3), 2),
        "cores": psutil.cpu_count(logical=True),
        "os": platform.system().lower(),
        "arch": platform.machine(),
    }
