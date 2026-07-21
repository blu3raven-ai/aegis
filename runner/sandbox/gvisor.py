"""Standalone gVisor (runsc) detonation tier.

Runs the untrusted setup entry under gVisor's userspace kernel with NO container
daemon and NO host Docker socket, so detonation works where nested rootless
podman cannot: Docker Desktop's LinuxKit VM blocks nested multi-ID user
namespaces, which is exactly the environment where the podman tier graceful-skips.

Egress is observed the same way as the podman tier and reuses ``honeypot.py``
verbatim: inside a fresh, routeless network namespace the target's DNS answers
resolve to an in-namespace honeypot, and every outbound TCP is DNAT'd to it. The
honeypot logs each attempt; nothing has a route off-box.

The runtime picture (validated empirically on Docker Desktop arm64):
- ``runsc --rootless`` cannot use gVisor's own netstack (``--network=sandbox``
  downgrades to ``host``), so we pin egress with the OUTER netns's real netfilter
  instead. gVisor's netstack has no iptables NAT, so this is the only workable
  capture path for the rootless standalone runtime.
- The whole flow runs inside ``unshare --net --map-root-user`` so the honeypot +
  netfilter rules live in a throwaway namespace and never touch the runner's own
  networking. This needs only default container caps + ``seccomp=unconfined`` on
  the runner (see docker-compose.yml): no ``--privileged``, no socket.

The argv / OCI / script builders below are pure and unit-tested;
``detonate_gvisor`` is the thin real-namespace orchestration, guarded so ANY
failure returns None and the caller graceful-skips.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import tempfile
import threading
from collections.abc import Sequence

from runner.sandbox.honeypot import EgressEvent, parse_egress_log
from runner.scanners._subprocess import run_tool

logger = logging.getLogger(__name__)

# In-namespace honeypot address. Any non-loopback local address works; 127/8 does
# not, because REDIRECT/DNAT to loopback needs route_localnet, which is read-only
# in a rootless user+net namespace. Placed on lo so it is delivered locally.
_HP_IP = "10.0.0.53"
_DNS_PORT = 53
_TCP_CATCH_PORT = 8888
_PLATFORM = "systrap"  # userspace trap platform; works without KVM
_PROBE_TIMEOUT_S = 30.0


def runsc_binary() -> str:
    """The runsc binary path. Overridable for tests / non-standard installs."""
    return (os.environ.get("RUNSC_BINARY") or "runsc").strip() or "runsc"


def _honeypot_argv() -> list[str]:
    """Launch the reused honeypot as a subprocess (not a container)."""
    return [sys.executable, "-m", "runner.sandbox.honeypot"]


def runsc_do_argv(cmd: Sequence[str], *, network: str = "none") -> list[str]:
    """Standalone ``runsc do`` argv (no bundle), used by the availability probe."""
    return [
        runsc_binary(),
        "--rootless",
        f"--network={network}",
        f"--platform={_PLATFORM}",
        "--ignore-cgroups",
        "do",
        *cmd,
    ]


def runsc_run_argv(bundle_dir: str, container_id: str) -> list[str]:
    """Standalone ``runsc run`` argv for a prepared OCI bundle. ``--network=host``
    shares the (unshared, routeless) netns we set up so the honeypot captures the
    target's egress."""
    return [
        runsc_binary(),
        "--rootless",
        "--network=host",
        f"--platform={_PLATFORM}",
        "--ignore-cgroups",
        "run",
        "--bundle",
        bundle_dir,
        container_id,
    ]


def oci_config(entry_cmd: Sequence[str], *, cwd: str = "/", read_only: bool = True) -> dict:
    """A minimal, hardened OCI runtime spec for the untrusted target.

    No network namespace is declared, so the container shares the caller's netns
    (the routeless one with the honeypot). Root is read-only, caps are dropped,
    scratch is a size-capped tmpfs, the same profile as the docker/podman tier.
    """
    return {
        "ociVersion": "1.0.0",
        "process": {
            "terminal": False,
            "user": {"uid": 65534, "gid": 65534},
            "args": list(entry_cmd),
            "env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME=/tmp",
            ],
            "cwd": cwd,
            "capabilities": {k: [] for k in ("bounding", "effective", "permitted", "inheritable")},
            "noNewPrivileges": True,
            "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
        },
        "root": {"path": "rootfs", "readonly": read_only},
        "hostname": "sandbox",
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {
                "destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
                "options": ["nosuid", "nodev", "rw", "size=64m"],
            },
            {
                "destination": "/dev", "type": "tmpfs", "source": "tmpfs",
                "options": ["nosuid", "size=1m", "mode=755"],
            },
        ],
        "linux": {
            "namespaces": [
                {"type": "pid"}, {"type": "mount"}, {"type": "ipc"}, {"type": "uts"},
            ],
        },
    }


def netns_script(
    *, bundle_dir: str, container_id: str, log_path: str, timeout_s: float,
    hp_ip: str = _HP_IP, tcp_port: int = _TCP_CATCH_PORT, dns_port: int = _DNS_PORT,
) -> str:
    """The shell run INSIDE ``unshare --net --map-root-user``: stand up the
    honeypot on a routeless loopback, pin all target egress to it with netfilter,
    then run the target under runsc and tear down. Never leaves a route off-box:
    the only address is ``hp_ip`` on lo, and DNS answers point back at it."""
    hp = " ".join(_honeypot_argv())
    run = " ".join(runsc_run_argv(bundle_dir, container_id))
    # A default route via lo lets even hardcoded-IP dials reach OUTPUT/nat so the
    # DNAT below rewrites them to the honeypot; without it they fail at routing
    # (still no egress, just unobserved). DNS-resolved dials are captured either way.
    return f"""set -u
ip link set lo up
ip addr add {hp_ip}/32 dev lo 2>/dev/null || true
ip route add default dev lo 2>/dev/null || true
iptables -t nat -A OUTPUT -p tcp -j DNAT --to-destination {hp_ip}:{tcp_port}
iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to-destination {hp_ip}:{dns_port}
HONEYPOT_SELF_IP={hp_ip} {hp} > {log_path} 2>/dev/null &
HP_PID=$!
sleep 1
timeout {int(timeout_s)} {run} >/dev/null 2>&1 || true
kill $HP_PID 2>/dev/null || true
wait $HP_PID 2>/dev/null || true
"""


def unshare_argv(script_path: str) -> list[str]:
    """Run the netns script in a fresh user+net namespace (no privileged needed)."""
    return ["unshare", "--net", "--map-root-user", "sh", script_path]


def _write_resolv_conf(rootfs_dir: str, hp_ip: str = _HP_IP) -> None:
    """Point the target's resolver at the honeypot so name lookups are captured
    and answered (A -> hp_ip), making the follow-up TCP dial land on the catch."""
    etc = os.path.join(rootfs_dir, "etc")
    os.makedirs(etc, exist_ok=True)
    with open(os.path.join(etc, "resolv.conf"), "w") as fh:
        fh.write(f"nameserver {hp_ip}\n")


_available: bool | None = None
_available_lock = threading.Lock()


def runsc_available(cancel_event: "threading.Event | None" = None) -> bool:
    """True iff this host can actually run the standalone gVisor tier: the runsc
    binary executes AND a fresh user+net namespace is creatable. Probed with a
    real ``runsc do`` inside ``unshare`` (the honest end-to-end check, not a
    version string), cached per process. A False result just falls through to the
    podman tier / graceful-skip."""
    global _available
    with _available_lock:
        if _available is None:
            _available = _probe(cancel_event)
        return _available


def _probe(cancel_event: "threading.Event | None") -> bool:
    if not shutil.which(runsc_binary()):
        return False
    probe = " ".join(runsc_do_argv(["true"], network="none"))
    script = f"set -e\nip link set lo up 2>/dev/null || true\n{probe}\n"
    fd, path = tempfile.mkstemp(prefix="aegis-gvisor-probe-", suffix=".sh")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(script)
        code, _out, _err = run_tool(
            unshare_argv(path), timeout=_PROBE_TIMEOUT_S, cancel_event=cancel_event,
        )
    except Exception:  # noqa: BLE001 - unshare/runsc missing or blocked, so unavailable
        logger.info("[detonation] gVisor tier unavailable on this host", exc_info=True)
        return False
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return code == 0


# Baked per-ecosystem base rootfs (extracted base images). The gVisor tier runs
# the setup entry directly against this + the repo overlaid at /app, avoiding the
# nested container build that fails on Docker Desktop. CI bakes these dirs into
# the runner image; absent means the tier graceful-skips.
_BASE_ROOTFS_DIR = "/opt/aegis-rootfs"
_ECOSYSTEM_BASE = {"npm": "npm", "python": "python", "shell": "shell"}


def base_rootfs_dir() -> str:
    return (os.environ.get("AEGIS_BASE_ROOTFS_DIR") or _BASE_ROOTFS_DIR).strip() or _BASE_ROOTFS_DIR


def prepare_rootfs(ecosystem: str, repo_root: str, run_id: str) -> str | None:
    """Materialise a writable rootfs for ``ecosystem`` with the repo at /app, or
    None if the baked base for this ecosystem is absent (tier graceful-skips).

    The setup entry installs its own deps at detonation time (that is the payload
    we want to fire), so no pre-built dependency image is needed, just the base
    interpreter/toolchain plus the repo tree.
    """
    base_name = _ECOSYSTEM_BASE.get(ecosystem)
    if not base_name:
        return None
    base = os.path.join(base_rootfs_dir(), base_name)
    if not os.path.isdir(base):
        return None
    dest = tempfile.mkdtemp(prefix=f"aegis-gvisor-rootfs-{run_id}-")
    try:
        # ponytail: full copy of the base rootfs per detonation. Detonation is
        # triage-gated + opt-in (rare), so simplicity wins; switch to an overlay
        # lowerdir if throughput ever matters.
        shutil.copytree(base, dest, dirs_exist_ok=True, symlinks=True)
        app = os.path.join(dest, "app")
        shutil.copytree(repo_root, app, dirs_exist_ok=True, symlinks=True)
        return dest
    except Exception:  # noqa: BLE001 - any prep failure means skip, never a false verdict
        shutil.rmtree(dest, ignore_errors=True)
        logger.warning("[detonation] gVisor rootfs prep failed for %s", ecosystem, exc_info=True)
        return None


def detonate_gvisor(
    rootfs_dir: str, entry_cmd: Sequence[str], *, run_id: str,
    cwd: str = "/", timeout_s: float = 60.0,
    cancel_event: "threading.Event | None" = None,
) -> list[EgressEvent] | None:
    """Detonate ``entry_cmd`` against ``rootfs_dir`` under standalone gVisor and
    return observed egress attempts. Returns None on ANY setup failure (runtime
    unavailable, namespace/orchestration error) so the caller graceful-skips; an
    empty list means 'ran, observed no egress'.

    ``rootfs_dir`` is a prepared root filesystem (base image extracted + repo
    files in place). We do not build an image here; the gVisor tier avoids the
    nested container build that fails on Docker Desktop.
    """
    if not runsc_available(cancel_event):
        return None
    bundle = tempfile.mkdtemp(prefix=f"aegis-gvisor-{run_id}-")
    log_fd, log_path = tempfile.mkstemp(prefix=f"aegis-gvisor-log-{run_id}-", suffix=".jsonl")
    os.close(log_fd)
    try:
        # runsc expects the bundle's rootfs at <bundle>/rootfs; symlink to avoid a copy.
        os.symlink(os.path.abspath(rootfs_dir), os.path.join(bundle, "rootfs"))
        _write_resolv_conf(rootfs_dir)
        with open(os.path.join(bundle, "config.json"), "w") as fh:
            json.dump(oci_config(entry_cmd, cwd=cwd), fh)
        script = netns_script(
            bundle_dir=bundle, container_id=f"aegis-deto-{run_id}",
            log_path=log_path, timeout_s=timeout_s,
        )
        sfd, spath = tempfile.mkstemp(prefix=f"aegis-gvisor-run-{run_id}-", suffix=".sh")
        try:
            with os.fdopen(sfd, "w") as fh:
                fh.write(script)
            # timeout inside the script bounds the target; add slack for teardown.
            run_tool(
                unshare_argv(spath), timeout=timeout_s + 30.0, cancel_event=cancel_event,
            )
        finally:
            try:
                os.unlink(spath)
            except OSError:
                pass
        with open(log_path) as fh:
            return parse_egress_log(fh.read())
    except Exception:  # noqa: BLE001 - any failure means graceful-skip, never a false verdict
        logger.warning("[detonation] gVisor detonation errored, skipping", exc_info=True)
        return None
    finally:
        shutil.rmtree(bundle, ignore_errors=True)
        try:
            os.unlink(log_path)
        except OSError:
            pass
