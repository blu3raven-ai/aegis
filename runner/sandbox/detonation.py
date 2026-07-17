"""Detonate an untrusted entry flow and capture its egress attempts.

Runs the target on the egress-denied ``--internal`` detonation network with the
honeypot sidecar as its DNS resolver and TCP catch-all. The honeypot logs every
outbound attempt the target makes; nothing reaches the internet (the network has
no route off-box). Any captured event is behavior a benign local setup/skill
never produces — a reverse shell's connect, a DNS-delivered payload's lookup.

The argv builders and log collection here are pure/unit-tested; ``detonate`` is
the thin real-container orchestration (create net → honeypot → target → collect
→ teardown), which only runs under a live runtime.
"""
from __future__ import annotations

import logging
import os
import threading

from runner.sandbox.harness import (
    SandboxLimits,
    build_run_args,
    container_cli,
    docker_cli_env,
    runtime_available,
)
from runner.sandbox.honeypot import EgressEvent, parse_egress_log
from runner.sandbox.network import internal_network
from runner.scanners._subprocess import run_tool

logger = logging.getLogger(__name__)

_CATCH_PORT = 8888
_INSPECT_TIMEOUT_S = 15.0
_START_TIMEOUT_S = 30.0
# The embedded honeypot image. The ``localhost/`` prefix keeps podman from ever
# treating it as a remote ref to pull — it must resolve from the local store.
_HONEYPOT_LOCAL_TAG = "localhost/aegis-honeypot:embedded"
# CI bakes the honeypot OCI archive here; the runner loads it at startup (no pull).
_DEFAULT_HONEYPOT_ARCHIVE = "/opt/aegis-honeypot/image.tar"
_HONEYPOT_BUILD_TIMEOUT_S = 600.0
_HONEYPOT_LOAD_TIMEOUT_S = 180.0
_HONEYPOT_PROBE_TIMEOUT_S = 60.0
_honeypot_lock = threading.Lock()
_honeypot_ready: bool | None = None  # None = untried; cached bool after first probe
# Redirect ALL of the target's outbound TCP to the honeypot's single catch port,
# so a reverse shell to any port lands on the logger. UDP/53 (DNS) is untouched
# and still reaches the resolver. Runs inside the trusted honeypot only.
_HONEYPOT_CMD = (
    "sh", "-c",
    "iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port "
    f"{_CATCH_PORT} && HONEYPOT_SELF_IP=$(hostname -i) "
    "exec python -m runner.sandbox.honeypot",
)


def honeypot_image() -> str:
    """The trusted honeypot image ref. An explicit ``HONEYPOT_IMAGE`` (a pinned
    mirror or pre-loaded tag) wins; otherwise the locally-built embedded honeypot,
    which ``ensure_honeypot_image`` builds on demand. The runner's own image is no
    longer the default: it lives in a (usually private) registry the embedded
    rootless podman has no store entry or credentials for, so pointing detonation
    at it silently failed the honeypot pull."""
    return (os.environ.get("HONEYPOT_IMAGE") or "").strip() or _HONEYPOT_LOCAL_TAG


def _image_present(image: str) -> bool:
    """True if ``image`` is already in the local store. ``image inspect`` works on
    both podman and docker (unlike ``image exists``), keeping the dev path portable."""
    try:
        code, _out, _err = run_tool(
            [container_cli(), "image", "inspect", image], timeout=_INSPECT_TIMEOUT_S, env=docker_cli_env()
        )
    except Exception:  # noqa: BLE001
        return False
    return code == 0


def _honeypot_archive_path() -> str:
    return (os.environ.get("HONEYPOT_ARCHIVE") or _DEFAULT_HONEYPOT_ARCHIVE).strip()


def _load_honeypot_archive(archive: str) -> bool:
    """Load the baked OCI archive into the local store (airgap path — no pull)."""
    try:
        code, _out, _err = run_tool(
            [container_cli(), "load", "-i", archive], timeout=_HONEYPOT_LOAD_TIMEOUT_S, env=docker_cli_env()
        )
    except Exception:  # noqa: BLE001
        logger.warning("[detonation] honeypot archive load errored (%s)", archive, exc_info=True)
        return False
    if code != 0:
        logger.warning("[detonation] honeypot archive load failed (rc=%s, %s)", code, archive)
        return False
    # podman normalises an unqualified tag to localhost/; if the archive's tag did
    # not land as our ref, alias it (best-effort) so downstream runs resolve it.
    if not _image_present(_HONEYPOT_LOCAL_TAG):
        try:
            run_tool(
                [container_cli(), "tag", "aegis-honeypot:embedded", _HONEYPOT_LOCAL_TAG],
                timeout=_INSPECT_TIMEOUT_S, env=docker_cli_env(),
            )
        except Exception:  # noqa: BLE001 — the presence check below is the real gate
            pass
    return _image_present(_HONEYPOT_LOCAL_TAG)


def _build_embedded_honeypot(cancel_event: threading.Event | None) -> bool:
    """Dev fallback: build the honeypot from a public base inside the local runtime
    (the same nested build the target already uses). Used only when the baked
    archive is absent — the shipped runner always has the archive."""
    here = os.path.dirname(os.path.abspath(__file__))   # .../runner/sandbox
    dockerfile = os.path.join(here, "honeypot.Dockerfile")
    context = os.path.dirname(here)                      # the runner package dir
    if not os.path.isfile(dockerfile):
        logger.warning("[detonation] honeypot Dockerfile missing at %s — detonation unavailable", dockerfile)
        return False
    args = [container_cli(), "build", "--file", dockerfile, "--tag", _HONEYPOT_LOCAL_TAG, context]
    try:
        code, _out, _err = run_tool(
            args, timeout=_HONEYPOT_BUILD_TIMEOUT_S, env=docker_cli_env(), cancel_event=cancel_event
        )
    except Exception:  # noqa: BLE001
        logger.warning("[detonation] honeypot build errored — detonation unavailable", exc_info=True)
        return False
    if code != 0:
        logger.warning("[detonation] honeypot build failed (rc=%s) — detonation unavailable", code)
        return False
    return _image_present(_HONEYPOT_LOCAL_TAG)


def _make_honeypot_available(cancel_event: threading.Event | None) -> bool:
    """Get the embedded honeypot image into the local store. Prefer the baked OCI
    archive (airgap, no pull); fall back to building it from a public base when the
    archive is absent (dev). Idempotent — a no-op once the image is present."""
    if _image_present(_HONEYPOT_LOCAL_TAG):
        return True
    archive = _honeypot_archive_path()
    if os.path.isfile(archive) and _load_honeypot_archive(archive):
        return True
    return _build_embedded_honeypot(cancel_event)


def _probe_nested_run(image: str, cancel_event: threading.Event | None) -> bool:
    """Actually start a throwaway container from the honeypot image to prove this
    host can run nested containers. This is the HONEST availability check the old
    ``podman version`` probe lacked: on a host that blocks nested user namespaces
    it fails here, so detonation reports unavailable instead of failing mid-run."""
    args = [container_cli(), "run", "--rm", "--network=none", image, "true"]
    try:
        code, _out, _err = run_tool(
            args, timeout=_HONEYPOT_PROBE_TIMEOUT_S, env=docker_cli_env(), cancel_event=cancel_event
        )
    except Exception:  # noqa: BLE001
        logger.warning(
            "[detonation] nested-run probe errored — detonation unavailable on this host; "
            "static scanning is unaffected", exc_info=True,
        )
        return False
    if code != 0:
        logger.warning(
            "[detonation] nested-run probe failed (rc=%s) — this host blocks nested containers; "
            "detonation unavailable, static scanning is unaffected", code,
        )
        return False
    return True


def ensure_honeypot_image(cancel_event: threading.Event | None = None) -> str | None:
    """Make a runnable honeypot image available and return its ref, or None if it
    cannot be (→ caller graceful-skips detonation). An explicit ``HONEYPOT_IMAGE``
    is trusted as-is. Otherwise the embedded honeypot is provisioned once — loaded
    from the baked archive, or built as a dev fallback — then a real nested run
    verifies the host can actually detonate. The outcome is cached for the process."""
    override = (os.environ.get("HONEYPOT_IMAGE") or "").strip()
    if override:
        return override
    global _honeypot_ready
    with _honeypot_lock:
        if _honeypot_ready is None:
            _honeypot_ready = _make_honeypot_available(cancel_event) and _probe_nested_run(
                _HONEYPOT_LOCAL_TAG, cancel_event
            )
        return _HONEYPOT_LOCAL_TAG if _honeypot_ready else None


def honeypot_run_args(image: str, *, network: str, name: str) -> list[str]:
    """Detached run of the honeypot. It is TRUSTED (our image), so unlike the
    target it gets ``NET_ADMIN`` to install the TCP redirect — but it stays on the
    egress-denied network and forwards nothing."""
    return [
        container_cli(), "run", "-d", "--rm",
        f"--network={network}",
        "--cap-drop=ALL", "--cap-add=NET_ADMIN",  # only what the redirect needs
        "--security-opt=no-new-privileges",
        "--user=0:0",  # root: iptables needs it (paired with NET_ADMIN). Trusted,
                       # ephemeral, egress-denied — the TARGET stays non-root.
        "--name", name,
        image, *_HONEYPOT_CMD,
    ]


def target_run_args(
    image: str, cmd, *, network: str, dns_ip: str, name: str,
    limits: SandboxLimits | None = None, runtime: str | None = None,
) -> list[str]:
    """The untrusted target: every hardened control, resolver pointed at the
    honeypot, on the egress-denied network. Not detached — we run the entry flow
    and wait for it under a timeout."""
    return build_run_args(
        image, cmd, network=network, dns=dns_ip, name=name, limits=limits, runtime=runtime,
    )


def container_ip(name: str, network: str, *, cancel_event: threading.Event | None = None) -> str:
    """The container's address on ``network`` (empty string if not resolvable)."""
    # `index` (not dot access) because our network names contain hyphens, which a
    # Go template cannot address as a map key with `.Networks.<name>`.
    fmt = '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}'
    try:
        code, out, _err = run_tool(
            [container_cli(), "inspect", "-f", fmt, name],
            timeout=_INSPECT_TIMEOUT_S, env=docker_cli_env(), cancel_event=cancel_event,
        )
    except Exception:  # noqa: BLE001
        return ""
    return out.strip() if code == 0 else ""


def collect_egress(honeypot_name: str, *, cancel_event: threading.Event | None = None) -> list[EgressEvent]:
    """Read the honeypot's logged egress attempts. Empty on any failure — a missing
    log means 'observed nothing', never a crash."""
    try:
        code, out, _err = run_tool(
            [container_cli(), "logs", honeypot_name],
            timeout=_INSPECT_TIMEOUT_S, env=docker_cli_env(), cancel_event=cancel_event,
        )
    except Exception:  # noqa: BLE001
        return []
    return parse_egress_log(out) if code == 0 else []


def _remove(name: str) -> None:
    try:
        run_tool([container_cli(), "rm", "-f", name], timeout=_START_TIMEOUT_S, env=docker_cli_env())
    except Exception:  # noqa: BLE001 — teardown never masks the result
        pass


def detonate(
    target_image: str, entry_cmd, *, run_id: str, timeout_s: float = 60.0,
    limits: SandboxLimits | None = None, runtime: str | None = None,
    cancel_event: threading.Event | None = None,
) -> list[EgressEvent] | None:
    """Run ``entry_cmd`` in ``target_image`` on an egress-denied net with the
    honeypot, returning the observed egress attempts. Returns None on any setup
    failure (no runtime, honeypot won't start, no IP) — the caller graceful-skips;
    an empty list means 'ran, observed no egress'."""
    if not runtime_available():
        return None
    hp_image = ensure_honeypot_image(cancel_event=cancel_event)
    if not hp_image:  # honeypot image unavailable / host can't detonate → skip
        return None
    hp_name = f"aegis-deto-hp-{run_id}"
    tgt_name = f"aegis-deto-tgt-{run_id}"
    with internal_network(f"aegis-deto-net-{run_id}", cancel_event=cancel_event) as net:
        if net is None:
            return None
        hp_args = honeypot_run_args(hp_image, network=net, name=hp_name)
        try:
            code, _out, _err = run_tool(hp_args, timeout=_START_TIMEOUT_S, env=docker_cli_env(), cancel_event=cancel_event)
            if code != 0:
                return None
            hp_ip = container_ip(hp_name, net, cancel_event=cancel_event)
            if not hp_ip:
                return None
            tgt_args = target_run_args(
                target_image, entry_cmd, network=net, dns_ip=hp_ip, name=tgt_name,
                limits=limits, runtime=runtime,
            )
            # The target may hang (reverse shell holds the socket) — the timeout is
            # the stop condition, not success. We read the honeypot log regardless.
            try:
                run_tool(tgt_args, timeout=timeout_s, env=docker_cli_env(), cancel_event=cancel_event)
            except Exception:  # noqa: BLE001 — target timeout/kill is expected
                pass
            return collect_egress(hp_name, cancel_event=cancel_event)
        finally:
            _remove(tgt_name)
            _remove(hp_name)
