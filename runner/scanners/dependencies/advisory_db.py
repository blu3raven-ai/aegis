"""Build a custom Grype advisory DB from vunnel-fetched advisories.

Port of the `build_custom_advisory_db` shell function in
scanners/dependencies/run.sh. The behaviour mirrors the bash original:

* If `ADVISORY_PROVIDERS` is unset/empty, do nothing and return None.
* If either `vunnel` or `grype-db` is not on PATH, log a warning and return None.
* For each comma-separated provider, run `vunnel run <provider>` — failures
  are logged and tolerated so a single broken source does not kill the build.
* Compile the DB with `grype-db build`; failure returns None so Grype falls
  back to its built-in DB.
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
import threading
from pathlib import Path

from runner.scanners._subprocess import run_tool

logger = logging.getLogger(__name__)

_VUNNEL_TIMEOUT_S = 600.0
_GRYPE_DB_BUILD_TIMEOUT_S = 600.0


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def build_custom_advisory_db(
    work_dir: Path | None = None,
    *,
    cancel_event: threading.Event | None = None,
) -> Path | None:
    """Build a custom Grype DB from providers listed in `ADVISORY_PROVIDERS`.

    Returns the path to the built `.db` file, or None if no providers were
    configured, required tools are missing, or the build failed.
    """
    providers_raw = os.environ.get("ADVISORY_PROVIDERS", "").strip()
    if not providers_raw:
        return None

    if not _tool_available("vunnel") or not _tool_available("grype-db"):
        logger.warning(
            "[!] vunnel or grype-db not available - skipping custom advisory DB"
        )
        return None

    providers = [p.strip() for p in providers_raw.split(",") if p.strip()]
    if not providers:
        return None

    if work_dir is None:
        work_dir = Path(tempfile.mkdtemp(prefix="vunnel-work."))
    else:
        work_dir = Path(work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)

    data_dir = work_dir / "data"
    build_dir = work_dir / "build"
    data_dir.mkdir(parents=True, exist_ok=True)
    build_dir.mkdir(parents=True, exist_ok=True)

    vunnel_config = work_dir / "vunnel.yaml"
    nvd_api_key = os.environ.get("NVD_API_KEY", "")
    ghsa_api_key = os.environ.get("GHSA_API_KEY", "")
    vunnel_config.write_text(
        "root: {root}\n"
        "providers:\n"
        "  nvd:\n"
        '    api_key: "{nvd}"\n'
        "  github:\n"
        '    token: "{ghsa}"\n'.format(
            root=str(data_dir), nvd=nvd_api_key, ghsa=ghsa_api_key
        )
    )

    logger.info("[+] Building custom advisory DB: providers=%s", ",".join(providers))

    for provider in providers:
        logger.info("[+] Fetching advisories from %s...", provider)
        rc, _, stderr = run_tool(
            ["vunnel", "-c", str(vunnel_config), "run", provider],
            timeout=_VUNNEL_TIMEOUT_S,
            cancel_event=cancel_event,
        )
        if rc == 0:
            logger.info("[+] Fetched: %s", provider)
        else:
            logger.warning(
                "[!] vunnel failed for %s (continuing): %s",
                provider,
                (stderr or "")[:200],
            )

    logger.info("[+] Compiling custom Grype DB...")
    rc, _, stderr = run_tool(
        ["grype-db", "build", "-d", str(build_dir)],
        cwd=data_dir,
        timeout=_GRYPE_DB_BUILD_TIMEOUT_S,
        cancel_event=cancel_event,
    )
    if rc != 0:
        logger.warning(
            "[!] grype-db build failed - continuing with built-in DB: %s",
            (stderr or "")[:200],
        )
        return None

    db_files = sorted(build_dir.rglob("*.db"))
    if not db_files:
        logger.warning("[!] grype-db produced no DB file - continuing with built-in DB")
        return None

    db_path = db_files[0]
    logger.info("[✓] Custom advisory DB ready: %s", db_path)
    return db_path
