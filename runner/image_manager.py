# runner/image_manager.py
"""Build, validate, and monitor scanner Docker images (local or registry)."""
from __future__ import annotations

import logging
import os
import subprocess
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SCANNERS_DIR = Path(os.environ.get("SCANNERS_DIR", "/scanners"))

_initial_build_done = threading.Event()

IMAGE_SOURCE = os.environ.get("SCANNER_IMAGE_SOURCE", "auto")

SCANNER_CONFIGS = {
    "dependencies": {
        "image": "aegis/scanner-dependencies:latest",
        "registry_image": "ghcr.io/u9u-p/security/dependencies-scanner:latest",
        "dockerfile": "dependencies/Dockerfile",
        "label_key": "io.aegis.security.dependencies-scanner.signature",
        "label_value": "aegis-dependencies-scanner",
    },
    "code_scanning": {
        "image": "aegis/scanner-code-scanning:latest",
        "registry_image": "ghcr.io/u9u-p/security/code-scanning-scanner:latest",
        "dockerfile": "code-scanning/Dockerfile",
        "label_key": "io.aegis.security.code-scanning-scanner.signature",
        "label_value": "aegis-code-scanning-scanner",
    },
    "secrets": {
        "image": "aegis/scanner-secrets:latest",
        "registry_image": "ghcr.io/u9u-p/security/secret-scanner:latest",
        "dockerfile": "secrets/Dockerfile",
        "label_key": "io.aegis.security.secret-scanner.signature",
        "label_value": "aegis-secret-scanner",
    },
    "container_scanning": {
        "image": "aegis/scanner-container:latest",
        "registry_image": "ghcr.io/u9u-p/security/container-scanner:latest",
        "dockerfile": "container/Dockerfile",
        "label_key": "io.aegis.security.container-scanner.signature",
        "label_value": "aegis-container-scanner",
    },
}


def get_image_name(scanner_type: str) -> str:
    config = SCANNER_CONFIGS.get(scanner_type)
    if not config:
        return ""
    return config["image"]


def validate_image(image: str) -> bool:
    """Check that a scanner image exists and has a valid signature label."""
    for config in SCANNER_CONFIGS.values():
        if config["image"] == image:
            return _check_label(image, config["label_key"], config["label_value"])
    return False


def _check_label(image: str, label_key: str, label_value: str) -> bool:
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", f'{{{{index .Config.Labels "{label_key}"}}}}', image],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return False
        return result.stdout.strip() == label_value
    except Exception:
        return False


def _image_exists(image: str) -> bool:
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _pull_image(registry_image: str, local_image: str) -> bool:
    """Pull a scanner image from the registry and retag to the local name."""
    try:
        result = subprocess.run(
            ["docker", "pull", registry_image],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            logger.error("[image-manager] Pull failed for %s:\n%s", registry_image, result.stderr[-500:])
            return False

        if registry_image != local_image:
            subprocess.run(
                ["docker", "tag", registry_image, local_image],
                capture_output=True, timeout=10,
            )

        return True
    except subprocess.TimeoutExpired:
        logger.error("[image-manager] Pull timed out for %s", registry_image)
        return False
    except Exception:
        logger.exception("[image-manager] Unexpected error pulling %s", registry_image)
        return False


def _should_build() -> bool:
    if IMAGE_SOURCE == "local":
        return True
    if IMAGE_SOURCE == "registry":
        return False
    return SCANNERS_DIR.exists()


def _should_pull() -> bool:
    if IMAGE_SOURCE == "registry":
        return True
    if IMAGE_SOURCE == "local":
        return False
    return True


def build_missing_images() -> dict[str, str]:
    """Ensure scanner images are available (build from source or pull from registry)."""
    use_build = _should_build()
    use_pull = _should_pull()
    logger.info("[+] Scanner image source: %s (build=%s pull=%s)", IMAGE_SOURCE, use_build, use_pull)

    if not use_build and not use_pull:
        logger.warning("[!] No image source available (no /scanners/ dir and SCANNER_IMAGE_SOURCE=local)")
        return {t: "unavailable" for t in SCANNER_CONFIGS}

    statuses: dict[str, str] = {}

    for scanner_type, config in SCANNER_CONFIGS.items():
        image = config["image"]

        if _check_label(image, config["label_key"], config["label_value"]):
            logger.info("[✓] %s: ready", image)
            statuses[scanner_type] = "ready"
            continue

        if use_build:
            dockerfile = SCANNERS_DIR / config["dockerfile"]
            if dockerfile.exists():
                logger.info("[+] Building %s ...", image)
                statuses[scanner_type] = "building"

                try:
                    build_timeout = int(os.environ.get("SCANNER_BUILD_TIMEOUT", "1800"))
                    proc = subprocess.Popen(
                        [
                            "docker", "buildx", "build",
                            "--progress=plain",
                            "-t", image,
                            "-f", str(dockerfile),
                            str(SCANNERS_DIR),
                        ],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True,
                        env={**os.environ, "DOCKER_BUILDKIT": "1"},
                    )
                    assert proc.stdout is not None
                    for line in proc.stdout:
                        stripped = line.rstrip()
                        if stripped:
                            logger.info("[build] %s | %s", scanner_type, stripped)
                    exit_code = proc.wait(timeout=build_timeout)

                    if exit_code == 0 and _check_label(image, config["label_key"], config["label_value"]):
                        logger.info("[✓] %s: built and verified", image)
                        statuses[scanner_type] = "ready"
                        continue

                    if exit_code != 0:
                        logger.error("[!] Build failed for %s (exit code %d)", image, exit_code)
                    else:
                        logger.error("[!] %s: built but label validation failed", image)

                except subprocess.TimeoutExpired:
                    logger.error("[!] Build timed out for %s (limit: %ds)", image, build_timeout)
                    proc.kill()
                    proc.wait()
                except Exception:
                    logger.exception("[!] Unexpected error building %s", image)

                if not use_pull:
                    statuses[scanner_type] = "build_failed"
                    continue

        if use_pull:
            registry_image = config["registry_image"]
            logger.info("[+] Pulling %s ...", registry_image)

            if _pull_image(registry_image, image):
                if _check_label(image, config["label_key"], config["label_value"]):
                    logger.info("[✓] %s: pulled and verified", image)
                    statuses[scanner_type] = "ready"
                else:
                    logger.error("[!] %s: pulled but label validation failed", image)
                    statuses[scanner_type] = "invalid"
            else:
                statuses[scanner_type] = "pull_failed"
            continue

        statuses[scanner_type] = "unavailable"

    _initial_build_done.set()
    return statuses


def check_all_images() -> dict[str, dict[str, Any]]:
    """Return status of all scanner images for heartbeat reporting."""
    source = "local" if SCANNERS_DIR.exists() else "registry"
    result: dict[str, dict[str, Any]] = {}

    for scanner_type, config in SCANNER_CONFIGS.items():
        image = config["image"]
        base = {"image": image, "registryImage": config["registry_image"], "source": source}

        if _check_label(image, config["label_key"], config["label_value"]):
            result[scanner_type] = {**base, "status": "ready", "signature": config["label_value"]}
        elif _image_exists(image):
            result[scanner_type] = {**base, "status": "invalid"}
        else:
            status = "building" if not _initial_build_done.is_set() else "missing"
            result[scanner_type] = {**base, "status": status}

    return result
