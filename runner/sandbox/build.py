"""Best-effort image build for runtime verification. Dockerfile-first: if the repo
has no Dockerfile we return None and the caller GRACEFULLY SKIPS (the finding stays
needs_runtime_verification — no false confidence). Honest and bounded, mirroring
Argo's 'launcher recipe or skip'.

Trust boundary: a build must fetch dependencies, so it CANNOT run with
``--network=none`` (unlike the run phase). The untrusted Dockerfile RUN steps
therefore have network during build — accepted, because the build is wall-clock
capped, passes NO secrets (no --build-arg/--secret), and runs on the ephemeral,
secret-less runner. The RUN phase that serves the app gets the full sandbox.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

from runner.sandbox.harness import docker_cli_env
from runner.scanners._subprocess import run_tool

_DOCKERFILE_NAMES = ("Dockerfile", "dockerfile")
_DEFAULT_BUILD_TIMEOUT_S = 600.0


@dataclass(frozen=True)
class BuildRecipe:
    dockerfile: str  # absolute path
    context: str     # absolute build-context dir


def detect_recipe(repo_root: str) -> BuildRecipe | None:
    """A build recipe iff the repo root has a Dockerfile; else None (skip)."""
    root = Path(repo_root)
    for name in _DOCKERFILE_NAMES:
        p = root / name
        if p.is_file():
            return BuildRecipe(dockerfile=str(p), context=str(root))
    return None


def build_image_args(recipe: BuildRecipe, tag: str) -> list[str]:
    """The ``docker build`` argv. No secrets are passed (no --build-arg/--secret);
    network is intentionally NOT disabled here (deps must fetch)."""
    return ["docker", "build", "--file", recipe.dockerfile, "--tag", tag, recipe.context]


def build_image(
    repo_root: str, tag: str, *,
    timeout_s: float = _DEFAULT_BUILD_TIMEOUT_S,
    cancel_event: threading.Event | None = None,
) -> bool:
    """Build the target image, wall-clock capped. Returns True on success, False on
    no-recipe / build failure / timeout — the caller treats False as 'skip runtime
    verification for this finding', never as a verdict."""
    recipe = detect_recipe(repo_root)
    if recipe is None:
        return False
    args = build_image_args(recipe, tag)
    code, _out, _err = run_tool(args, timeout=timeout_s, env=docker_cli_env(), cancel_event=cancel_event)
    return code == 0
