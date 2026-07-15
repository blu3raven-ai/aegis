"""Build-recipe detection + hardened build invocation for runtime verification."""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from runner.sandbox.build import BuildRecipe, build_image, build_image_args, detect_recipe
from runner.sandbox.harness import docker_cli_env


def _repo(dockerfile: bool = True) -> str:
    d = tempfile.mkdtemp()
    if dockerfile:
        (Path(d) / "Dockerfile").write_text("FROM scratch\n")
    (Path(d) / "app.py").write_text("x = 1\n")
    return d


def test_detect_recipe_finds_dockerfile():
    r = detect_recipe(_repo(dockerfile=True))
    assert r is not None and r.dockerfile.endswith("Dockerfile")


def test_detect_recipe_none_without_dockerfile_so_caller_skips():
    assert detect_recipe(_repo(dockerfile=False)) is None


def test_build_args_pass_file_tag_context_and_no_secret_flags():
    r = BuildRecipe(dockerfile="/repo/Dockerfile", context="/repo")
    a = build_image_args(r, "target:run")
    assert a[:2] == ["docker", "build"]
    assert "--file" in a and "/repo/Dockerfile" in a
    assert "--tag" in a and "target:run" in a
    assert a[-1] == "/repo"                       # context last
    assert "--build-arg" not in a and "--secret" not in a  # no secrets in build


def test_build_image_skips_when_no_recipe():
    # No Dockerfile -> False (skip), and docker is never invoked.
    with patch("runner.sandbox.build.run_tool") as rt:
        ok = build_image(_repo(dockerfile=False), "t")
    assert ok is False
    rt.assert_not_called()


def test_build_image_returns_true_on_zero_exit():
    with patch("runner.sandbox.build.run_tool", return_value=(0, "", "")) as rt:
        ok = build_image(_repo(dockerfile=True), "t", timeout_s=60.0)
    assert ok is True
    assert rt.call_args.kwargs["timeout"] == 60.0


def test_build_image_returns_false_on_build_failure():
    with patch("runner.sandbox.build.run_tool", return_value=(1, "", "boom")):
        assert build_image(_repo(dockerfile=True), "t") is False


def test_docker_cli_env_excludes_secrets_keeps_path():
    with patch.dict("os.environ",
                    {"PATH": "/usr/bin", "DOCKER_HOST": "unix:///x", "GIT_TOKEN": "s", "OPENAI_API_KEY": "s"},
                    clear=True):
        env = docker_cli_env()
    assert env["PATH"] == "/usr/bin" and env["DOCKER_HOST"] == "unix:///x"
    assert "GIT_TOKEN" not in env and "OPENAI_API_KEY" not in env
