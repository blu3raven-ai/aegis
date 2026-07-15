"""The app container must start DETACHED, fully hardened, egress-denied, with no
host port published; readiness must poll until an HTTP response or the cap."""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from runner.sandbox.build import BuildRecipe
from runner.sandbox.runtime_app import detect_port, run_app_args, wait_ready


def test_run_app_args_is_detached_and_hardened():
    a = run_app_args("img:tag", network="net", name="app")
    assert a[1] == "run" and "-d" in a
    assert "--network=net" in a and "--read-only" in a and "--cap-drop=ALL" in a
    assert "--security-opt=no-new-privileges" in a and "--user=65534:65534" in a
    assert "--name" in a and "app" in a
    # No host port is published — the sidecar reaches the app over the internal net.
    assert not any(x == "-p" or x.startswith("--publish") for x in a)
    # App uses its own entrypoint: image is last, no cmd appended after it.
    assert a[-1] == "img:tag"


def _recipe(text: str) -> BuildRecipe:
    d = tempfile.mkdtemp()
    p = Path(d) / "Dockerfile"
    p.write_text(text)
    return BuildRecipe(dockerfile=str(p), context=d)


def test_detect_port_reads_expose():
    assert detect_port(_recipe("FROM x\nEXPOSE 8080\n")) == 8080


def test_detect_port_none_when_no_expose():
    assert detect_port(_recipe("FROM x\nRUN true\n")) is None


def test_wait_ready_true_on_first_http_response():
    with patch("runner.sandbox.runtime_app._probe_once", return_value="404"):
        assert wait_ready("app", 8080, network="net", _sleep=lambda *_: None) is True


def test_wait_ready_times_out_on_no_response():
    clock = {"t": 0.0}

    def now():
        clock["t"] += 0.5
        return clock["t"]

    with patch("runner.sandbox.runtime_app._probe_once", return_value="000"):
        assert wait_ready("app", 8080, network="net", cap_s=2.0,
                          _sleep=lambda *_: None, _now=now) is False


def test_wait_ready_false_on_unknown_port():
    with patch("runner.sandbox.runtime_app._probe_once") as p:
        assert wait_ready("app", 0, network="net") is False
    p.assert_not_called()
