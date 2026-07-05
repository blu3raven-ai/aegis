"""Path-traversal regression guards on static mount + SPA fallback."""
import pytest

from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _restore_main_module():
    """Restore src.main.app to the pre-test instance after each test.

    Tests in this module call reload(src.main) with a temporary STATIC_ROOT,
    which replaces src.main.app with a brand-new FastAPI instance that has
    static mounts + spa_fallback registered.  Without cleanup that new app
    object is visible to later tests that do ``from src.main import app``,
    causing CSRF mismatches and missing middleware.

    Strategy: save the original app object before the test, then point
    src.main.app back to it in teardown so other modules see the original app.
    """
    import src.main
    original_app = src.main.app
    yield
    src.main.app = original_app


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("safe")
    (tmp_path / "secret.txt").write_text("SHOULD NOT BE READABLE")
    monkeypatch.setenv("STATIC_ROOT", str(static_root))
    from importlib import reload
    import src.main
    reload(src.main)
    return TestClient(src.main.app), tmp_path


@pytest.mark.parametrize("path", [
    "../secret.txt", "..%2Fsecret.txt", "%2e%2e/secret.txt",
    "_next/../../secret.txt", "//secret.txt", "..//secret.txt",
    "..\\secret.txt", "....//secret.txt",
])
def test_static_path_traversal_rejected(app_client, path):
    client, _ = app_client
    response = client.get(f"/{path}")
    assert "SHOULD NOT BE READABLE" not in response.text
    assert response.status_code in (200, 400, 404)
    if response.status_code == 200:
        assert response.text == "safe"


def test_double_url_encoded_traversal_rejected(app_client):
    client, _ = app_client
    response = client.get("/%252e%252e/secret.txt")
    assert "SHOULD NOT BE READABLE" not in response.text
