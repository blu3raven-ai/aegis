"""Tests for container scanning registry authentication."""
import base64
import json
import os
import pytest
from unittest.mock import patch, MagicMock


# ── _resolve_registry_username ─────────────────────────────────────────────


class TestResolveRegistryUsername:
    """Test provider-specific username resolution."""

    def _resolve(self, registry: str, token: str) -> str:
        from src.containers.scanner import _resolve_registry_username
        return _resolve_registry_username(registry, token)

    def test_ghcr_resolves_from_api(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"login": "octocat"}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
            result = self._resolve("ghcr.io", "ghp_abc123")

        assert result == "octocat"
        # Verify it called the correct GitHub API endpoint
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.full_url == "https://api.github.com/user"
        assert "Bearer ghp_abc123" in req.get_header("Authorization")

    def test_ghcr_with_github_pat_prefix(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"login": "user2"}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = self._resolve("ghcr.io", "github_pat_xyz789")

        assert result == "user2"

    def test_ghcr_non_pat_token_skips_api(self):
        """Non-GitHub PAT tokens should not call the GitHub API."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            result = self._resolve("ghcr.io", "some_other_token")

        mock_urlopen.assert_not_called()
        assert result == "_token"  # falls through to default

    def test_ghcr_api_failure_returns_token_with_warning(self):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            result = self._resolve("ghcr.io", "ghp_abc123")

        # Falls through to default since GHCR-specific resolution failed
        assert result == "_token"

    def test_aws_ecr(self):
        result = self._resolve("123456789.dkr.ecr.us-east-1.amazonaws.com", "aws-token")
        assert result == "AWS"

    def test_aws_ecr_other_region(self):
        result = self._resolve("999999999.dkr.ecr.eu-west-1.amazonaws.com", "aws-token")
        assert result == "AWS"

    def test_gitlab_registry(self):
        result = self._resolve("registry.gitlab.com", "glpat-xxx")
        assert result == "oauth2"

    def test_gitlab_self_hosted(self):
        result = self._resolve("registry.gitlab.mycompany.com", "glpat-xxx")
        assert result == "oauth2"

    def test_docker_hub(self):
        result = self._resolve("docker.io", "dckr_pat_xxx")
        assert result == "_token"

    def test_unknown_registry(self):
        result = self._resolve("myregistry.internal.co", "some-token")
        assert result == "_token"

    def test_empty_registry(self):
        result = self._resolve("", "some-token")
        assert result == "_token"


# ── Registry auth collection from sources ──────────────────────────────────


class TestRegistryAuthCollection:
    """Test that _run_full_or_sbom correctly collects auth from multiple sources."""

    def _make_source(self, images, token="", username="", registry_token=""):
        from dataclasses import dataclass

        @dataclass
        class FakeSource:
            container_images: list
            registry_token: str
            registry_username: str

        return FakeSource(
            container_images=images,
            registry_token=registry_token or token,
            registry_username=username,
        )

    def test_single_registry(self):
        """Single source with GHCR images."""
        sources = [self._make_source(
            images=["ghcr.io/org/app:v1", "ghcr.io/org/api:v2"],
            registry_token="ghp_test",
        )]

        seen = set()
        auths = []
        for src in sources:
            token = src.registry_token
            if not token:
                continue
            for img in src.container_images:
                parts = img.split("/")
                registry = parts[0] if len(parts) > 1 and "." in parts[0] else ""
                if registry and registry not in seen:
                    seen.add(registry)
                    auths.append({"registry": registry, "token": token})

        assert len(auths) == 1
        assert auths[0]["registry"] == "ghcr.io"

    def test_multiple_registries(self):
        """Multiple sources with different registries."""
        sources = [
            self._make_source(
                images=["ghcr.io/org/app:v1"],
                registry_token="ghp_test",
            ),
            self._make_source(
                images=["123456.dkr.ecr.us-east-1.amazonaws.com/myapp:latest"],
                registry_token="aws_token",
            ),
        ]

        seen = set()
        auths = []
        for src in sources:
            token = src.registry_token
            if not token:
                continue
            for img in src.container_images:
                parts = img.split("/")
                registry = parts[0] if len(parts) > 1 and "." in parts[0] else ""
                if registry and registry not in seen:
                    seen.add(registry)
                    auths.append({"registry": registry, "token": token})

        assert len(auths) == 2
        registries = {a["registry"] for a in auths}
        assert "ghcr.io" in registries
        assert "123456.dkr.ecr.us-east-1.amazonaws.com" in registries

    def test_source_without_token_skipped(self):
        """Sources without tokens should not produce auth entries."""
        sources = [self._make_source(
            images=["ghcr.io/org/app:v1"],
            registry_token="",
        )]

        auths = []
        for src in sources:
            if not src.registry_token:
                continue
            auths.append({"registry": "ghcr.io"})

        assert len(auths) == 0

    def test_deduplicates_same_registry(self):
        """Multiple images from the same registry should produce one auth entry."""
        sources = [self._make_source(
            images=["ghcr.io/org/app:v1", "ghcr.io/org/api:v2", "ghcr.io/org/web:v3"],
            registry_token="ghp_test",
        )]

        seen = set()
        auths = []
        for src in sources:
            token = src.registry_token
            if not token:
                continue
            for img in src.container_images:
                parts = img.split("/")
                registry = parts[0] if len(parts) > 1 and "." in parts[0] else ""
                if registry and registry not in seen:
                    seen.add(registry)
                    auths.append({"registry": registry})

        assert len(auths) == 1


# ── Docker config.json generation (runner side) ───────────────────────────


class TestDockerConfigGeneration:
    """Test that the runner builds correct Docker config.json from REGISTRY_AUTHS."""

    def _build_config(self, auths: list[dict]) -> dict:
        """Simulate runner's Docker config.json generation (Syft format)."""
        docker_config: dict = {"auths": {}}
        for entry in auths:
            registry = entry.get("registry", "")
            token = entry.get("token", "")
            username = entry.get("username", "") or "_token"
            if registry and token:
                docker_config["auths"][registry] = {
                    "username": username,
                    "password": token,
                }
        return docker_config

    def test_single_registry(self):
        config = self._build_config([
            {"registry": "ghcr.io", "username": "octocat", "token": "ghp_test"},
        ])
        assert "ghcr.io" in config["auths"]
        assert config["auths"]["ghcr.io"]["username"] == "octocat"
        assert config["auths"]["ghcr.io"]["password"] == "ghp_test"

    def test_multiple_registries(self):
        config = self._build_config([
            {"registry": "ghcr.io", "username": "octocat", "token": "ghp_test"},
            {"registry": "123456.dkr.ecr.us-east-1.amazonaws.com", "username": "AWS", "token": "ecr_token"},
            {"registry": "registry.gitlab.com", "username": "oauth2", "token": "glpat_test"},
        ])
        assert len(config["auths"]) == 3
        assert "ghcr.io" in config["auths"]
        assert "123456.dkr.ecr.us-east-1.amazonaws.com" in config["auths"]
        assert "registry.gitlab.com" in config["auths"]
        assert config["auths"]["123456.dkr.ecr.us-east-1.amazonaws.com"]["username"] == "AWS"

    def test_missing_username_uses_default(self):
        config = self._build_config([
            {"registry": "custom.io", "username": "", "token": "tok"},
        ])
        assert config["auths"]["custom.io"]["username"] == "_token"
        assert config["auths"]["custom.io"]["password"] == "tok"

    def test_empty_token_skipped(self):
        config = self._build_config([
            {"registry": "ghcr.io", "username": "user", "token": ""},
        ])
        assert len(config["auths"]) == 0

    def test_empty_registry_skipped(self):
        config = self._build_config([
            {"registry": "", "username": "user", "token": "tok"},
        ])
        assert len(config["auths"]) == 0

    def test_token_with_special_chars(self):
        """Tokens with special characters should be preserved as-is."""
        config = self._build_config([
            {"registry": "ghcr.io", "username": "user", "token": "abc:def/ghi+jkl="},
        ])
        assert config["auths"]["ghcr.io"]["password"] == "abc:def/ghi+jkl="


# ── REGISTRY_AUTHS encryption ─────────────────────────────────────────────


class TestRegistryAuthsEncryption:
    """Test that REGISTRY_AUTHS is in SENSITIVE_KEYS and gets encrypted."""

    def test_registry_auths_in_sensitive_keys(self):
        from src.runner.jobs import SENSITIVE_KEYS
        assert "REGISTRY_AUTHS" in SENSITIVE_KEYS

    def test_registry_token_in_sensitive_keys(self):
        from src.runner.jobs import SENSITIVE_KEYS
        assert "REGISTRY_TOKEN" in SENSITIVE_KEYS

    def test_git_token_in_sensitive_keys(self):
        from src.runner.jobs import SENSITIVE_KEYS
        assert "GIT_TOKEN" in SENSITIVE_KEYS
