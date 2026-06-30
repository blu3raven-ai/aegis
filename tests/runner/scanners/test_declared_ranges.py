"""Tests for runner.scanners.dependencies.declared_ranges."""
from __future__ import annotations

import json
from pathlib import Path

from runner.scanners.dependencies.declared_ranges import (
    annotate_sbom_with_declared_ranges,
    parse_declared_ranges,
    tomllib,
)

_TOML_AVAILABLE = tomllib is not None


# ---------------------------------------------------------------------------
# parse_declared_ranges — one test per ecosystem
# ---------------------------------------------------------------------------


def test_package_json_merges_all_dep_sections(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"lodash": "^4.17.0"},
                "devDependencies": {"jest": "~29.0.0"},
                "peerDependencies": {"react": ">=18"},
                "optionalDependencies": {"fsevents": "*"},
            }
        )
    )
    ranges = parse_declared_ranges(tmp_path)
    assert ranges["lodash"] == "^4.17.0"
    assert ranges["jest"] == "~29.0.0"
    assert ranges["react"] == ">=18"
    assert ranges["fsevents"] == "*"  # loose constraint kept — it is signal


def test_requirements_txt_specifiers_and_skips(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "\n".join(
            [
                "# a comment",
                "requests>=2.31.0,<3",
                "flask[async]==2.0.1",
                "-r other.txt",
                "-e .",
                "https://example.com/pkg.whl",
                "  pydantic ~= 2.0  # inline comment",
            ]
        )
    )
    ranges = parse_declared_ranges(tmp_path)
    assert ranges["requests"] == ">=2.31.0,<3"
    assert ranges["flask"] == "==2.0.1"
    assert ranges["pydantic"] == "~= 2.0"
    assert "other" not in ranges  # -r include skipped


def test_requirements_glob_picks_up_variants(tmp_path: Path) -> None:
    (tmp_path / "requirements-dev.txt").write_text("black==24.1.0\n")
    ranges = parse_declared_ranges(tmp_path)
    assert ranges["black"] == "==24.1.0"


def test_pyproject_pep621_and_poetry(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'dependencies = ["httpx>=0.27", "click[colors] >= 8.0"]',
                "",
                "[tool.poetry.dependencies]",
                'python = "^3.11"',
                'fastapi = "^0.110.0"',
                'uvicorn = { version = ">=0.29", extras = ["standard"] }',
            ]
        )
    )
    ranges = parse_declared_ranges(tmp_path)
    if _TOML_AVAILABLE:
        assert ranges["httpx"] == ">=0.27"
        assert ranges["click"] == ">= 8.0"
        assert ranges["fastapi"] == "^0.110.0"
        assert ranges["uvicorn"] == ">=0.29"
        assert "python" not in ranges  # interpreter, not a dependency
    else:
        # Without tomllib, toml sources are skipped gracefully.
        assert "httpx" not in ranges
        assert "fastapi" not in ranges


def test_go_mod_require_block_and_single_line(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "\n".join(
            [
                "module example.com/acme-org/widget",
                "go 1.22",
                "",
                "require (",
                "    github.com/stretchr/testify v1.9.0",
                "    golang.org/x/sync v0.7.0 // indirect",
                ")",
                "",
                "require github.com/spf13/cobra v1.8.0",
            ]
        )
    )
    ranges = parse_declared_ranges(tmp_path)
    assert ranges["github.com/stretchr/testify"] == "v1.9.0"
    assert ranges["golang.org/x/sync"] == "v0.7.0"
    assert ranges["github.com/spf13/cobra"] == "v1.8.0"


def test_gemfile_with_and_without_constraint(tmp_path: Path) -> None:
    (tmp_path / "Gemfile").write_text(
        "\n".join(
            [
                "source 'https://rubygems.org'",
                "gem 'rails', '~> 7.1'",
                "gem 'puma', '>= 6.0'",
                "gem 'rake'",  # no constraint -> skipped
                "# gem 'commented', '1.0'",
            ]
        )
    )
    ranges = parse_declared_ranges(tmp_path)
    assert ranges["rails"] == "~> 7.1"
    assert ranges["puma"] == ">= 6.0"
    assert "rake" not in ranges
    assert "commented" not in ranges


def test_cargo_toml_string_and_table_deps(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        "\n".join(
            [
                "[package]",
                'name = "acme-org-widget"',
                "",
                "[dependencies]",
                'serde = "1.0"',
                'tokio = { version = "1.37", features = ["full"] }',
                "",
                "[dev-dependencies]",
                'criterion = "0.5"',
            ]
        )
    )
    ranges = parse_declared_ranges(tmp_path)
    if _TOML_AVAILABLE:
        assert ranges["serde"] == "1.0"
        assert ranges["tokio"] == "1.37"
        assert ranges["criterion"] == "0.5"
    else:
        assert "serde" not in ranges


def test_first_non_empty_constraint_wins_on_collision(tmp_path: Path) -> None:
    # package.json (parsed before requirements) should win for a shared name.
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"shared-pkg": "^1.0.0"}})
    )
    (tmp_path / "requirements.txt").write_text("shared-pkg==2.0.0\n")
    ranges = parse_declared_ranges(tmp_path)
    assert ranges["shared-pkg"] == "^1.0.0"


def test_missing_manifests_returns_empty(tmp_path: Path) -> None:
    assert parse_declared_ranges(tmp_path) == {}


def test_subdir_manifests_are_picked_up(tmp_path: Path) -> None:
    sub = tmp_path / "frontend"
    sub.mkdir()
    (sub / "package.json").write_text(
        json.dumps({"dependencies": {"axios": "^1.6.0"}})
    )
    ranges = parse_declared_ranges(tmp_path)
    assert ranges["axios"] == "^1.6.0"


# ---------------------------------------------------------------------------
# annotate_sbom_with_declared_ranges
# ---------------------------------------------------------------------------


def _write_sbom(path: Path, components: list) -> None:
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": components}))


def test_annotate_matches_by_name_and_purl(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    _write_sbom(
        sbom,
        [
            {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
            {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
            # name absent / mismatched, but purl carries the bare name.
            {"name": "Cobra", "purl": "pkg:golang/github.com/spf13/cobra@v1.8.0"},
            {"name": "untouched", "version": "1.0.0"},
        ],
    )
    ranges = {
        "lodash": "^4.17.0",
        "requests": ">=2.31.0,<3",
        "github.com/spf13/cobra": "v1.8.0",
    }
    n = annotate_sbom_with_declared_ranges(sbom, ranges)
    assert n == 3

    data = json.loads(sbom.read_text())
    by_name = {c.get("name"): c for c in data["components"]}

    def _range(comp: dict) -> str | None:
        for p in comp.get("properties", []):
            if p["name"] == "aegis:declared_range":
                return p["value"]
        return None

    assert _range(by_name["lodash"]) == "^4.17.0"
    assert _range(by_name["requests"]) == ">=2.31.0,<3"
    assert _range(by_name["Cobra"]) == "v1.8.0"  # matched via purl bare name
    assert "properties" not in by_name["untouched"]


def test_annotate_scoped_npm_purl(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    _write_sbom(
        sbom,
        [{"name": "babel", "purl": "pkg:npm/%40babel/core@7.24.0"}],
    )
    # Declared under the scoped name as it appears in package.json.
    n = annotate_sbom_with_declared_ranges(sbom, {"@babel/core": "^7.24.0"})
    assert n == 1
    data = json.loads(sbom.read_text())
    props = data["components"][0]["properties"]
    assert props == [{"name": "aegis:declared_range", "value": "^7.24.0"}]


def test_annotate_is_idempotent(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    _write_sbom(sbom, [{"name": "lodash", "purl": "pkg:npm/lodash@4.17.21"}])
    ranges = {"lodash": "^4.17.0"}

    assert annotate_sbom_with_declared_ranges(sbom, ranges) == 1
    assert annotate_sbom_with_declared_ranges(sbom, ranges) == 0  # no duplicate

    data = json.loads(sbom.read_text())
    props = data["components"][0]["properties"]
    matches = [p for p in props if p["name"] == "aegis:declared_range"]
    assert len(matches) == 1


def test_annotate_preserves_existing_properties(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    _write_sbom(
        sbom,
        [
            {
                "name": "lodash",
                "properties": [{"name": "syft:package:type", "value": "npm"}],
            }
        ],
    )
    annotate_sbom_with_declared_ranges(sbom, {"lodash": "^4.17.0"})
    data = json.loads(sbom.read_text())
    names = {p["name"] for p in data["components"][0]["properties"]}
    assert names == {"syft:package:type", "aegis:declared_range"}


def test_annotate_empty_ranges_is_noop(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    _write_sbom(sbom, [{"name": "lodash"}])
    assert annotate_sbom_with_declared_ranges(sbom, {}) == 0


def test_annotate_malformed_sbom_returns_zero(tmp_path: Path) -> None:
    ranges = {"lodash": "^4.17.0"}

    not_dict = tmp_path / "list.json"
    not_dict.write_text(json.dumps(["not", "a", "dict"]))
    assert annotate_sbom_with_declared_ranges(not_dict, ranges) == 0

    no_components = tmp_path / "no_comp.json"
    no_components.write_text(json.dumps({"bomFormat": "CycloneDX"}))
    assert annotate_sbom_with_declared_ranges(no_components, ranges) == 0

    bad_components = tmp_path / "bad_comp.json"
    bad_components.write_text(json.dumps({"components": "nope"}))
    assert annotate_sbom_with_declared_ranges(bad_components, ranges) == 0

    bad_entry = tmp_path / "bad_entry.json"
    bad_entry.write_text(json.dumps({"components": ["string", 5, None]}))
    assert annotate_sbom_with_declared_ranges(bad_entry, ranges) == 0

    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{not json")
    assert annotate_sbom_with_declared_ranges(invalid_json, ranges) == 0

    missing = tmp_path / "missing.json"
    assert annotate_sbom_with_declared_ranges(missing, ranges) == 0
