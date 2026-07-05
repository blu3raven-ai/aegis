"""Tests for runner.scanners.dependencies.declared_ranges."""
from __future__ import annotations

import json
from pathlib import Path

from runner.scanners.dependencies.declared_ranges import (
    Declaration,
    annotate_sbom_with_declared_ranges,
    parse_declared_ranges,
    tomllib,
)

_TOML_AVAILABLE = tomllib is not None


def _decl(constraint: str, path: str = "package.json", line: int = 1) -> Declaration:
    return Declaration(constraint=constraint, path=path, line=line)


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
    decls = parse_declared_ranges(tmp_path)
    assert decls["lodash"].constraint == "^4.17.0"
    assert decls["jest"].constraint == "~29.0.0"
    assert decls["react"].constraint == ">=18"
    assert decls["fsevents"].constraint == "*"  # loose constraint kept — it is signal
    assert decls["lodash"].path == "package.json"


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
    decls = parse_declared_ranges(tmp_path)
    assert decls["requests"].constraint == ">=2.31.0,<3"
    assert decls["flask"].constraint == "==2.0.1"
    assert decls["pydantic"].constraint == "~= 2.0"
    assert "other" not in decls  # -r include skipped


def test_requirements_captures_exact_line_and_path(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "\n".join(["# header", "requests>=2.31.0", "flask==2.0.1"])
    )
    decls = parse_declared_ranges(tmp_path)
    assert decls["requests"].path == "requirements.txt"
    assert decls["requests"].line == 2  # 1-indexed, after the comment
    assert decls["flask"].line == 3


def test_requirements_glob_picks_up_variants(tmp_path: Path) -> None:
    (tmp_path / "requirements-dev.txt").write_text("black==24.1.0\n")
    decls = parse_declared_ranges(tmp_path)
    assert decls["black"].constraint == "==24.1.0"


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
    decls = parse_declared_ranges(tmp_path)
    if _TOML_AVAILABLE:
        assert decls["httpx"].constraint == ">=0.27"
        assert decls["click"].constraint == ">= 8.0"
        assert decls["fastapi"].constraint == "^0.110.0"
        assert decls["uvicorn"].constraint == ">=0.29"
        assert "python" not in decls  # interpreter, not a dependency
    else:
        # Without tomllib, toml sources are skipped gracefully.
        assert "httpx" not in decls
        assert "fastapi" not in decls


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
    decls = parse_declared_ranges(tmp_path)
    assert decls["github.com/stretchr/testify"].constraint == "v1.9.0"
    assert decls["github.com/stretchr/testify"].line == 5
    assert decls["golang.org/x/sync"].constraint == "v0.7.0"
    assert decls["github.com/spf13/cobra"].constraint == "v1.8.0"
    assert decls["github.com/spf13/cobra"].line == 9


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
    decls = parse_declared_ranges(tmp_path)
    assert decls["rails"].constraint == "~> 7.1"
    assert decls["puma"].constraint == ">= 6.0"
    assert "rake" not in decls
    assert "commented" not in decls


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
    decls = parse_declared_ranges(tmp_path)
    if _TOML_AVAILABLE:
        assert decls["serde"].constraint == "1.0"
        assert decls["tokio"].constraint == "1.37"
        assert decls["criterion"].constraint == "0.5"
    else:
        assert "serde" not in decls


def test_first_non_empty_constraint_wins_on_collision(tmp_path: Path) -> None:
    # package.json (parsed before requirements) should win for a shared name.
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"shared-pkg": "^1.0.0"}})
    )
    (tmp_path / "requirements.txt").write_text("shared-pkg==2.0.0\n")
    decls = parse_declared_ranges(tmp_path)
    assert decls["shared-pkg"].constraint == "^1.0.0"


def test_missing_manifests_returns_empty(tmp_path: Path) -> None:
    assert parse_declared_ranges(tmp_path) == {}


def test_subdir_manifests_are_picked_up(tmp_path: Path) -> None:
    sub = tmp_path / "frontend"
    sub.mkdir()
    (sub / "package.json").write_text(
        json.dumps({"dependencies": {"axios": "^1.6.0"}})
    )
    decls = parse_declared_ranges(tmp_path)
    assert decls["axios"].constraint == "^1.6.0"
    assert decls["axios"].path == "frontend/package.json"  # relative to checkout root


# ---------------------------------------------------------------------------
# annotate_sbom_with_declared_ranges
# ---------------------------------------------------------------------------


def _write_sbom(path: Path, components: list) -> None:
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": components}))


def _props(comp: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in comp.get("properties", [])}


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
    decls = {
        "lodash": _decl("^4.17.0", "package.json", 3),
        "requests": _decl(">=2.31.0,<3", "requirements.txt", 1),
        "github.com/spf13/cobra": _decl("v1.8.0", "go.mod", 5),
    }
    n = annotate_sbom_with_declared_ranges(sbom, decls, tmp_path)
    assert n == 3

    data = json.loads(sbom.read_text())
    by_name = {c.get("name"): c for c in data["components"]}

    assert _props(by_name["lodash"])["aegis:declared_range"] == "^4.17.0"
    assert _props(by_name["lodash"])["aegis:declared_path"] == "package.json"
    assert _props(by_name["lodash"])["aegis:declared_line"] == "3"
    assert _props(by_name["requests"])["aegis:declared_range"] == ">=2.31.0,<3"
    # matched via purl bare name
    assert _props(by_name["Cobra"])["aegis:declared_range"] == "v1.8.0"
    assert "properties" not in by_name["untouched"]


def test_annotate_stamps_code_window_when_manifest_readable(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        "\n".join(
            [
                "{",
                '  "dependencies": {',
                '    "lodash": "^4.17.0"',
                "  }",
                "}",
            ]
        )
    )
    sbom = tmp_path / "sbom.cdx.json"
    _write_sbom(sbom, [{"name": "lodash", "purl": "pkg:npm/lodash@4.17.21"}])
    decls = {"lodash": _decl("^4.17.0", "package.json", 3)}

    assert annotate_sbom_with_declared_ranges(sbom, decls, tmp_path) == 1
    data = json.loads(sbom.read_text())
    props = _props(data["components"][0])
    assert '"lodash": "^4.17.0"' in props["aegis:declared_snippet"]
    # window radius 4, declaration on line 3 -> window starts at line 1
    assert props["aegis:declared_snippet_start"] == "1"


def test_annotate_skips_window_when_manifest_missing(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    _write_sbom(sbom, [{"name": "lodash", "purl": "pkg:npm/lodash@4.17.21"}])
    # No package.json on disk -> read_code_window returns nothing, no snippet.
    decls = {"lodash": _decl("^4.17.0", "package.json", 3)}
    assert annotate_sbom_with_declared_ranges(sbom, decls, tmp_path) == 1
    props = _props(json.loads(sbom.read_text())["components"][0])
    assert "aegis:declared_range" in props
    assert "aegis:declared_snippet" not in props


def test_annotate_scoped_npm_purl(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    _write_sbom(
        sbom,
        [{"name": "babel", "purl": "pkg:npm/%40babel/core@7.24.0"}],
    )
    # Declared under the scoped name as it appears in package.json.
    n = annotate_sbom_with_declared_ranges(
        sbom, {"@babel/core": _decl("^7.24.0")}, tmp_path
    )
    assert n == 1
    props = _props(json.loads(sbom.read_text())["components"][0])
    assert props["aegis:declared_range"] == "^7.24.0"


def test_annotate_is_idempotent(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    _write_sbom(sbom, [{"name": "lodash", "purl": "pkg:npm/lodash@4.17.21"}])
    decls = {"lodash": _decl("^4.17.0")}

    assert annotate_sbom_with_declared_ranges(sbom, decls, tmp_path) == 1
    assert annotate_sbom_with_declared_ranges(sbom, decls, tmp_path) == 0  # no duplicate

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
    annotate_sbom_with_declared_ranges(sbom, {"lodash": _decl("^4.17.0")}, tmp_path)
    data = json.loads(sbom.read_text())
    names = {p["name"] for p in data["components"][0]["properties"]}
    assert "syft:package:type" in names
    assert "aegis:declared_range" in names


def test_annotate_empty_decls_is_noop(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    _write_sbom(sbom, [{"name": "lodash"}])
    assert annotate_sbom_with_declared_ranges(sbom, {}, tmp_path) == 0


def test_annotate_malformed_sbom_returns_zero(tmp_path: Path) -> None:
    decls = {"lodash": _decl("^4.17.0")}

    not_dict = tmp_path / "list.json"
    not_dict.write_text(json.dumps(["not", "a", "dict"]))
    assert annotate_sbom_with_declared_ranges(not_dict, decls, tmp_path) == 0

    no_components = tmp_path / "no_comp.json"
    no_components.write_text(json.dumps({"bomFormat": "CycloneDX"}))
    assert annotate_sbom_with_declared_ranges(no_components, decls, tmp_path) == 0

    bad_components = tmp_path / "bad_comp.json"
    bad_components.write_text(json.dumps({"components": "nope"}))
    assert annotate_sbom_with_declared_ranges(bad_components, decls, tmp_path) == 0

    bad_entry = tmp_path / "bad_entry.json"
    bad_entry.write_text(json.dumps({"components": ["string", 5, None]}))
    assert annotate_sbom_with_declared_ranges(bad_entry, decls, tmp_path) == 0

    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{not json")
    assert annotate_sbom_with_declared_ranges(invalid_json, decls, tmp_path) == 0

    missing = tmp_path / "missing.json"
    assert annotate_sbom_with_declared_ranges(missing, decls, tmp_path) == 0


# ── dependency scope (dev vs prod) ───────────────────────────────────────────


def test_npm_dev_dependencies_tagged_dev(tmp_path: Path) -> None:
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
    decls = parse_declared_ranges(tmp_path)
    assert decls["lodash"].scope == "prod"
    assert decls["jest"].scope == "dev"
    # peer/optional are runtime-relevant, not dev-only
    assert decls["react"].scope == "prod"
    assert decls["fsevents"].scope == "prod"


def test_prod_wins_when_dep_in_both_sections(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"shared": "^1.0.0"},
                "devDependencies": {"shared": "^1.0.0"},
            }
        )
    )
    # dependencies is parsed first; a dep used in prod is never mislabelled dev.
    assert parse_declared_ranges(tmp_path)["shared"].scope == "prod"


def test_requirements_dev_filename_tagged_dev(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests>=2.31.0\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest>=7.0\n")
    decls = parse_declared_ranges(tmp_path)
    assert decls["requests"].scope == "prod"
    assert decls["pytest"].scope == "dev"


def test_cargo_dev_and_build_deps_tagged_dev(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        "\n".join(
            [
                "[dependencies]",
                'serde = "1.0"',
                "[dev-dependencies]",
                'proptest = "1.4"',
                "[build-dependencies]",
                'cc = "1.0"',
            ]
        )
    )
    decls = parse_declared_ranges(tmp_path)
    assert decls["serde"].scope == "prod"
    assert decls["proptest"].scope == "dev"
    assert decls["cc"].scope == "dev"


def test_poetry_groups_and_pep735_tagged_dev(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "\n".join(
            [
                "[tool.poetry.dependencies]",
                'requests = "^2.31"',
                "[tool.poetry.group.dev.dependencies]",
                'black = "^24.0"',
                "[dependency-groups]",
                'test = ["pytest>=7.0"]',
            ]
        )
    )
    decls = parse_declared_ranges(tmp_path)
    assert decls["requests"].scope == "prod"
    assert decls["black"].scope == "dev"
    assert decls["pytest"].scope == "dev"


def test_annotate_stamps_scope_property(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    _write_sbom(
        sbom,
        [{"name": "jest", "version": "29.0.0", "purl": "pkg:npm/jest@29.0.0"}],
    )
    decls = {"jest": Declaration(constraint="~29.0.0", path="package.json", line=2, scope="dev")}
    annotate_sbom_with_declared_ranges(sbom, decls, tmp_path)
    data = json.loads(sbom.read_text())
    props = _props(data["components"][0])
    assert props["aegis:declared_scope"] == "dev"


# ── monorepo discovery + additional ecosystems ───────────────────────────────


def test_discovers_manifests_in_arbitrary_nested_dirs(tmp_path: Path) -> None:
    (tmp_path / "packages" / "web").mkdir(parents=True)
    (tmp_path / "packages" / "web" / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^18.0.0"}})
    )
    (tmp_path / "services" / "api").mkdir(parents=True)
    (tmp_path / "services" / "api" / "go.mod").write_text(
        "module x\nrequire github.com/gin-gonic/gin v1.9.0\n"
    )
    decls = parse_declared_ranges(tmp_path)
    assert decls["react"].constraint == "^18.0.0"
    assert decls["react"].path == "packages/web/package.json"
    assert decls["github.com/gin-gonic/gin"].constraint == "v1.9.0"


def test_discovery_prunes_vendored_manifests(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4"}}))
    nested = tmp_path / "node_modules" / "some-dep"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text(json.dumps({"dependencies": {"evil": "^1"}}))
    decls = parse_declared_ranges(tmp_path)
    assert "lodash" in decls
    assert "evil" not in decls  # vendored manifest pruned


def test_maven_pom_with_namespace_and_scope(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.30</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>unresolved</artifactId>
      <version>${acme.version}</version>
    </dependency>
  </dependencies>
</project>"""
    )
    decls = parse_declared_ranges(tmp_path)
    assert decls["spring-core"].constraint == "5.3.30"
    assert decls["spring-core"].scope == "prod"
    assert decls["junit"].scope == "dev"  # test scope
    assert "unresolved" not in decls  # ${property} version skipped


def test_composer_require_and_require_dev(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text(
        json.dumps({
            "require": {"php": ">=8.1", "monolog/monolog": "^3.0"},
            "require-dev": {"phpunit/phpunit": "^10.0"},
        })
    )
    decls = parse_declared_ranges(tmp_path)
    assert decls["monolog/monolog"].constraint == "^3.0"
    assert decls["monolog/monolog"].scope == "prod"
    assert decls["phpunit/phpunit"].scope == "dev"
    assert "php" not in decls  # platform requirement skipped


def test_csproj_package_references(tmp_path: Path) -> None:
    (tmp_path / "App.csproj").write_text(
        """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>"""
    )
    decls = parse_declared_ranges(tmp_path)
    assert decls["newtonsoft.json"].constraint == "13.0.3"
    assert decls["serilog"].constraint == "3.1.1"
