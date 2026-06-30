"""Capture each direct dependency's declared version range from manifests.

Lockfiles and SBOM generators record the *resolved* version a build pinned to,
but the manifest the developer actually wrote down declares a *range* (npm
``^4.17.0``, pip ``>=2.31,<3``). That declared range is signal an analyst needs:
it tells them whether a fixed version is already reachable without a manifest
edit. This module parses root-level manifests for direct declarations only and
stamps the range onto the matching CycloneDX component as an ``aegis:declared_range``
property. It is purely additive enrichment — every parse is best-effort and a
failure to read or parse any file is swallowed so the scan never breaks.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from urllib.parse import unquote

try:  # tomllib is stdlib on 3.11+; toml-based ecosystems are skipped without it.
    import tomllib
except ImportError:  # pragma: no cover - exercised only on <3.11 runners
    tomllib = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_PROPERTY_NAME = "aegis:declared_range"

# Cap per-file reads so a hostile or accidentally-huge manifest can't exhaust
# memory. Real manifests are kilobytes; 5 MiB is a generous ceiling.
_MAX_FILE_BYTES = 5 * 1024 * 1024

# Conventional locations a project's own direct-dependency manifests live in,
# beyond the checkout root. Bounded on purpose — we do not walk the whole tree
# (that would pull in vendored / transitive manifests, which are not "direct").
_SUBDIR_CANDIDATES = ("src", "app", "backend", "frontend", "server")


def _read_text(path: Path) -> str | None:
    """Read a manifest if present and within the size cap; else return None."""
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _read_toml(path: Path) -> dict | None:
    """Parse a TOML manifest, or return None if tomllib is unavailable / invalid."""
    if tomllib is None:
        return None
    raw = _read_text(path)
    if raw is None:
        return None
    try:
        return tomllib.loads(raw)
    except (tomllib.TOMLDecodeError, ValueError):
        return None


def _add(ranges: dict[str, str], name: str | None, constraint: object) -> None:
    """Record name→constraint, lower-casing the name and keeping the first hit.

    Blank constraints are skipped (no signal); a loose ``*`` / ``latest`` is kept
    because "this dep floats" is itself meaningful to a triager.
    """
    if not name:
        return
    if not isinstance(constraint, str):
        return
    value = constraint.strip()
    if not value:
        return
    key = name.strip().lower()
    if not key:
        return
    ranges.setdefault(key, value)


# PEP 508 requirement: a leading package name, an optional [extras] group, then
# the version specifier (which we keep, stopping at any environment marker).
_PEP508_NAME = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;]*)$"
)
# requirements.txt line: name + optional extras + specifier, stopping at markers.
_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;#]*)"
)


def _parse_package_json(checkout: Path, ranges: dict[str, str]) -> None:
    raw = _read_text(checkout / "package.json")
    if raw is None:
        return
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return
    if not isinstance(data, dict):
        return
    for section in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        block = data.get(section)
        if isinstance(block, dict):
            for name, constraint in block.items():
                _add(ranges, name, constraint)


def _parse_requirements(checkout: Path, ranges: dict[str, str]) -> None:
    for path in sorted(checkout.glob("requirements*.txt")):
        raw = _read_text(path)
        if raw is None:
            continue
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Skip pip options, includes, editable installs, and bare URLs.
            if stripped.startswith(("-", "git+", "http://", "https://")):
                continue
            match = _REQ_LINE.match(stripped)
            if not match:
                continue
            name, specifier = match.group(1), match.group(2).strip()
            _add(ranges, name, specifier)


def _parse_pyproject(checkout: Path, ranges: dict[str, str]) -> None:
    data = _read_toml(checkout / "pyproject.toml")
    if data is None:
        return

    # PEP 621: [project].dependencies is a list of PEP 508 strings.
    project = data.get("project")
    if isinstance(project, dict):
        deps = project.get("dependencies")
        if isinstance(deps, list):
            for entry in deps:
                if not isinstance(entry, str):
                    continue
                match = _PEP508_NAME.match(entry)
                if match:
                    _add(ranges, match.group(1), match.group(2).strip())

    # Poetry: [tool.poetry.dependencies] is a table of name→constraint.
    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            deps = poetry.get("dependencies")
            if isinstance(deps, dict):
                for name, constraint in deps.items():
                    if name.lower() == "python":  # the interpreter, not a dep
                        continue
                    if isinstance(constraint, str):
                        _add(ranges, name, constraint)
                    elif isinstance(constraint, dict):
                        _add(ranges, name, constraint.get("version"))


_GOMOD_REQUIRE_LINE = re.compile(r"^([^\s]+)\s+(v[^\s]+)")


def _parse_go_mod(checkout: Path, ranges: dict[str, str]) -> None:
    raw = _read_text(checkout / "go.mod")
    if raw is None:
        return
    in_block = False
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if in_block:
            if stripped.startswith(")"):
                in_block = False
                continue
            match = _GOMOD_REQUIRE_LINE.match(stripped)
            if match:
                _add(ranges, match.group(1), match.group(2))
            continue
        if stripped.startswith("require ("):
            in_block = True
            continue
        if stripped.startswith("require "):
            match = _GOMOD_REQUIRE_LINE.match(stripped[len("require "):].strip())
            if match:
                _add(ranges, match.group(1), match.group(2))


_GEMFILE_LINE = re.compile(
    r"""^\s*gem\s+["']([^"']+)["']\s*,\s*["']([^"']+)["']"""
)


def _parse_gemfile(checkout: Path, ranges: dict[str, str]) -> None:
    raw = _read_text(checkout / "Gemfile")
    if raw is None:
        return
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _GEMFILE_LINE.match(stripped)
        if match:
            _add(ranges, match.group(1), match.group(2))


def _parse_cargo_toml(checkout: Path, ranges: dict[str, str]) -> None:
    data = _read_toml(checkout / "Cargo.toml")
    if data is None:
        return
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, constraint in block.items():
            if isinstance(constraint, str):
                _add(ranges, name, constraint)
            elif isinstance(constraint, dict):
                _add(ranges, name, constraint.get("version"))


_PARSERS = (
    _parse_package_json,
    _parse_requirements,
    _parse_pyproject,
    _parse_go_mod,
    _parse_gemfile,
    _parse_cargo_toml,
)


def parse_declared_ranges(checkout_dir: Path) -> dict[str, str]:
    """Scan a checkout for direct-dependency manifests and return name→range.

    Parses root-level manifests (plus a bounded set of conventional subdirs) for
    the project's own declared direct dependencies across npm, PyPI, Go, Ruby and
    Cargo. Names are lower-cased; on collisions the first non-empty constraint
    wins. Every per-file read and parse is best-effort — a missing or malformed
    manifest is skipped, never raised — so this is always safe to call.
    """
    ranges: dict[str, str] = {}
    roots = [checkout_dir]
    for sub in _SUBDIR_CANDIDATES:
        candidate = checkout_dir / sub
        try:
            if candidate.is_dir():
                roots.append(candidate)
        except OSError:
            continue
    for root in roots:
        for parser in _PARSERS:
            try:
                parser(root, ranges)
            except Exception:  # noqa: BLE001 - enrichment is strictly best-effort
                logger.debug("declared-range parser %s failed", parser.__name__)
    return ranges


def _purl_name_candidates(purl: object) -> list[str]:
    """Return lower-cased name candidates from a purl, if parseable.

    A purl looks like ``pkg:npm/%40scope/name@1.2.3`` or ``pkg:pypi/requests@2.0``.
    Yields both the namespaced form a manifest declares (``@scope/name``) and the
    bare trailing segment, so either declaration style matches.
    """
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return []
    body = purl[len("pkg:"):]
    body = body.split("?", 1)[0].split("#", 1)[0]
    # type/namespace.../name@version — drop the type, keep namespace + name.
    after_type = body.split("/", 1)
    if len(after_type) != 2:
        return []
    path = after_type[1].rsplit("@", 1)[0]  # drop the @version suffix
    if not path:
        return []
    segments = [unquote(seg) for seg in path.split("/") if seg]
    if not segments:
        return []
    candidates: list[str] = []
    full = "/".join(segments).lower()  # e.g. "@babel/core"
    if full:
        candidates.append(full)
    bare = segments[-1].lower()
    if bare and bare != full:
        candidates.append(bare)
    return candidates


def annotate_sbom_with_declared_ranges(sbom_path: Path, ranges: dict[str, str]) -> int:
    """Stamp ``aegis:declared_range`` onto components matching a declared range.

    Loads the CycloneDX JSON at ``sbom_path``, matches each component by its
    lower-cased ``name`` (and, for namespaced purls, the bare package name) and
    appends an ``aegis:declared_range`` property. Existing such properties are
    left untouched so re-running is idempotent. Fully guarded: a non-dict SBOM,
    missing/non-list components, or non-dict component entries yield 0 rather
    than raising. Returns the number of components annotated.
    """
    if not ranges:
        return 0
    raw = _read_text(sbom_path)
    if raw is None:
        return 0
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return 0
    if not isinstance(data, dict):
        return 0
    components = data.get("components")
    if not isinstance(components, list):
        return 0

    annotated = 0
    for component in components:
        if not isinstance(component, dict):
            continue
        candidates: list[str] = []
        name = component.get("name")
        if isinstance(name, str) and name.strip():
            candidates.append(name.strip().lower())
        candidates.extend(_purl_name_candidates(component.get("purl")))

        constraint = next((ranges[c] for c in candidates if c in ranges), None)
        if constraint is None:
            continue

        props = component.get("properties")
        if not isinstance(props, list):
            props = []
            component["properties"] = props
        if any(
            isinstance(p, dict) and p.get("name") == _PROPERTY_NAME for p in props
        ):
            continue  # idempotent — don't duplicate on re-run
        props.append({"name": _PROPERTY_NAME, "value": constraint})
        annotated += 1

    if annotated:
        sbom_path.write_text(json.dumps(data, separators=(",", ":")))
    return annotated
