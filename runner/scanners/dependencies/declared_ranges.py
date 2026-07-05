"""Capture each direct dependency's declared range and manifest location.

Lockfiles and SBOM generators record the *resolved* version a build pinned to,
but the manifest the developer actually wrote down declares a *range* (npm
``^4.17.0``, pip ``>=2.31,<3``) at a specific file and line. That declared range
is signal an analyst needs — it tells them whether a fixed version is already
reachable without a manifest edit — and the file/line lets the finding drawer
show the exact declaration in context and deep-link back to the repo. This module
parses root-level manifests for direct declarations only and stamps the range,
the manifest path, the declaration line and a small surrounding code window onto
the matching CycloneDX component as ``aegis:declared_*`` properties. It is purely
additive enrichment — every parse is best-effort and a failure to read or parse
any file is swallowed so the scan never breaks.
"""
from __future__ import annotations

import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from runner.scanners._context import read_code_window

try:  # tomllib is stdlib on 3.11+; toml-based ecosystems are skipped without it.
    import tomllib
except ImportError:  # pragma: no cover - exercised only on <3.11 runners
    tomllib = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_RANGE_PROPERTY = "aegis:declared_range"
_PATH_PROPERTY = "aegis:declared_path"
_LINE_PROPERTY = "aegis:declared_line"
_SNIPPET_PROPERTY = "aegis:declared_snippet"
_SNIPPET_START_PROPERTY = "aegis:declared_snippet_start"
_SCOPE_PROPERTY = "aegis:declared_scope"

# Manifests are short; a tight window keeps the declaration in view without
# dumping the whole file (or the SBOM it rides in) full of unrelated deps.
_WINDOW_RADIUS = 4

# Cap per-file reads so a hostile or accidentally-huge manifest can't exhaust
# memory. Real manifests are kilobytes; 5 MiB is a generous ceiling.
_MAX_FILE_BYTES = 5 * 1024 * 1024

# Direct-dependency manifests can live anywhere in a monorepo (packages/*,
# services/*, apps/web, …), so discover them by a bounded walk rather than a
# fixed subdir guess. These directories never hold a project's *own* direct
# manifests (they are vendored deps, build output, or VCS internals) and are
# pruned so the walk stays cheap and doesn't pick up transitive manifests.
_PRUNE_DIRS = frozenset({
    "node_modules", "vendor", "bower_components", "dist", "build", "out",
    "target", "coverage", "__pycache__", "site-packages",
})

# Manifest filenames whose presence marks a directory as a discovery root.
# requirements*.txt is matched by prefix, so it is handled separately.
_MANIFEST_FILENAMES = frozenset({
    "package.json", "pyproject.toml", "go.mod", "Gemfile", "Cargo.toml",
    "pom.xml", "composer.json",
})

# Guardrails so a pathological monorepo can't blow up the scan.
_MAX_WALK_DEPTH = 6
_MAX_MANIFEST_DIRS = 200


def _has_manifest(filenames: list[str]) -> bool:
    return any(
        f in _MANIFEST_FILENAMES
        or (f.startswith("requirements") and f.endswith(".txt"))
        or f.endswith(".csproj")
        for f in filenames
    )


def _discover_manifest_dirs(checkout_dir: Path) -> list[Path]:
    """Directories under ``checkout_dir`` that hold a direct-dependency manifest.

    Walks the tree depth-first with dot-dirs and vendored/build directories
    pruned, capped at ``_MAX_WALK_DEPTH`` deep and ``_MAX_MANIFEST_DIRS`` total
    so a huge monorepo stays bounded. The checkout root is always included."""
    roots: list[Path] = [checkout_dir]
    seen: set[Path] = {checkout_dir}
    for dirpath, dirnames, filenames in os.walk(checkout_dir):
        here = Path(dirpath)
        depth = len(here.relative_to(checkout_dir).parts)
        if depth >= _MAX_WALK_DEPTH:
            dirnames[:] = []
        else:
            dirnames[:] = sorted(
                d for d in dirnames if d not in _PRUNE_DIRS and not d.startswith(".")
            )
        if here not in seen and _has_manifest(filenames):
            roots.append(here)
            seen.add(here)
            if len(roots) >= _MAX_MANIFEST_DIRS:
                logger.warning(
                    "declared_ranges: manifest-dir cap (%d) hit; stopping discovery",
                    _MAX_MANIFEST_DIRS,
                )
                break
    return roots


@dataclass(frozen=True)
class Declaration:
    """A direct dependency's declared constraint and where it was declared."""

    constraint: str
    path: str  # manifest path, relative to the checkout root
    line: int  # 1-indexed line the dependency is declared on
    scope: str = "prod"  # "dev" for dev/test/build-only deps, else "prod"


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


def _rel(path: Path, checkout_dir: Path) -> str:
    """Manifest path relative to the checkout root (bare name if outside it)."""
    try:
        return path.relative_to(checkout_dir).as_posix()
    except ValueError:
        return path.name


def _find_line(lines: list[str], name: str) -> int:
    """First 1-indexed line mentioning ``name``; 1 when not found.

    Used for structured manifests (JSON / TOML) where the parser hands back
    values without positions. Best-effort: the declared name almost always
    appears on its own declaration line, and a wrong guess only shifts the
    preview window, never breaks it.
    """
    needle = name.strip().lower()
    if needle:
        for i, line in enumerate(lines, 1):
            if needle in line.lower():
                return i
    return 1


def _add(
    decls: dict[str, Declaration],
    name: str | None,
    constraint: object,
    *,
    path: str,
    line: int,
    scope: str = "prod",
) -> None:
    """Record name→declaration, lower-casing the name and keeping the first hit.

    Blank constraints are skipped (no signal); a loose ``*`` / ``latest`` is kept
    because "this dep floats" is itself meaningful to a triager. When the same
    dep is declared in both a prod and a dev section, the first (prod) hit wins,
    so a dep used in production is never mislabelled dev.
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
    decls.setdefault(
        key, Declaration(constraint=value, path=path, line=max(1, line), scope=scope)
    )


# PEP 508 requirement: a leading package name, an optional [extras] group, then
# the version specifier (which we keep, stopping at any environment marker).
_PEP508_NAME = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;]*)$"
)
# requirements.txt line: name + optional extras + specifier, stopping at markers.
_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;#]*)"
)


def _parse_package_json(root: Path, checkout_dir: Path, decls: dict[str, Declaration]) -> None:
    manifest = root / "package.json"
    raw = _read_text(manifest)
    if raw is None:
        return
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return
    if not isinstance(data, dict):
        return
    path = _rel(manifest, checkout_dir)
    lines = raw.splitlines()
    for section in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        block = data.get(section)
        if isinstance(block, dict):
            # Only devDependencies are dev-only; peer/optional are runtime-relevant.
            scope = "dev" if section == "devDependencies" else "prod"
            for name, constraint in block.items():
                _add(decls, name, constraint, path=path, line=_find_line(lines, name), scope=scope)


def _parse_requirements(root: Path, checkout_dir: Path, decls: dict[str, Declaration]) -> None:
    for manifest in sorted(root.glob("requirements*.txt")):
        raw = _read_text(manifest)
        if raw is None:
            continue
        path = _rel(manifest, checkout_dir)
        # requirements.txt has no dev section, but the conventional filename
        # (requirements-dev.txt, test-requirements.txt) signals dev-only deps.
        tokens = set(re.split(r"[-_.]", manifest.stem.lower()))
        scope = "dev" if tokens & {"dev", "test", "tests", "testing", "development"} else "prod"
        for lineno, line in enumerate(raw.splitlines(), 1):
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
            _add(decls, name, specifier, path=path, line=lineno, scope=scope)


def _iter_pep735_groups(data: dict) -> "list[tuple[str, object]]":
    """Yield (name, constraint) from PEP 735 [dependency-groups] tables.

    These groups (test, lint, docs, …) are development tooling, never shipped.
    Entries are PEP 508 requirement strings or include-group dicts (skipped)."""
    out: list[tuple[str, object]] = []
    groups = data.get("dependency-groups")
    if not isinstance(groups, dict):
        return out
    for members in groups.values():
        if not isinstance(members, list):
            continue
        for member in members:
            if not isinstance(member, str):  # {"include-group": ...} — not a dep
                continue
            m = _PEP508_NAME.match(member)
            if m:
                out.append((m.group(1), m.group(2).strip() or "*"))
    return out


def _iter_poetry_dev_deps(poetry: dict) -> "list[tuple[str, object]]":
    """Yield (name, constraint) from Poetry dev sections (dev groups + legacy)."""
    out: list[tuple[str, object]] = []
    legacy = poetry.get("dev-dependencies")
    if isinstance(legacy, dict):
        out.extend((n, c) for n, c in legacy.items())
    groups = poetry.get("group")
    if isinstance(groups, dict):
        for group in groups.values():
            deps = group.get("dependencies") if isinstance(group, dict) else None
            if isinstance(deps, dict):
                out.extend((n, c) for n, c in deps.items())
    return out


def _parse_pyproject(root: Path, checkout_dir: Path, decls: dict[str, Declaration]) -> None:
    if tomllib is None:
        return
    manifest = root / "pyproject.toml"
    raw = _read_text(manifest)
    if raw is None:
        return
    try:
        data = tomllib.loads(raw)
    except (tomllib.TOMLDecodeError, ValueError):
        return
    path = _rel(manifest, checkout_dir)
    lines = raw.splitlines()

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
                    name = match.group(1)
                    _add(decls, name, match.group(2).strip(), path=path, line=_find_line(lines, name))

    # PEP 735: [dependency-groups] are dev/test/tooling groups, never shipped.
    for name, constraint in _iter_pep735_groups(data):
        _add(decls, name, constraint, path=path, line=_find_line(lines, name), scope="dev")

    # Poetry: [tool.poetry.dependencies] is a table of name→constraint. Dev deps
    # live in [tool.poetry.group.*.dependencies] or the legacy dev-dependencies.
    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            deps = poetry.get("dependencies")
            if isinstance(deps, dict):
                for name, constraint in deps.items():
                    if name.lower() == "python":  # the interpreter, not a dep
                        continue
                    line = _find_line(lines, name)
                    if isinstance(constraint, str):
                        _add(decls, name, constraint, path=path, line=line)
                    elif isinstance(constraint, dict):
                        _add(decls, name, constraint.get("version"), path=path, line=line)
            for name, constraint in _iter_poetry_dev_deps(poetry):
                line = _find_line(lines, name)
                version = constraint if isinstance(constraint, str) else (
                    constraint.get("version") if isinstance(constraint, dict) else None
                )
                _add(decls, name, version, path=path, line=line, scope="dev")


_GOMOD_REQUIRE_LINE = re.compile(r"^([^\s]+)\s+(v[^\s]+)")


def _parse_go_mod(root: Path, checkout_dir: Path, decls: dict[str, Declaration]) -> None:
    manifest = root / "go.mod"
    raw = _read_text(manifest)
    if raw is None:
        return
    path = _rel(manifest, checkout_dir)
    in_block = False
    for lineno, line in enumerate(raw.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if in_block:
            if stripped.startswith(")"):
                in_block = False
                continue
            match = _GOMOD_REQUIRE_LINE.match(stripped)
            if match:
                _add(decls, match.group(1), match.group(2), path=path, line=lineno)
            continue
        if stripped.startswith("require ("):
            in_block = True
            continue
        if stripped.startswith("require "):
            match = _GOMOD_REQUIRE_LINE.match(stripped[len("require "):].strip())
            if match:
                _add(decls, match.group(1), match.group(2), path=path, line=lineno)


_GEMFILE_LINE = re.compile(
    r"""^\s*gem\s+["']([^"']+)["']\s*,\s*["']([^"']+)["']"""
)


def _parse_gemfile(root: Path, checkout_dir: Path, decls: dict[str, Declaration]) -> None:
    manifest = root / "Gemfile"
    raw = _read_text(manifest)
    if raw is None:
        return
    path = _rel(manifest, checkout_dir)
    for lineno, line in enumerate(raw.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _GEMFILE_LINE.match(stripped)
        if match:
            _add(decls, match.group(1), match.group(2), path=path, line=lineno)


def _parse_cargo_toml(root: Path, checkout_dir: Path, decls: dict[str, Declaration]) -> None:
    if tomllib is None:
        return
    manifest = root / "Cargo.toml"
    raw = _read_text(manifest)
    if raw is None:
        return
    try:
        data = tomllib.loads(raw)
    except (tomllib.TOMLDecodeError, ValueError):
        return
    path = _rel(manifest, checkout_dir)
    lines = raw.splitlines()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        # dev-dependencies (tests) and build-dependencies (compile-time) aren't
        # in the shipped artifact; only [dependencies] is production runtime.
        scope = "prod" if section == "dependencies" else "dev"
        for name, constraint in block.items():
            line = _find_line(lines, name)
            if isinstance(constraint, str):
                _add(decls, name, constraint, path=path, line=line, scope=scope)
            elif isinstance(constraint, dict):
                _add(decls, name, constraint.get("version"), path=path, line=line, scope=scope)


def _localname(tag: str) -> str:
    """Strip an XML namespace (``{uri}local``) down to the local tag name."""
    return tag.rsplit("}", 1)[-1]


def _parse_pom_xml(root: Path, checkout_dir: Path, decls: dict[str, Declaration]) -> None:
    manifest = root / "pom.xml"
    raw = _read_text(manifest)
    if raw is None:
        return
    try:
        tree = ET.fromstring(raw)
    except ET.ParseError:
        return
    path = _rel(manifest, checkout_dir)
    lines = raw.splitlines()
    for dep in tree.iter():
        if _localname(dep.tag) != "dependency":
            continue
        fields = {_localname(c.tag): (c.text or "").strip() for c in dep}
        artifact = fields.get("artifactId")
        version = fields.get("version")
        if not artifact or not version or version.startswith("${"):
            continue  # unresolved property version carries no usable range
        scope = "dev" if fields.get("scope") in ("test", "provided") else "prod"
        _add(decls, artifact, version, path=path, line=_find_line(lines, artifact), scope=scope)


def _parse_composer_json(root: Path, checkout_dir: Path, decls: dict[str, Declaration]) -> None:
    manifest = root / "composer.json"
    raw = _read_text(manifest)
    if raw is None:
        return
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return
    if not isinstance(data, dict):
        return
    path = _rel(manifest, checkout_dir)
    lines = raw.splitlines()
    for section, scope in (("require", "prod"), ("require-dev", "dev")):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, constraint in block.items():
            if isinstance(name, str) and "/" not in name:
                continue  # skip platform reqs like "php" / "ext-*"
            _add(decls, name, constraint, path=path, line=_find_line(lines, name), scope=scope)


def _parse_csproj(root: Path, checkout_dir: Path, decls: dict[str, Declaration]) -> None:
    for manifest in sorted(root.glob("*.csproj")):
        raw = _read_text(manifest)
        if raw is None:
            continue
        try:
            tree = ET.fromstring(raw)
        except ET.ParseError:
            continue
        path = _rel(manifest, checkout_dir)
        lines = raw.splitlines()
        for ref in tree.iter():
            if _localname(ref.tag) != "PackageReference":
                continue
            name = ref.get("Include") or ref.get("Update")
            version = ref.get("Version")
            if not name or not version:
                continue
            _add(decls, name, version, path=path, line=_find_line(lines, name))


_PARSERS = (
    _parse_package_json,
    _parse_requirements,
    _parse_pyproject,
    _parse_go_mod,
    _parse_gemfile,
    _parse_cargo_toml,
    _parse_pom_xml,
    _parse_composer_json,
    _parse_csproj,
)


def parse_declared_ranges(checkout_dir: Path) -> dict[str, Declaration]:
    """Scan a checkout for direct-dependency manifests and return name→declaration.

    Discovers manifests anywhere in the checkout (bounded walk, see
    ``_discover_manifest_dirs``) and parses the project's own declared direct
    dependencies across npm, PyPI, Go, Ruby, Cargo, Maven, Composer and NuGet.
    Names are lower-cased; on collisions the first declaration wins. Every
    per-file read and parse is best-effort — a missing or malformed manifest is
    skipped, never raised — so this is always safe to call.
    """
    decls: dict[str, Declaration] = {}
    for root in _discover_manifest_dirs(checkout_dir):
        for parser in _PARSERS:
            try:
                parser(root, checkout_dir, decls)
            except Exception:  # noqa: BLE001 - enrichment is strictly best-effort
                logger.debug("declared-range parser %s failed", parser.__name__)
    return decls


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


def _stamp(props: list, name: str, value: str) -> None:
    props.append({"name": name, "value": value})


def annotate_sbom_with_declared_ranges(
    sbom_path: Path, decls: dict[str, Declaration], checkout_dir: Path
) -> int:
    """Stamp ``aegis:declared_*`` onto components matching a declared dependency.

    Loads the CycloneDX JSON at ``sbom_path``, matches each component by its
    lower-cased ``name`` (and, for namespaced purls, the bare package name) and
    appends the declared range, manifest path, declaration line and — when the
    manifest is still readable under ``checkout_dir`` — a small surrounding code
    window. Components already carrying ``aegis:declared_range`` are left
    untouched so re-running is idempotent. Fully guarded: a non-dict SBOM,
    missing/non-list components, or non-dict component entries yield 0 rather
    than raising. Returns the number of components annotated.
    """
    if not decls:
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

        decl = next((decls[c] for c in candidates if c in decls), None)
        if decl is None:
            continue

        props = component.get("properties")
        if not isinstance(props, list):
            props = []
            component["properties"] = props
        if any(
            isinstance(p, dict) and p.get("name") == _RANGE_PROPERTY for p in props
        ):
            continue  # idempotent — don't duplicate on re-run

        _stamp(props, _RANGE_PROPERTY, decl.constraint)
        _stamp(props, _PATH_PROPERTY, decl.path)
        _stamp(props, _LINE_PROPERTY, str(decl.line))
        _stamp(props, _SCOPE_PROPERTY, decl.scope)
        window, win_start = read_code_window(
            checkout_dir, decl.path, decl.line, radius=_WINDOW_RADIUS
        )
        if window is not None and win_start is not None:
            _stamp(props, _SNIPPET_PROPERTY, window)
            _stamp(props, _SNIPPET_START_PROPERTY, str(win_start))
        annotated += 1

    if annotated:
        sbom_path.write_text(json.dumps(data, separators=(",", ":")))
    return annotated
