"""SBOM diff engine — Phase 37.

Compares two CycloneDX JSON SBOMs and classifies component-level changes
into added / removed / version-changed / unchanged buckets.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass


@dataclass
class ComponentDiff:
    added: list[dict]           # components present in `to` but not `from`
    removed: list[dict]         # components present in `from` but not `to`
    version_changed: list[dict] # {"name", "from_version", "to_version", "purl"}
    unchanged_count: int


def _strip_purl_version(purl: str) -> str:
    """Drop the ``@version`` from a purl so a pure version bump keeps a stable
    identity. ``pkg:npm/lodash@4.17.21`` -> ``pkg:npm/lodash``; qualifiers and
    subpath are preserved and the encoded ``@`` (``%40``) in a scoped name is
    untouched (only the literal version separator is removed)."""
    if not purl or not purl.startswith("pkg:"):
        return purl or ""
    cut = len(purl)
    for sep in ("?", "#"):
        i = purl.find(sep)
        if i != -1:
            cut = min(cut, i)
    path, suffix = purl[:cut], purl[cut:]
    at = path.rfind("@")
    if at != -1:
        path = path[:at]
    return path + suffix


def _identity(c: dict) -> tuple[str | None, str]:
    """Version-insensitive component identity: (name, version-stripped purl).
    Real CycloneDX purls embed the version, so keying on the raw purl would
    split every bump into an add+remove pair; stripping the version lets a pure
    bump classify as version_changed instead."""
    return (c.get("name"), _strip_purl_version(c.get("purl", "")))


def diff_sboms(from_sbom: dict, to_sbom: dict) -> ComponentDiff:
    """Diff two CycloneDX JSON SBOMs by component name + version-stripped purl.

    Identity ignores the purl's version so a pure version bump on the same
    package appears in version_changed rather than as a separate add+remove
    pair. Components without a purl use (name, "") as their key, which is still
    unambiguous for most ecosystems.

    When a package coexists in multiple versions on a side (npm hoisting,
    stacked container layers) the bump pairing is ambiguous, so that identity is
    diffed by exact version instead (add/remove/unchanged, no version_changed) —
    this stops a shadowed vulnerable copy from being mis-reported as resolved.

    A non-CycloneDX side (e.g. a corrupt or non-dict blob) contributes no
    components rather than raising.
    """
    def _components(sbom: dict) -> list[dict]:
        comps = sbom.get("components", []) if isinstance(sbom, dict) else []
        return [c for c in comps if isinstance(c, dict)] if isinstance(comps, list) else []

    def _group(components: list[dict]) -> dict[tuple, list[dict]]:
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for c in components:
            groups[_identity(c)].append(c)
        return groups

    from_groups = _group(_components(from_sbom))
    to_groups = _group(_components(to_sbom))

    added: list[dict] = []
    removed: list[dict] = []
    version_changed: list[dict] = []
    unchanged = 0

    # Sort keys (tuples may carry a None name) for deterministic output.
    for key in sorted(set(from_groups) | set(to_groups), key=lambda k: (k[0] or "", k[1])):
        f_list = from_groups.get(key, [])
        t_list = to_groups.get(key, [])

        if len(f_list) <= 1 and len(t_list) <= 1:
            # The common case: at most one component per identity on each side.
            f = f_list[0] if f_list else None
            t = t_list[0] if t_list else None
            if f is not None and t is not None:
                if f.get("version") != t.get("version"):
                    version_changed.append(
                        {
                            "name": key[0],
                            "purl": key[1],
                            "from_version": f.get("version"),
                            "to_version": t.get("version"),
                            # Raw CycloneDX licenses[] from each side, classified
                            # by the resolver so a bump that changes the license
                            # surfaces.
                            "from_licenses": f.get("licenses") or [],
                            "to_licenses": t.get("licenses") or [],
                        }
                    )
                else:
                    unchanged += 1
            elif t is not None:
                added.append(t)
            elif f is not None:
                removed.append(f)
        else:
            # The same package coexists in multiple versions on at least one side
            # (npm hoisting, stacked container layers). Collapsing them to one
            # identity would drop the shadowed copies and could report a vuln
            # "resolved" while a vulnerable version still ships — so diff by exact
            # version instead. No version_changed is emitted: with several
            # versions present there is no unambiguous from->to pairing.
            f_by_ver = {c.get("version"): c for c in f_list}
            t_by_ver = {c.get("version"): c for c in t_list}
            for v in sorted(set(t_by_ver) - set(f_by_ver), key=lambda x: x or ""):
                added.append(t_by_ver[v])
            for v in sorted(set(f_by_ver) - set(t_by_ver), key=lambda x: x or ""):
                removed.append(f_by_ver[v])
            unchanged += len(set(f_by_ver) & set(t_by_ver))

    return ComponentDiff(
        added=added,
        removed=removed,
        version_changed=version_changed,
        unchanged_count=unchanged,
    )
