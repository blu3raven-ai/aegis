"""SBOM diff engine — Phase 37.

Compares two CycloneDX JSON SBOMs and classifies component-level changes
into added / removed / version-changed / unchanged buckets.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ComponentDiff:
    added: list[dict]           # components present in `to` but not `from`
    removed: list[dict]         # components present in `from` but not `to`
    version_changed: list[dict] # {"name", "from_version", "to_version", "purl"}
    unchanged_count: int


def diff_sboms(from_sbom: dict, to_sbom: dict) -> ComponentDiff:
    """Diff two CycloneDX JSON SBOMs by component name + purl.

    Identity key is (name, purl) so a pure version bump on the same package
    appears in version_changed rather than as a separate add+remove pair.
    Components without a purl use (name, "") as their key, which is still
    unambiguous for most ecosystems.
    """
    from_components = {
        (c.get("name"), c.get("purl", "")): c
        for c in from_sbom.get("components", [])
    }
    to_components = {
        (c.get("name"), c.get("purl", "")): c
        for c in to_sbom.get("components", [])
    }

    from_keys = set(from_components)
    to_keys = set(to_components)

    added_keys = to_keys - from_keys
    removed_keys = from_keys - to_keys
    common_keys = from_keys & to_keys

    version_changed: list[dict] = []
    unchanged = 0
    for key in common_keys:
        f = from_components[key]
        t = to_components[key]
        if f.get("version") != t.get("version"):
            version_changed.append(
                {
                    "name": key[0],
                    "purl": key[1],
                    "from_version": f.get("version"),
                    "to_version": t.get("version"),
                }
            )
        else:
            unchanged += 1

    return ComponentDiff(
        added=[to_components[k] for k in added_keys],
        removed=[from_components[k] for k in removed_keys],
        version_changed=version_changed,
        unchanged_count=unchanged,
    )
