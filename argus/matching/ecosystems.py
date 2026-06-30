"""Ecosystem normalization and version-scheme resolution for the matcher.

Bridges three vocabularies that name the same thing differently:

- **purl type** — derived from the package URL (``npm``, ``pypi``, ``golang``...).
- **OSV ecosystem** — what the premium feed records store, using OSV's casing
  (``npm``, ``PyPI``, ``Go``, ``Debian``...).
- **univers Version class** — the comparison scheme for that ecosystem.

The matcher uses this to turn a component coordinate into the OSV ecosystem to
look up and the version class to compare with. Standalone (depends only on
``univers``) so the Argus service carries no Aegis import.
"""
from __future__ import annotations

from univers import versions as _V

from argus.matching.models import VulnerableRange

_PURL_TYPE_TO_OSV: dict[str, str] = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "go": "Go",
    "cargo": "crates.io",
    "crates": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
    "deb": "Debian",
    "apk": "Alpine",
    "rpm": "Red Hat",
}

# Distro purl types span several OSV ecosystems; disambiguate by purl namespace.
_DEB_NAMESPACE_TO_OSV = {"debian": "Debian", "ubuntu": "Ubuntu"}
_APK_NAMESPACE_TO_OSV = {"alpine": "Alpine", "wolfi": "Wolfi", "chainguard": "Chainguard"}
_RPM_NAMESPACE_TO_OSV = {
    "redhat": "Red Hat",
    "rhel": "Red Hat",
    "rocky": "Rocky Linux",
    "rockylinux": "Rocky Linux",
    "almalinux": "AlmaLinux",
    "alma": "AlmaLinux",
    "suse": "SUSE",
    "sles": "SUSE",
    "opensuse": "openSUSE",
}

_OSV_TO_VERSION_CLASS: dict[str, type] = {
    "npm": _V.SemverVersion,
    "PyPI": _V.PypiVersion,
    "Maven": _V.MavenVersion,
    "Go": _V.GolangVersion,
    "crates.io": _V.SemverVersion,
    "RubyGems": _V.RubygemsVersion,
    "NuGet": _V.NugetVersion,
    "Packagist": _V.ComposerVersion,
    "Hex": _V.SemverVersion,
    "Pub": _V.SemverVersion,
    "Debian": _V.DebianVersion,
    "Ubuntu": _V.DebianVersion,
    "Alpine": _V.AlpineLinuxVersion,
    "Wolfi": _V.AlpineLinuxVersion,
    "Chainguard": _V.AlpineLinuxVersion,
    "Red Hat": _V.RpmVersion,
    "Rocky Linux": _V.RpmVersion,
    "AlmaLinux": _V.RpmVersion,
    "SUSE": _V.RpmVersion,
    "openSUSE": _V.RpmVersion,
}


def osv_ecosystem_base(osv_ecosystem: str) -> str:
    """Strip a release suffix from an OSV ecosystem (``Debian:11`` -> ``Debian``)."""
    return osv_ecosystem.split(":", 1)[0]


def osv_base_ecosystem(purl_type: str, namespace: str | None = None) -> str | None:
    """Resolve a purl type (+ namespace) to its OSV base ecosystem, or None.

    Distro types (``deb``/``apk``/``rpm``) are disambiguated by namespace
    (``pkg:deb/ubuntu/...`` -> ``Ubuntu``). None means the type is unmapped, so
    the caller skips it rather than mis-matching.
    """
    t = (purl_type or "").lower()
    ns = (namespace or "").lower()
    if t == "deb":
        return _DEB_NAMESPACE_TO_OSV.get(ns, "Debian")
    if t == "apk":
        return _APK_NAMESPACE_TO_OSV.get(ns, "Alpine")
    if t == "rpm":
        return _RPM_NAMESPACE_TO_OSV.get(ns, "Red Hat")
    return _PURL_TYPE_TO_OSV.get(t)


def version_class_for(osv_ecosystem: str) -> type | None:
    """Return the univers Version class for an OSV ecosystem (suffix tolerated)."""
    return _OSV_TO_VERSION_CLASS.get(osv_ecosystem_base(osv_ecosystem))


def version_in_range(version: str, vrange: VulnerableRange, version_cls: type) -> bool:
    """Test whether ``version`` falls inside ``vrange`` (OSV half-open semantics).

    Unparseable versions fail closed for that single comparison (return False)
    rather than raising — one bad version string must never crash a batch.
    """
    try:
        v = version_cls(version)
    except Exception:  # noqa: BLE001 - unparseable version is simply not comparable
        return False

    introduced = vrange.introduced
    if introduced and introduced != "0":
        try:
            if v < version_cls(introduced):
                return False
        except Exception:  # noqa: BLE001
            return False
    if vrange.fixed:
        try:
            if not (v < version_cls(vrange.fixed)):
                return False
        except Exception:  # noqa: BLE001
            return False
    if vrange.last_affected:
        try:
            if v > version_cls(vrange.last_affected):
                return False
        except Exception:  # noqa: BLE001
            return False
    return True
