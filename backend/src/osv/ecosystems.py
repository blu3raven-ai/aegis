"""OSV ecosystem normalization and version-scheme resolution.

Bridges three vocabularies that name the same thing differently:

- **purl type** — what ``SbomComponent.ecosystem`` stores, derived from the
  package URL (e.g. ``npm``, ``pypi``, ``golang``, ``deb``).
- **OSV ecosystem** — what ``osv_vulnerable_ranges.ecosystem`` stores, taken
  from each advisory's ``affected[].package.ecosystem`` (e.g. ``npm``, ``PyPI``,
  ``Go``, ``Debian:11``). OSV names are case-sensitive and distro entries carry
  a release suffix.
- **univers Version class** — the comparison scheme for that ecosystem.

The matcher uses this module to turn an SBOM component into the OSV ecosystem to
query and the version class to compare with.
"""
from __future__ import annotations

import re

from univers import versions as _V

# purl type -> OSV base ecosystem (the GCS bucket dir name). Distro types are
# refined further by purl namespace in osv_base_ecosystem().
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

# purl namespace -> OSV ecosystem, for distro package types where the same purl
# type (deb/apk/rpm) spans multiple OSV ecosystems.
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

# OSV base ecosystem -> univers Version class. Ecosystems without a dedicated
# univers class fall back to a scheme with compatible ordering.
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

DISTRO_ECOSYSTEMS = frozenset(
    {"Debian", "Ubuntu", "Alpine", "Wolfi", "Chainguard",
     "Red Hat", "Rocky Linux", "AlmaLinux", "SUSE", "openSUSE"}
)

# Canonical fetch list (correct OSV casing). Language ecosystems + the distro
# ecosystems needed for container OS-package matching. Each {name}/all.zip
# bundles every release; the per-release suffix lives inside each advisory.
DEFAULT_FETCH_ECOSYSTEMS: tuple[str, ...] = (
    "npm", "PyPI", "Maven", "Go", "crates.io", "RubyGems", "NuGet",
    "Packagist", "Hex", "Pub",
    "Debian", "Ubuntu", "Alpine", "Wolfi", "Chainguard",
    "Red Hat", "Rocky Linux", "AlmaLinux", "SUSE", "openSUSE",
)


def osv_ecosystem_base(osv_ecosystem: str) -> str:
    """Strip the release suffix from an OSV ecosystem (``Debian:11`` -> ``Debian``)."""
    return osv_ecosystem.split(":", 1)[0]


def osv_base_ecosystem(purl_type: str, namespace: str | None = None) -> str | None:
    """Resolve an SBOM component's purl type (+ namespace) to its OSV base ecosystem.

    Distro types (``deb``/``apk``/``rpm``) are disambiguated by namespace
    (``pkg:deb/ubuntu/...`` -> ``Ubuntu``). Returns None for unmapped types so
    the caller can skip rather than mis-match.
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


# Distro qualifier prefix -> OSV base, but ONLY for distros whose OSV release
# ecosystem is EXACTLY `<Base>:<release>` with the release copied verbatim from
# the purl `distro=` qualifier. Today that is Debian alone: OSV stores Debian as
# plain `Debian:11`/`Debian:12`, so distro=debian-11 -> Debian:11 matches exactly
# (and codenames like debian-trixie fail the numeric regex below -> no narrowing).
#
# Deliberately EXCLUDED so the matcher falls back to unnarrowed base matching
# rather than risk dropping a real advisory (a false negative):
#   - Ubuntu — OSV suffixes LTS releases as `Ubuntu:22.04:LTS` (and `Ubuntu:Pro:…`),
#     not the bare `Ubuntu:22.04` the purl carries, so exact-equality narrowing
#     would skip every LTS advisory. Needs release-segment-aware matching,
#     validated against the live mirror, before it can be enabled.
#   - Alpine (`v` prefix: `Alpine:v3.18`) and the RPM family — same verbatim mismatch.
_VERBATIM_RELEASE_DISTROS = {"debian": "Debian"}


def osv_release_ecosystem(distro: str | None) -> str | None:
    """Resolve a component's *release-specific* OSV ecosystem (e.g. ``Debian:11``)
    from its purl ``distro=`` qualifier, or None when the release can't be mapped
    with confidence. None means "don't narrow" — the matcher keeps testing the
    component against all releases of the base, which over-reports but never
    drops a real advisory.
    """
    if not distro:
        return None
    name, sep, release = distro.strip().lower().partition("-")
    if not sep or not release:
        return None
    base = _VERBATIM_RELEASE_DISTROS.get(name)
    if base is None:
        return None
    # Only a plain dotted-numeric release maps verbatim; anything else (codenames,
    # suffixes) is left to fall back rather than guessed.
    if not re.fullmatch(r"\d+(\.\d+)*", release):
        return None
    return f"{base}:{release}"


def version_class_for(osv_ecosystem: str) -> type | None:
    """Return the univers Version class for an OSV ecosystem (release suffix tolerated)."""
    return _OSV_TO_VERSION_CLASS.get(osv_ecosystem_base(osv_ecosystem))
