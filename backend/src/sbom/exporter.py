"""SBOM format conversion — CycloneDX JSON is the internal storage format.

Supported output formats
------------------------
cyclonedx-json     passthrough (no conversion needed)
cyclonedx-xml      CycloneDX → XML (minimal hand-written serializer; no third-party dep)
spdx-json          CycloneDX → SPDX 2.3 JSON (field mapping defined by the SPDX spec)
spdx-tag-value     SPDX JSON → SPDX tag-value text (manual serialization)

All four formats are fully implemented with hand-written serializers and no
third-party dependency.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any


SUPPORTED_FORMATS = frozenset(
    {"cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag-value"}
)


class SbomExporter:
    """Convert an in-memory CycloneDX JSON SBOM dict to the requested format.

    All public methods return a UTF-8 string.  The caller decides whether to
    write it to a file, return it from an HTTP endpoint, etc.
    """

    def export(self, sbom: dict[str, Any], fmt: str) -> str:
        """Return the SBOM serialised as *fmt*.

        Parameters
        ----------
        sbom:
            Parsed CycloneDX JSON dict in CycloneDX format.
        fmt:
            One of the SUPPORTED_FORMATS strings.

        Raises
        ------
        ValueError
            When fmt is not a recognised format string.
        """
        if fmt not in SUPPORTED_FORMATS:
            raise ValueError(
                f"Unknown format '{fmt}'. "
                f"Supported formats: {', '.join(sorted(SUPPORTED_FORMATS))}"
            )

        if fmt == "cyclonedx-json":
            return self._to_cyclonedx_json(sbom)
        if fmt == "cyclonedx-xml":
            return self._to_cyclonedx_xml(sbom)
        if fmt == "spdx-json":
            return self._to_spdx_json(sbom)
        if fmt == "spdx-tag-value":
            return self._to_spdx_tag_value(sbom)

        # Unreachable — kept for exhaustiveness
        raise ValueError(f"Unhandled format: {fmt}")  # pragma: no cover

    # ------------------------------------------------------------------
    # CycloneDX JSON — passthrough
    # ------------------------------------------------------------------

    def _to_cyclonedx_json(self, sbom: dict[str, Any]) -> str:
        return json.dumps(sbom, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # CycloneDX XML — minimal serializer
    # ------------------------------------------------------------------

    def _to_cyclonedx_xml(self, sbom: dict[str, Any]) -> str:
        """Serialize CycloneDX JSON to CycloneDX XML.

        Only the most common fields are mapped.  Uncommon extension fields
        (e.g. externalReferences, services) are silently dropped — this is
        intentional: the goal is interoperability for compliance tools, not
        lossless round-trips.
        """
        spec = sbom.get("specVersion", "1.4")
        ns = f"http://cyclonedx.org/schema/bom/{spec}"
        ET.register_namespace("", ns)

        bom_el = ET.Element(f"{{{ns}}}bom")
        serial = sbom.get("serialNumber", "")
        if serial:
            bom_el.set("serialNumber", str(serial))
        bom_el.set("version", str(sbom.get("version", 1)))

        # metadata
        meta = sbom.get("metadata", {})
        if isinstance(meta, dict) and meta:
            meta_el = ET.SubElement(bom_el, f"{{{ns}}}metadata")
            if ts := meta.get("timestamp"):
                ts_el = ET.SubElement(meta_el, f"{{{ns}}}timestamp")
                ts_el.text = str(ts)

            for tool in meta.get("tools", []):
                if not isinstance(tool, dict):
                    continue
                tools_el = meta_el.find(f"{{{ns}}}tools")
                if tools_el is None:
                    tools_el = ET.SubElement(meta_el, f"{{{ns}}}tools")
                tool_el = ET.SubElement(tools_el, f"{{{ns}}}tool")
                if name := tool.get("name"):
                    n_el = ET.SubElement(tool_el, f"{{{ns}}}name")
                    n_el.text = str(name)
                if version := tool.get("version"):
                    v_el = ET.SubElement(tool_el, f"{{{ns}}}version")
                    v_el.text = str(version)

        # components
        comps = sbom.get("components", [])
        if comps:
            comps_el = ET.SubElement(bom_el, f"{{{ns}}}components")
            for comp in comps:
                if not isinstance(comp, dict):
                    continue
                c_el = ET.SubElement(comps_el, f"{{{ns}}}component")
                # ElementTree refuses non-string text/attrs; SBOM values derive
                # from scanned artifacts and can be malformed (e.g. a numeric
                # version), so coerce defensively rather than 500 the export.
                c_el.set("type", str(comp.get("type", "library")))
                if bom_ref := comp.get("bom-ref"):
                    c_el.set("bom-ref", str(bom_ref))
                for field in ("name", "version", "purl", "description"):
                    if val := comp.get(field):
                        f_el = ET.SubElement(c_el, f"{{{ns}}}{field}")
                        f_el.text = str(val)
                # licenses
                for lic in comp.get("licenses", []):
                    if not isinstance(lic, dict):
                        continue
                    lics_el = c_el.find(f"{{{ns}}}licenses")
                    if lics_el is None:
                        lics_el = ET.SubElement(c_el, f"{{{ns}}}licenses")
                    lic_el = ET.SubElement(lics_el, f"{{{ns}}}license")
                    lic_obj = lic.get("license")
                    lic_id = (lic_obj.get("id") if isinstance(lic_obj, dict) else None) or lic.get("expression")
                    if lic_id:
                        id_el = ET.SubElement(lic_el, f"{{{ns}}}id")
                        id_el.text = str(lic_id)

        # dependencies
        deps = sbom.get("dependencies", [])
        if deps:
            deps_el = ET.SubElement(bom_el, f"{{{ns}}}dependencies")
            for dep in deps:
                if not isinstance(dep, dict):
                    continue
                dep_el = ET.SubElement(deps_el, f"{{{ns}}}dependency")
                dep_el.set("ref", str(dep.get("ref", "")))
                for sub in dep.get("dependsOn", []):
                    sub_el = ET.SubElement(dep_el, f"{{{ns}}}dependency")
                    sub_el.set("ref", str(sub))

        ET.indent(bom_el, space="  ")
        xml_str = ET.tostring(bom_el, encoding="unicode", xml_declaration=False)
        return f'<?xml version="1.0" encoding="UTF-8"?>\n{xml_str}'

    # ------------------------------------------------------------------
    # SPDX JSON — CycloneDX → SPDX 2.3 field mapping
    # ------------------------------------------------------------------

    def _to_spdx_json(self, sbom: dict[str, Any]) -> str:
        """Convert CycloneDX JSON to SPDX 2.3 JSON.

        Field mapping follows the SPDX 2.3 spec and the CycloneDX/SPDX
        interoperability guidance.  Fields without a natural counterpart are
        assigned sensible defaults so the output validates against SPDX tools.
        """
        meta = sbom.get("metadata", {})
        if not isinstance(meta, dict):
            meta = {}
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        created = meta.get("timestamp", now_iso)

        # creators — map CycloneDX tools array to SPDX Tool: entries
        creators: list[str] = []
        for tool in meta.get("tools", []):
            if not isinstance(tool, dict):
                continue
            name = tool.get("name", "unknown")
            version = tool.get("version", "")
            creators.append(f"Tool: {name}-{version}" if version else f"Tool: {name}")
        if not creators:
            creators = ["Tool: aegis-sbom-exporter"]

        meta_component = meta.get("component")
        doc_name = str(
            (meta_component.get("name") if isinstance(meta_component, dict) else None)
            or sbom.get("serialNumber", "")
            or "unnamed-sbom"
        )

        # Sanitize SPDX document name — must not contain spaces in the doc namespace
        safe_name = re.sub(r"\s+", "-", doc_name)

        spdx_doc: dict[str, Any] = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {
                "created": created,
                "creators": creators,
            },
            "name": doc_name,
            "dataLicense": "CC0-1.0",
            "documentNamespace": (
                f"https://spdx.org/spdxdocs/{safe_name}-"
                f"{sbom.get('serialNumber', 'no-serial')}"
            ),
            "packages": [],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-Package-0",
                }
            ],
        }

        packages: list[dict[str, Any]] = []
        bom_ref_to_spdx: dict[str, str] = {}

        for idx, comp in enumerate(sbom.get("components", [])):
            if not isinstance(comp, dict):
                continue
            spdx_id = f"SPDXRef-Package-{idx}"
            bom_ref = comp.get("bom-ref", f"comp-{idx}")
            bom_ref_to_spdx[bom_ref] = spdx_id

            # License — prefer the first license id; fall back to NOASSERTION
            licenses = comp.get("licenses", [])
            first = licenses[0] if licenses else None
            if isinstance(first, dict):
                lic_obj = first.get("license")
                lic_id = (
                    (lic_obj.get("id") if isinstance(lic_obj, dict) else None)
                    or first.get("expression")
                    or "NOASSERTION"
                )
            else:
                lic_id = "NOASSERTION"

            pkg: dict[str, Any] = {
                "SPDXID": spdx_id,
                "name": comp.get("name", ""),
                "versionInfo": comp.get("version", ""),
                "licenseDeclared": lic_id,
                "licenseConcluded": lic_id,
                "copyrightText": "NOASSERTION",
                "downloadLocation": comp.get("purl") or "NOASSERTION",
                "filesAnalyzed": False,
            }
            if purl := comp.get("purl"):
                pkg["externalRefs"] = [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": purl,
                    }
                ]
            packages.append(pkg)

        spdx_doc["packages"] = packages

        # Map CycloneDX dependency graph → SPDX DEPENDS_ON relationships
        relationships: list[dict[str, Any]] = spdx_doc["relationships"]
        for dep in sbom.get("dependencies", []):
            if not isinstance(dep, dict):
                continue
            src_ref = dep.get("ref", "")
            src_spdx = bom_ref_to_spdx.get(src_ref)
            if src_spdx is None:
                continue
            for dep_on in dep.get("dependsOn", []):
                tgt_spdx = bom_ref_to_spdx.get(dep_on)
                if tgt_spdx is None:
                    continue
                relationships.append(
                    {
                        "spdxElementId": src_spdx,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": tgt_spdx,
                    }
                )

        return json.dumps(spdx_doc, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # SPDX tag-value — serialise from SPDX JSON
    # ------------------------------------------------------------------

    def _to_spdx_tag_value(self, sbom: dict[str, Any]) -> str:
        """Convert CycloneDX JSON → SPDX tag-value text via the SPDX JSON intermediate.

        SPDX tag-value is a line-oriented key: value format defined in the
        SPDX 2.3 spec §4.  Only the mandatory and most common optional fields
        are emitted — unknown fields are silently dropped.
        """
        spdx_json_str = self._to_spdx_json(sbom)
        spdx = json.loads(spdx_json_str)

        lines: list[str] = []

        def _tag(name: str, value: Any) -> None:
            if value is not None and value != "":
                lines.append(f"{name}: {value}")

        # Document-level fields
        _tag("SPDXVersion", spdx.get("spdxVersion", "SPDX-2.3"))
        _tag("DataLicense", spdx.get("dataLicense", "CC0-1.0"))
        _tag("SPDXID", spdx.get("SPDXID", "SPDXRef-DOCUMENT"))
        _tag("DocumentName", spdx.get("name", ""))
        _tag("DocumentNamespace", spdx.get("documentNamespace", ""))

        ci = spdx.get("creationInfo", {})
        for creator in ci.get("creators", []):
            _tag("Creator", creator)
        _tag("Created", ci.get("created", ""))

        lines.append("")

        # Packages
        for pkg in spdx.get("packages", []):
            _tag("PackageName", pkg.get("name", ""))
            _tag("SPDXID", pkg.get("SPDXID", ""))
            _tag("PackageVersion", pkg.get("versionInfo", ""))
            _tag("PackageDownloadLocation", pkg.get("downloadLocation", "NOASSERTION"))
            _tag("FilesAnalyzed", str(pkg.get("filesAnalyzed", False)).lower())
            _tag("PackageLicenseConcluded", pkg.get("licenseConcluded", "NOASSERTION"))
            _tag("PackageLicenseDeclared", pkg.get("licenseDeclared", "NOASSERTION"))
            _tag("PackageCopyrightText", pkg.get("copyrightText", "NOASSERTION"))
            for ext_ref in pkg.get("externalRefs", []):
                _tag(
                    "ExternalRef",
                    f"{ext_ref['referenceCategory']} {ext_ref['referenceType']} {ext_ref['referenceLocator']}",
                )
            lines.append("")

        # Relationships
        for rel in spdx.get("relationships", []):
            _tag(
                "Relationship",
                f"{rel['spdxElementId']} {rel['relationshipType']} {rel['relatedSpdxElement']}",
            )

        return "\n".join(lines)
