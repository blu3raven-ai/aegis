"""RulePackLoader — load and manage rule packs from multiple sources.

Rule packs are named collections of Rule instances. The engine's reload_rules()
method drains in-flight dispatches, swaps in a fresh set of packs from this
loader, then resumes. No engine restart required.

Sources:
  builtin  — the nine rules shipped with Aegis
  argus    — rule packs pushed by the Argus intelligence service
  local-file — filesystem path for operator-supplied rules (dev/testing)
"""
from __future__ import annotations

import importlib.util
import logging
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.argus.connector import ArgusConnector
    from src.correlation.rule import Rule

logger = logging.getLogger(__name__)


@dataclass
class RulePack:
    pack_id: str
    version: str
    rules: list["Rule"]
    source: str  # "builtin" | "argus" | "local-file"


class RulePackLoader:
    """Assembles rule packs from all configured sources.

    Designed to be called on each hot-reload cycle. Every call to
    load_builtin() / load_from_argus() / load_from_path() is idempotent —
    it replaces whatever pack with the same pack_id was loaded previously.
    """

    def __init__(self, argus_connector: "ArgusConnector | None" = None) -> None:
        self._connector = argus_connector
        self._packs: dict[str, RulePack] = {}

    # ── source loaders ────────────────────────────────────────────────────────

    def load_builtin(self) -> RulePack:
        """Load (or reload) the built-in rule pack from the rules package."""
        from src.correlation.rules import (
            IntelMatchRule,
            ReachableCveRule,
            SecretToResourceRule,
            LifecycleRule,
            EpssEscalationRule,
            PublicExposureDataHandlingRule,
            CrossRepoCveClusterRule,
            ContainerBaseImagePropagationRule,
            CredentialReuseChainRule,
            AttributionRollupRule,
            SeverityVelocityRule,
            MttrTrackingRule,
            AnomalyDetectionRule,
        )

        pack = RulePack(
            pack_id="builtin",
            version="11.0.0",
            source="builtin",
            rules=[
                IntelMatchRule(),
                ReachableCveRule(),
                SecretToResourceRule(),
                LifecycleRule(),
                EpssEscalationRule(),
                PublicExposureDataHandlingRule(),
                CrossRepoCveClusterRule(),
                ContainerBaseImagePropagationRule(),
                CredentialReuseChainRule(),
                AttributionRollupRule(),
                SeverityVelocityRule(),
                MttrTrackingRule(),
                AnomalyDetectionRule(),
            ],
        )
        self._packs[pack.pack_id] = pack
        logger.info("rule_pack_loader: loaded builtin pack (%d rules)", len(pack.rules))
        return pack

    def load_from_argus(self) -> list[RulePack]:
        """Fetch rule packs from the Argus connector.

        Argus returns serialized rule descriptors. Each descriptor must contain:
          pack_id, version, and a list of fully-qualified class names (or inline
          Python source). Only class-name references are supported today;
          inline source is a future extension point.

        Returns an empty list when Argus is unconfigured or returns nothing.
        """
        if self._connector is None:
            return []

        try:
            raw_packs = self._connector.get_rule_packs()
        except Exception:
            logger.exception("rule_pack_loader: failed to fetch rule packs from Argus")
            return []

        loaded: list[RulePack] = []
        for raw in raw_packs or []:
            pack = self._load_argus_pack(raw)
            if pack is not None:
                self._packs[pack.pack_id] = pack
                loaded.append(pack)

        logger.info("rule_pack_loader: loaded %d pack(s) from Argus", len(loaded))
        return loaded

    def load_from_path(self, path: Path) -> RulePack:
        """Load a rule pack from a Python module on disk.

        The module must expose a top-level ``RULE_PACK`` attribute of type
        ``RulePack``. This is intended for local development and operator
        customisation.
        """
        if not path.exists():
            raise FileNotFoundError(f"rule pack path not found: {path}")

        spec = importlib.util.spec_from_file_location(f"_rule_pack_{path.stem}", path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load rule pack from {path}")

        mod = types.ModuleType(spec.name)
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]

        pack: RulePack | None = getattr(mod, "RULE_PACK", None)
        if pack is None or not isinstance(pack, RulePack):
            raise AttributeError(
                f"module {path} must expose a top-level RULE_PACK: RulePack attribute"
            )

        pack = RulePack(
            pack_id=pack.pack_id,
            version=pack.version,
            rules=pack.rules,
            source="local-file",
        )
        self._packs[pack.pack_id] = pack
        logger.info(
            "rule_pack_loader: loaded local-file pack %s v%s (%d rules) from %s",
            pack.pack_id, pack.version, len(pack.rules), path,
        )
        return pack

    # ── aggregate view ────────────────────────────────────────────────────────

    def get_all_rules(self) -> list["Rule"]:
        """Return a flat list of all rules across all loaded packs, deduped by name."""
        seen: set[str] = set()
        rules: list["Rule"] = []
        for pack in self._packs.values():
            for rule in pack.rules:
                if rule.name not in seen:
                    seen.add(rule.name)
                    rules.append(rule)
        return rules

    @property
    def pack_count(self) -> int:
        return len(self._packs)

    # ── internal ──────────────────────────────────────────────────────────────

    def _load_argus_pack(self, raw: dict) -> RulePack | None:
        pack_id = raw.get("pack_id")
        version = raw.get("version", "unknown")
        rule_refs: list[str] = raw.get("rule_classes", [])

        if not pack_id:
            logger.warning("rule_pack_loader: skipping Argus pack with no pack_id")
            return None

        rules: list["Rule"] = []
        for ref in rule_refs:
            try:
                module_path, class_name = ref.rsplit(".", 1)
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name)
                rules.append(cls())
            except Exception:
                logger.exception(
                    "rule_pack_loader: could not load rule class %s from Argus pack %s",
                    ref, pack_id,
                )

        return RulePack(pack_id=pack_id, version=version, rules=rules, source="argus")
