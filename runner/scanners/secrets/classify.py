"""Lazy-loaded ML classifier for BetterLeaks findings.

Heavy dependencies (``onnxruntime``, ``transformers``, ``numpy``) are imported
only inside :class:`OnnxClassifier` so module import stays cheap. The runner
agent imports this module to dispatch scans, and we don't want a multi-hundred
megabyte tensor lib load on cold start when the job in flight is not an
``ai_enhanced`` secrets scan.

The ONNX model bundle (``model.onnx`` + tokenizer + ``config.json``) is baked
into the runner image at ``/opt/aegis/secrets-model`` by a dedicated build
stage. The path can be overridden at runtime via the ``SECRETS_MODEL_PATH``
environment variable (useful for tests and local development).

Output adds ``ai_classification``, ``ai_confidence``, and ``ai_reasoning`` to
each finding. When the model is unavailable, callers receive the original
findings untouched.
"""
from __future__ import annotations

import glob
import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


DEFAULT_MODEL_PATH = os.environ.get(
    "SECRETS_MODEL_PATH", "/opt/aegis/secrets-model"
)

_REAL_LABELS = {"real", "true_positive", "label_1"}
_FP_LABELS = {"false_positive", "fp", "label_0"}
_FALLBACK_RESULT: dict[str, Any] = {"label": "uncertain", "reasoning": ""}


class OnnxClassifier:
    """Thin wrapper around ``onnxruntime`` + ``AutoTokenizer``.

    Imports of the ML runtime live inside ``__init__`` so simply referencing
    this class does not pull in ~hundreds of MB of tensor libraries.
    """

    def __init__(self, model_path: str) -> None:
        import onnxruntime as ort  # noqa: PLC0415
        from transformers import AutoTokenizer  # noqa: PLC0415

        self._tokenizer = AutoTokenizer.from_pretrained(model_path)
        self._session = ort.InferenceSession(
            f"{model_path}/model.onnx",
            providers=["CPUExecutionProvider"],
        )
        self._ort_input_names = {inp.name for inp in self._session.get_inputs()}
        config_path = Path(model_path) / "config.json"
        with open(config_path) as f:
            config = json.load(f)
        raw = config.get("id2label", {"0": "label_0", "1": "label_1"})
        self._id2label: dict[int, str] = {int(k): v for k, v in raw.items()}

    def __call__(self, findings: list[dict]) -> list[dict[str, Any]]:
        import numpy as np  # noqa: PLC0415

        texts = [_finding_text(f) for f in findings]

        # Dedup by (secret, rule_id) to avoid redundant inference passes.
        key_to_idx: dict[tuple[str, str], int] = {}
        unique_indices: list[int] = []
        for i, finding in enumerate(findings):
            secret = str(finding.get("Secret") or finding.get("secret") or "")
            rule = str(finding.get("RuleID") or finding.get("rule_id") or "")
            key = (secret, rule) if (secret or rule) else (texts[i], "")
            if key not in key_to_idx:
                key_to_idx[key] = i
                unique_indices.append(i)

        unique_texts = [texts[i] for i in unique_indices]
        total_unique = len(unique_texts)
        total = len(findings)
        logger.info(
            "Classifying %d unique finding(s) (%d total) with secrets-sentinel (ONNX)...",
            total_unique,
            total,
        )

        unique_results: list[dict[str, Any]] = []
        for batch_start in range(0, len(unique_texts), 64):
            batch = unique_texts[batch_start : batch_start + 64]
            inputs = self._tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=512,
                return_tensors="np",
            )
            filtered = {
                k: v for k, v in dict(inputs).items() if k in self._ort_input_names
            }
            logits = self._session.run(["logits"], filtered)[0]
            exp = np.exp(logits - logits.max(axis=-1, keepdims=True))
            probs = exp / exp.sum(axis=-1, keepdims=True)
            for prob_row in probs:
                idx = int(np.argmax(prob_row))
                unique_results.append(
                    {
                        "label": self._id2label.get(idx, str(idx)),
                        "score": float(prob_row[idx]),
                        "reasoning": "",
                    }
                )
            done = min(batch_start + 64, total_unique)
            logger.info("[classify] %d/%d", done, total_unique)

        result_by_key: dict[tuple[str, str], dict] = {}
        for rank, idx in enumerate(unique_indices):
            finding = findings[idx]
            secret = str(finding.get("Secret") or finding.get("secret") or "")
            rule = str(finding.get("RuleID") or finding.get("rule_id") or "")
            key = (secret, rule) if (secret or rule) else (texts[idx], "")
            result_by_key[key] = unique_results[rank]

        results: list[dict] = []
        for i, finding in enumerate(findings):
            secret = str(finding.get("Secret") or finding.get("secret") or "")
            rule = str(finding.get("RuleID") or finding.get("rule_id") or "")
            key = (secret, rule) if (secret or rule) else (texts[i], "")
            results.append(result_by_key[key])

        return results


def _load_model(model_path: str = DEFAULT_MODEL_PATH) -> OnnxClassifier:
    return OnnxClassifier(model_path)


def _map_label(label: str) -> str:
    normalized = label.strip().lower()
    if normalized in _REAL_LABELS:
        return "likely_real"
    if normalized in _FP_LABELS:
        return "likely_false_positive"
    return "uncertain"


def _finding_text(finding: dict[str, Any]) -> str:
    """Build a rich context snippet for the classifier.

    Includes file path, rule ID, and the matched line with surrounding source
    context (``ContextBefore`` / ``ContextAfter``) when available so the model
    can use neighbouring lines (e.g. test files, placeholder comments, env
    blocks) in its reasoning.
    """
    parts: list[str] = []

    file_path = finding.get("File") or finding.get("file") or ""
    if file_path:
        parts.append(f"File: {file_path}")

    rule = finding.get("RuleID") or finding.get("rule_id") or ""
    if rule:
        parts.append(f"Rule: {rule}")

    match = finding.get("Match") or finding.get("match") or ""
    secret_val = finding.get("Secret") or finding.get("secret") or ""
    matched_line = match or (f"{rule} = '{secret_val}'" if (rule or secret_val) else "")

    context_before: list[str] = finding.get("ContextBefore") or []
    context_after: list[str] = finding.get("ContextAfter") or []

    if context_before or context_after:
        parts.append("Context:")
        for line in context_before:
            parts.append(f"  {line}")
        if matched_line:
            parts.append(f"> {matched_line}")
        for line in context_after:
            parts.append(f"  {line}")
    elif matched_line:
        parts.append(f"Match: {matched_line}")

    return "\n".join(parts)[:1024]


def _run_inference(model: Any, findings: list[dict]) -> list[dict[str, Any]]:
    """Run inference, returning a fallback list on failure."""
    try:
        return model(findings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[!] SLM inference failed: %s", exc)
        return [dict(_FALLBACK_RESULT) for _ in findings]


def _annotate(
    findings: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge classifier results into findings."""
    annotated = []
    for finding, result in zip(findings, results):
        entry: dict[str, Any] = {
            **finding,
            "ai_classification": _map_label(str(result.get("label") or "uncertain")),
            "ai_reasoning": str(result.get("reasoning") or ""),
        }
        score = result.get("score")
        if score is not None:
            entry["ai_confidence"] = round(float(score), 4)
        annotated.append(entry)
    return annotated


def classify_findings(
    input_path: str | Path,
    output_path: str | Path,
    model: Any = None,
    model_path: str = DEFAULT_MODEL_PATH,
) -> int:
    """Classify a single findings file.

    Returns the number of findings classified. When the input is empty or the
    ML runtime is unavailable, writes an unmodified copy of the input (or an
    empty list) and returns ``0``.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    with open(input_path, encoding="utf-8") as f:
        findings: list[dict[str, Any]] = json.load(f)

    if not findings:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump([], f)
        return 0

    if model is None:
        try:
            model = _load_model(model_path)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[!] ML model unavailable at %s (%s); pass-through copy.",
                model_path,
                exc,
            )
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(findings, f, ensure_ascii=False)
            return 0

    annotated = _annotate(findings, _run_inference(model, findings))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(annotated, f, ensure_ascii=False)
    return len(annotated)


def classify_batch(
    target_dir: str | Path,
    model: Any = None,
    model_path: str = DEFAULT_MODEL_PATH,
) -> int:
    """Classify every ``betterleaks_raw.json`` under ``target_dir`` in a single
    inference pass.

    Mirrors the ``--batch`` mode of the bash-era ``classify.py``: each raw
    file's findings are replaced by ``betterleaks.json`` with classifier
    annotations; the raw file is removed on success. Empty inputs are written
    as ``[]`` and the raw file is removed. Returns total findings classified.
    """
    target_dir = Path(target_dir)
    raw_files = sorted(
        glob.glob(f"{target_dir}/**/betterleaks_raw.json", recursive=True)
    )
    if not raw_files:
        logger.info("[+] No betterleaks_raw.json files found - skipping classification")
        return 0

    file_findings: list[tuple[str, str, list[dict[str, Any]]]] = []
    for raw in raw_files:
        out = os.path.join(os.path.dirname(raw), "betterleaks.json")
        with open(raw, encoding="utf-8") as f:
            findings = json.load(f)
        if findings:
            file_findings.append((raw, out, findings))
        else:
            with open(out, "w", encoding="utf-8") as f:
                json.dump([], f)
            os.remove(raw)

    if not file_findings:
        logger.info("[+] No findings to classify")
        return 0

    total = sum(len(findings) for _, _, findings in file_findings)
    logger.info(
        "[+] Loading model (%d findings across %d repo(s))...",
        total,
        len(file_findings),
    )
    if model is None:
        try:
            model = _load_model(model_path)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[!] ML model unavailable at %s (%s); pass-through.",
                model_path,
                exc,
            )
            for raw, out, findings in file_findings:
                with open(out, "w", encoding="utf-8") as f:
                    json.dump(findings, f, ensure_ascii=False)
                os.remove(raw)
            return 0

    all_findings = [f for _, _, findings in file_findings for f in findings]
    all_results = _run_inference(model, all_findings)
    logger.info("[OK] Inference complete")

    offset = 0
    for raw, out, findings in file_findings:
        n = len(findings)
        annotated = _annotate(findings, all_results[offset : offset + n])
        offset += n
        with open(out, "w", encoding="utf-8") as f:
            json.dump(annotated, f, ensure_ascii=False)
        os.remove(raw)
        logger.info("[OK] Classified %s", os.path.relpath(raw, target_dir))

    return total
