#!/usr/bin/env python3
"""Annotate BetterLeaks findings with secrets-sentinel (ONNX) classification.

Usage:
  python3 classify.py <input.json> <output.json>       # single file
  python3 classify.py --batch <dir>                    # all repos under dir

Model is loaded from MODEL_PATH (bundled in Docker image at build time).
Output adds 'ai_classification', 'ai_confidence', and 'ai_reasoning' to each finding.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
logger = logging.getLogger(__name__)
from typing import Any


MODEL_PATH = "/scanner/model"

_REAL_LABELS = {"real", "true_positive", "label_1"}   # label_1 = secrets-sentinel "secret detected"
_FP_LABELS = {"false_positive", "fp", "label_0"}      # label_0 = secrets-sentinel "normal/safe"
_FALLBACK_RESULT: dict[str, Any] = {"label": "uncertain", "reasoning": ""}


class OnnxClassifier:
    """Thin wrapper around onnxruntime + AutoTokenizer — no PyTorch at runtime."""

    def __init__(self, model_path: str) -> None:
        import onnxruntime as ort
        from transformers import AutoTokenizer
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
        import numpy as np
        texts = [_finding_text(f) for f in findings]

        # Dedup by (secret, rule_id) to avoid redundant inference
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
            total_unique, total,
        )

        # Batch inference in chunks of 64
        unique_results: list[dict[str, Any]] = []
        for batch_start in range(0, len(unique_texts), 64):
            batch = unique_texts[batch_start : batch_start + 64]
            inputs = self._tokenizer(batch, padding=True, truncation=True,
                                     max_length=512, return_tensors="np")
            filtered = {k: v for k, v in dict(inputs).items() if k in self._ort_input_names}
            logits = self._session.run(["logits"], filtered)[0]
            exp = np.exp(logits - logits.max(axis=-1, keepdims=True))
            probs = exp / exp.sum(axis=-1, keepdims=True)
            for prob_row in probs:
                idx = int(np.argmax(prob_row))
                unique_results.append({"label": self._id2label.get(idx, str(idx)),
                                       "score": float(prob_row[idx]),
                                       "reasoning": ""})
            done = min(batch_start + 64, total_unique)
            logger.info("[classify] %d/%d", done, total_unique)

        # Map unique results back to all findings via key lookup
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


def _load_model(model_path: str = MODEL_PATH) -> OnnxClassifier:
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
    context (ContextBefore / ContextAfter) when available, so the model can
    use neighbouring lines (e.g. test files, placeholder comments, env blocks)
    in its reasoning.
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
    except Exception as exc:
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
    input_path: str,
    output_path: str,
    model: Any = None,
) -> None:
    """Classify a single findings file. Pass a mock model for testing."""
    with open(input_path, encoding="utf-8") as f:
        findings: list[dict[str, Any]] = json.load(f)

    if not findings:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump([], f)
        return

    if model is None:
        model = _load_model()

    annotated = _annotate(findings, _run_inference(model, findings))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(annotated, f, ensure_ascii=False)


if __name__ == "__main__":
    import argparse
    import glob
    import os

    parser = argparse.ArgumentParser(description="Classify BetterLeaks findings with AI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--batch", metavar="DIR", help="Classify all betterleaks_raw.json files under DIR (single model load)")
    group.add_argument("input", nargs="?", help="Input JSON file (single-file mode)")
    parser.add_argument("output", nargs="?", help="Output JSON file (single-file mode)")
    args = parser.parse_args()

    if args.batch:
        raw_files = sorted(glob.glob(f"{args.batch}/**/betterleaks_raw.json", recursive=True))
        if not raw_files:
            logger.info("[+] No betterleaks_raw.json files found — skipping classification")
            sys.exit(0)

        # Load all findings upfront, tracking which file each belongs to
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
            sys.exit(0)

        total = sum(len(findings) for _, _, findings in file_findings)
        logger.info("[+] Loading model (%d findings across %d repo(s))...", total, len(file_findings))
        model = _load_model()
        logger.info("[+] Model loaded, running inference on %d findings...", total)

        # Single inference pass — avoids per-repo model reload overhead
        all_findings = [f for _, _, findings in file_findings for f in findings]
        all_results = _run_inference(model, all_findings)
        logger.info("[✓] Inference complete")

        # Split results back per file and write outputs
        offset = 0
        for raw, out, findings in file_findings:
            n = len(findings)
            annotated = _annotate(findings, all_results[offset : offset + n])
            offset += n
            with open(out, "w", encoding="utf-8") as f:
                json.dump(annotated, f, ensure_ascii=False)
            os.remove(raw)
            logger.info("[✓] Classified %s", os.path.relpath(raw, args.batch))
    else:
        if not args.input or not args.output:
            parser.print_usage(sys.stderr)
            sys.exit(1)
        classify_findings(args.input, args.output)
