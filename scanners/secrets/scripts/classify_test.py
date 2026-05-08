#!/usr/bin/env python3
"""Basic tests for classify.py — run with: python3 classify_test.py"""
import json
import sys
import tempfile
from pathlib import Path

# Bootstrap: import classify without running main
sys.path.insert(0, str(Path(__file__).parent.parent))
import classify

def test_map_label_real():
    assert classify._map_label("real") == "likely_real"
    assert classify._map_label("true_positive") == "likely_real"

def test_map_label_fp():
    assert classify._map_label("false_positive") == "likely_false_positive", classify._map_label("false_positive")
    assert classify._map_label("fp") == "likely_false_positive", classify._map_label("fp")

def test_map_label_unknown():
    assert classify._map_label("unknown_label") == "uncertain"

def test_classify_findings_empty_list():
    with tempfile.TemporaryDirectory() as tmp:
        inp = Path(tmp) / "input.json"
        out = Path(tmp) / "output.json"
        inp.write_text("[]")
        classify.classify_findings(str(inp), str(out), model=None)
        assert json.loads(out.read_text()) == []

def test_classify_findings_adds_field():
    finding = {"RuleID": "aws-access-key", "Secret": "AKIAIOSFODNN7EXAMPLE", "File": "config.py"}
    with tempfile.TemporaryDirectory() as tmp:
        inp = Path(tmp) / "input.json"
        out = Path(tmp) / "output.json"
        inp.write_text(json.dumps([finding]))
        class MockModel:
            def __call__(self, findings, **kwargs):
                return [{"label": "real", "reasoning": ""}] * len(findings)
        classify.classify_findings(str(inp), str(out), model=MockModel())
        results = json.loads(out.read_text())
        assert len(results) == 1
        assert results[0]["ai_classification"] == "likely_real"
        assert results[0]["Secret"] == "AKIAIOSFODNN7EXAMPLE"

def _make_onnx_classifier(session_run_fn):
    """Build an OnnxClassifier with mocked internals for testing."""
    import numpy as np
    import unittest.mock as mock

    classifier = classify.OnnxClassifier.__new__(classify.OnnxClassifier)
    classifier._id2label = {0: "label_0", 1: "label_1"}
    classifier._ort_input_names = {"input_ids", "attention_mask"}

    batches_seen = []

    def fake_tokenizer(texts, **kwargs):
        batches_seen.append(list(texts))
        n = len(texts)
        return {"input_ids": np.zeros((n, 10), dtype=np.int64),
                "attention_mask": np.ones((n, 10), dtype=np.int64)}

    classifier._tokenizer = fake_tokenizer
    classifier._session = mock.MagicMock()
    classifier._session.run = session_run_fn
    classifier._batches_seen = batches_seen
    return classifier


def test_dedup_calls_batch_once_for_duplicate_secrets():
    """Two findings with same Secret+RuleID must appear as one text in the batch."""
    import numpy as np

    findings = [
        {"Secret": "AKIAIOSFODNN7EXAMPLE", "RuleID": "aws-access-key", "File": "a.py"},
        {"Secret": "AKIAIOSFODNN7EXAMPLE", "RuleID": "aws-access-key", "File": "b.py"},
    ]

    def session_run(output_names, inputs):
        n = inputs["input_ids"].shape[0]
        return [np.array([[0.1, 0.9]] * n)]

    classifier = _make_onnx_classifier(session_run)
    results = classifier(findings)

    total_texts = sum(len(b) for b in classifier._batches_seen)
    assert total_texts == 1, f"Expected 1 unique text in batch, got {total_texts}"
    assert len(results) == 2
    assert results[0]["label"] == results[1]["label"], "Duplicate findings must share identical result"


def test_dedup_missing_secret_falls_back_to_text_key():
    """Findings with no Secret/RuleID are keyed by text — both texts must appear in batch."""
    import numpy as np

    findings = [
        {"File": "a.py", "Match": "something-unique"},
        {"File": "b.py", "Match": "something-else"},
    ]

    def session_run(output_names, inputs):
        n = inputs["input_ids"].shape[0]
        return [np.array([[0.8, 0.2]] * n)]

    classifier = _make_onnx_classifier(session_run)
    results = classifier(findings)

    total_texts = sum(len(b) for b in classifier._batches_seen)
    assert total_texts == 2, f"Expected 2 unique texts in batch, got {total_texts}"
    assert len(results) == 2


if __name__ == "__main__":
    tests = [test_map_label_real, test_map_label_fp, test_map_label_unknown,
             test_classify_findings_empty_list, test_classify_findings_adds_field,
             test_dedup_calls_batch_once_for_duplicate_secrets,
             test_dedup_missing_secret_falls_back_to_text_key]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
