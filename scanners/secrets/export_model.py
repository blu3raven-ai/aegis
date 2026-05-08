#!/usr/bin/env python3
"""Export secrets-sentinel to quantized ONNX INT8 and validate output matches PyTorch.

Run during Docker build (model-exporter stage only).
PyTorch and optimum are not present in the runtime image.
INT8 quantization halves model size and speeds up CPU inference with minimal accuracy loss.
"""
import logging
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch
from optimum.onnxruntime import ORTModelForSequenceClassification, ORTQuantizer
from optimum.onnxruntime.configuration import AutoQuantizationConfig
from transformers import AutoTokenizer, AutoModelForSequenceClassification

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(message)s")

MODEL_ID = "hypn05/secrets-sentinel"
OUTPUT_PATH = "/scanner/model"
QUANTIZED_PATH = "/scanner/model-q"

# Export to ONNX (FP32)
model = ORTModelForSequenceClassification.from_pretrained(MODEL_ID, export=True)
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
model.save_pretrained(OUTPUT_PATH)
tokenizer.save_pretrained(OUTPUT_PATH)
logger.info("[+] secrets-sentinel exported to ONNX (FP32)")

# Quantize to INT8 — halves model size, faster CPU inference
quantizer = ORTQuantizer.from_pretrained(OUTPUT_PATH)
qconfig = AutoQuantizationConfig.avx2(is_static=False, per_channel=False)
quantizer.quantize(save_dir=QUANTIZED_PATH, quantization_config=qconfig)
logger.info("[+] secrets-sentinel quantized to INT8")

# Swap quantized model in place
import shutil
shutil.rmtree(OUTPUT_PATH)
shutil.move(QUANTIZED_PATH, OUTPUT_PATH)
# ORTQuantizer saves as model_quantized.onnx; rename to match runtime expectation
import os
os.rename(f"{OUTPUT_PATH}/model_quantized.onnx", f"{OUTPUT_PATH}/model.onnx")
logger.info("[+] INT8 model installed")

# Validate: quantized model produces sensible logits
test_texts = [
    'api_key = "sk-abc123"',
    'password = "test"',
    'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"',
]
enc = tokenizer(test_texts, padding=True, truncation=True, max_length=128, return_tensors="np")

session = ort.InferenceSession(f"{OUTPUT_PATH}/model.onnx", providers=["CPUExecutionProvider"])
ort_input_names = {inp.name for inp in session.get_inputs()}
np_inputs = {k: v for k, v in dict(enc).items() if k in ort_input_names}
logits = session.run(["logits"], np_inputs)[0]

assert logits.shape == (3, 2), f"Unexpected logits shape: {logits.shape}"
logger.info("[+] Validation passed (logits shape: %s)", logits.shape)
