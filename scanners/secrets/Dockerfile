# ── Stage 1: Export + quantize secrets-sentinel to ONNX INT8 ───────────
FROM debian:bookworm-slim AS model-exporter
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --break-system-packages --no-cache-dir \
    "optimum[onnxruntime,exporters]" transformers && \
    pip3 install --break-system-packages --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu
COPY secrets/export_model.py /tmp/export_model.py
RUN python3 /tmp/export_model.py && rm -rf /root/.cache /tmp/export_model.py

# ── Stage 2: Runtime (onnxruntime only, no PyTorch) ────────────────────
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
LABEL "io.aegis.security.secret-scanner.signature"="aegis-secret-scanner"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq \
    python3 python3-pip parallel \
    && rm -rf /var/lib/apt/lists/*

# ML deps: onnxruntime + transformers tokenizer (no PyTorch)
RUN pip3 install --break-system-packages --no-cache-dir \
    onnxruntime transformers numpy

# Copy exported ONNX model from model-exporter stage
COPY --from=model-exporter /scanner/model /scanner/model

# Install TruffleHog
ARG TRUFFLEHOG_VERSION=3.95.2
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then TH_ARCH="arm64"; else TH_ARCH="amd64"; fi && \
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TH_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog

# Install BetterLeaks
ARG BETTERLEAKS_VERSION=1.2.0
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then BL_ARCH="arm64"; else BL_ARCH="x64"; fi && \
    curl -fsSL "https://github.com/betterleaks/betterleaks/releases/download/v${BETTERLEAKS_VERSION}/betterleaks_${BETTERLEAKS_VERSION}_linux_${BL_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin betterleaks && \
    chmod +x /usr/local/bin/betterleaks

# Create scanner user (UID 1000) for shared volume security
RUN groupadd -g 1000 scanner && useradd -u 1000 -g 1000 -m scanner

WORKDIR /scanner
RUN mkdir -p /scanner/output

COPY secrets/run.sh /scanner/run.sh
COPY secrets/scripts /scanner/scripts
COPY secrets/classify.py /scanner/classify.py
COPY secrets/enrich_context.py /scanner/enrich_context.py
COPY shared/manifest.py /scanner/manifest.py
COPY shared/lib.sh /scanner/shared/lib.sh
RUN chmod +x /scanner/run.sh /scanner/scripts/*.sh
RUN chown -R 1000:1000 /scanner

USER 1000

ENTRYPOINT ["/scanner/run.sh"]
