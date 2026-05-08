FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUTF8=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8
LABEL "io.aegis.security.code-scanning-scanner.signature"="aegis-code-scanning-scanner"

RUN apt-get update && apt-get install -y \
    ca-certificates curl wget git unzip jq gnupg parallel \
    && rm -rf /var/lib/apt/lists/*

# Install Opengrep (self-contained binary, arch-aware)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then \
      OPENGREP_BIN="opengrep_manylinux_aarch64"; \
    else \
      OPENGREP_BIN="opengrep_manylinux_x86"; \
    fi && \
    curl -L "https://github.com/opengrep/opengrep/releases/download/v1.20.0/${OPENGREP_BIN}" \
      -o /usr/local/bin/opengrep && \
    chmod +x /usr/local/bin/opengrep

# Bundle semgrep-rules security subset (pinned SHA) for offline scanning.
# Strip .git after checkout — the object store is not needed at runtime.
ARG SEMGREP_RULES_SHA=311ca4e9ba59d700624539bf658e3d29b134ee77
RUN git clone --no-checkout --filter=blob:none \
    https://github.com/semgrep/semgrep-rules.git /scanner/rules && \
    cd /scanner/rules && \
    git sparse-checkout init --cone && \
    git sparse-checkout set \
        python/lang/security \
        javascript/lang/security \
        typescript/lang/security \
        java/lang/security \
        go/lang/security \
        ruby/lang/security \
        php/lang/security \
        generic && \
    git checkout "$SEMGREP_RULES_SHA" && \
    rm -rf /scanner/rules/.git && \
    rm -f /scanner/rules/.pre-commit-config.yaml \
          /scanner/rules/metadata-schema.yaml.schm \
          /scanner/rules/template.yaml \
          /scanner/rules/Makefile \
          /scanner/rules/Pipfile \
          /scanner/rules/Pipfile.lock

# Python + tree-sitter-languages for reachability call graph analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --break-system-packages --no-cache-dir "tree-sitter==0.21.3" tree-sitter-languages

# Create scanner user (UID 1000) for shared volume security
RUN groupadd -g 1000 scanner && useradd -u 1000 -g 1000 -m scanner

# Pre-create .cache so Docker volume mounts for grype/trivy don't
# create it as root (which blocks opengrep from writing its cache)
RUN mkdir -p /home/scanner/.cache && chown 1000:1000 /home/scanner/.cache

WORKDIR /scanner
RUN mkdir -p /scanner/scripts /scanner/output

COPY code-scanning/run.sh /scanner/run.sh
COPY code-scanning/scripts /scanner/scripts
COPY shared/manifest.py /scanner/manifest.py
COPY shared/lib.sh /scanner/shared/lib.sh

RUN chmod +x /scanner/run.sh /scanner/scripts/*.sh
RUN chown -R 1000:1000 /scanner

USER 1000

ENTRYPOINT ["/scanner/run.sh"]
