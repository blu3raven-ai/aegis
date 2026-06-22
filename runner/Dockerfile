# syntax=docker/dockerfile:1.7

# ─── Builder stage ────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

ARG SYFT_VERSION=1.24.0
ARG GRYPE_VERSION=0.92.0
ARG GRYPE_DB_VERSION=0.53.3
ARG CDXGEN_VERSION=12.3.0
ARG CDXCLI_VERSION=0.27.1
ARG TRUFFLEHOG_VERSION=3.95.2
ARG SEMGREP_RULES_SHA=311ca4e9ba59d700624539bf658e3d29b134ee77
ARG NODE_MAJOR=22

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg git \
    && rm -rf /var/lib/apt/lists/*

# Node.js 22 for cdxgen (requires >=20)
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Syft + Grype + grype-db (Anchore install scripts)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
        sh -s -- -b /usr/local/bin v${SYFT_VERSION} && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
        sh -s -- -b /usr/local/bin v${GRYPE_VERSION} && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype-db/main/install.sh | \
        sh -s -- -b /usr/local/bin v${GRYPE_DB_VERSION}

# cdxgen — CycloneDX SBOM generator (arch-aware plugin binaries installed by npm)
RUN npm install -g @cyclonedx/cdxgen@${CDXGEN_VERSION} && \
    npm cache clean --force && \
    rm -rf /tmp/* /root/.npm

# CycloneDX CLI — arch-aware single binary
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then CDX_ARCH="linux-arm64"; else CDX_ARCH="linux-x64"; fi && \
    curl -fsSL "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v${CDXCLI_VERSION}/cyclonedx-${CDX_ARCH}" \
        -o /usr/local/bin/cyclonedx && chmod +x /usr/local/bin/cyclonedx

# TruffleHog — arch-aware tarball
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then TH_ARCH="arm64"; else TH_ARCH="amd64"; fi && \
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TH_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog

# semgrep-rules — pinned SHA, security subset only, .git stripped
RUN git clone --no-checkout --filter=blob:none \
        https://github.com/semgrep/semgrep-rules.git /opt/semgrep-rules && \
    cd /opt/semgrep-rules && \
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
    git checkout "${SEMGREP_RULES_SHA}" && \
    rm -rf /opt/semgrep-rules/.git && \
    rm -f /opt/semgrep-rules/.pre-commit-config.yaml \
          /opt/semgrep-rules/metadata-schema.yaml.schm \
          /opt/semgrep-rules/template.yaml \
          /opt/semgrep-rules/Makefile \
          /opt/semgrep-rules/Pipfile \
          /opt/semgrep-rules/Pipfile.lock

# Python deps installed from the lockfile so the runtime image pins the same
# transitive graph that local `uv sync` resolves to.
RUN pip install --no-cache-dir uv==0.9.21

WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv export --frozen --no-dev --no-emit-project --output-file=/tmp/requirements.txt && \
    uv pip install --system --prefix=/install -r /tmp/requirements.txt

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SEMGREP_RULES_PATH=/opt/semgrep-rules \
    RUNNER_WORKSPACE=/workspace

# Minimal runtime deps:
#   git        — repository clone
#   libstdc++6 — cdxgen native bits
#   libicu76   — cyclonedx-cli (.NET) globalization
#   procps     — pgrep, used by the HEALTHCHECK below
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git libstdc++6 libicu76 procps \
    && rm -rf /var/lib/apt/lists/*

# Scanner CLIs
COPY --from=builder \
    /usr/local/bin/syft \
    /usr/local/bin/grype \
    /usr/local/bin/grype-db \
    /usr/local/bin/cyclonedx \
    /usr/local/bin/trufflehog \
    /usr/local/bin/

# Semgrep rules bundle
COPY --from=builder /opt/semgrep-rules /opt/semgrep-rules

# Node.js runtime for cdxgen
COPY --from=builder /usr/bin/node /usr/bin/node
COPY --from=builder /usr/lib/node_modules /usr/lib/node_modules
RUN ln -s /usr/lib/node_modules/@cyclonedx/cdxgen/bin/cdxgen.js /usr/local/bin/cdxgen

# Python deps from builder prefix
COPY --from=builder /install /usr/local


# Application code (build context is the runner/ directory; mounted as /app/runner)
WORKDIR /app
COPY . /app/runner/

# Non-root user
RUN useradd --create-home --shell /bin/bash --uid 10001 aegis && \
    mkdir -p /workspace /home/aegis/.cache/grype && \
    chown -R aegis:aegis /app /workspace /home/aegis
USER aegis

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD pgrep -f "runner.agent" > /dev/null || exit 1

CMD ["python", "-c", "import logging, warnings; logging.basicConfig(level=logging.INFO, format='%(message)s'); logging.getLogger('httpx').setLevel(logging.WARNING); logging.getLogger('httpcore').setLevel(logging.WARNING); logging.getLogger('urllib3.connection').setLevel(logging.ERROR); warnings.filterwarnings('ignore', message='Failed to parse headers'); from runner.agent import RunnerAgent, load_config; a = RunnerAgent(load_config()); a.start()"]
