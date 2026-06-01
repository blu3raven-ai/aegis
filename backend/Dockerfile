# ── Stage 1: dependency builder ──────────────────────────────────────────────
# Installs Python packages with pip. Using pip --prefix produces a self-contained
# install tree that can be COPY'd into the runtime stage without bringing along gcc.
FROM python:3.13-slim AS build
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir --prefix=/install .


# ── Stage 2: mc binary ───────────────────────────────────────────────────────
# Grab the MinIO client binary for bucket/user initialisation at startup.
# Pinned to a specific tag; update via ARG override in CI.
FROM minio/mc:RELEASE.2025-04-03T17-07-06Z AS mc


# ── Stage 3: scanner-tool builder ────────────────────────────────────────────
# Downloads Syft, Grype, TruffleHog, and Opengrep static binaries.
# Kept as a separate stage so tool version bumps don't invalidate the Python
# package cache and vice versa.
FROM python:3.13-slim AS tool-builder

ARG SYFT_VERSION=1.24.0
ARG GRYPE_VERSION=0.92.0
ARG TRUFFLEHOG_VERSION=3.95.2
ARG OPENGREP_VERSION=1.20.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Syft: static Go binary
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
    sh -s -- -b /usr/local/bin v${SYFT_VERSION}

# Grype: static Go binary
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
    sh -s -- -b /usr/local/bin v${GRYPE_VERSION}

# TruffleHog: static Go binary (arch-aware)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then TH_ARCH="arm64"; else TH_ARCH="amd64"; fi && \
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TH_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog

# Opengrep: self-contained binary (arch-aware)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then OG_BIN="opengrep_manylinux_aarch64"; \
    else OG_BIN="opengrep_manylinux_x86"; fi && \
    curl -fsSL "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${OG_BIN}" \
    -o /usr/local/bin/opengrep && chmod +x /usr/local/bin/opengrep


# ── Stage 4: production runtime ──────────────────────────────────────────────
# Lean image: Python runtime + pre-built packages + scanner binaries.
# No compilers, no build scaffolding, no package manager caches.
FROM python:3.13-slim AS runtime

ARG SYFT_VERSION=1.24.0
ARG GRYPE_VERSION=0.92.0
ARG TRUFFLEHOG_VERSION=3.95.2
ARG OPENGREP_VERSION=1.20.0

LABEL org.opencontainers.image.title="aegis-backend" \
      org.opencontainers.image.source="https://github.com/blu3raven-ai/aegis" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Aegis"

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUTF8=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# gosu for privilege drop in entrypoint; libpq5 for psycopg2 at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git gosu libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Scanner binaries for incremental-scan adapters (Phase 7+)
# Pinned versions for reproducible builds; bump via ARG overrides in CI
COPY --from=tool-builder /usr/local/bin/syft        /usr/local/bin/syft
COPY --from=tool-builder /usr/local/bin/grype       /usr/local/bin/grype
COPY --from=tool-builder /usr/local/bin/trufflehog  /usr/local/bin/trufflehog
COPY --from=tool-builder /usr/local/bin/opengrep    /usr/local/bin/opengrep

# Python packages from build stage
COPY --from=build /install /usr/local

# mc binary for MinIO bucket/user init on startup
COPY --from=mc /usr/bin/mc /usr/local/bin/mc

# Application source
COPY . .

# Non-root user with home dir (mc stores config under ~/.mc)
RUN groupadd -r app && useradd -r -g app -m app && \
    mkdir -p /app/data && chown -R app:app /app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:8000/health/live || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
