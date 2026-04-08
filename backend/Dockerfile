# ── Stage 1: Build dependencies ───────────────────────────────────────────────
FROM python:3.13-slim AS build
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --no-cache-dir --prefix=/install .

# ── Stage 1b: Grab mc binary for MinIO admin init ────────────────────────────
FROM minio/mc:latest AS mc

# ── Stage 2: Production runtime ──────────────────────────────────────────────
FROM python:3.13-slim AS runtime
WORKDIR /app

# Install only runtime dependencies (no Docker — runner handles containers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git gosu libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from build stage
COPY --from=build /install /usr/local

# Copy mc binary for MinIO bucket/user init on startup
COPY --from=mc /usr/bin/mc /usr/local/bin/mc

# Copy application code
COPY . .

# Non-root user (with home dir for mc config)
RUN groupadd -r app && useradd -r -g app -m app && \
    mkdir -p /app/data && chown -R app:app /app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
