# Combined Aegis image: Next.js static export served by FastAPI.
# Single process (uvicorn), single user (app), single port (3000).

# ── Stage 1: frontend build (Next.js static export) ──────────────────────────
FROM node:20.18.1-slim AS frontend-build
WORKDIR /app
COPY --link frontend/package.json frontend/package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --ignore-scripts --no-audit --fund=false
COPY --link frontend/ ./
RUN npm run build && test -d out || (echo "static export failed — out/ not produced" && exit 1)


# ── Stage 2: backend Python dependencies ─────────────────────────────────────
FROM python:3.13-slim AS backend-build
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv==0.9.21
COPY backend/pyproject.toml backend/uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv export --frozen --no-dev --no-emit-project \
        --output-file=/tmp/requirements.txt && \
    uv pip install --system --prefix=/install -r /tmp/requirements.txt


# ── Stage 3: mc binary ───────────────────────────────────────────────────────
FROM minio/mc:RELEASE.2024-10-08T09-37-26Z AS mc


# ── Stage 4: runtime ─────────────────────────────────────────────────────────
FROM python:3.13-slim AS runtime

LABEL org.opencontainers.image.title="aegis" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/blu3raven-ai/aegis-dev"

ENV PYTHONUTF8=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    LANG=C.UTF-8 \
    STATIC_ROOT=/app/static

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl libpq5 libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi8 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Non-root user with nologin shell — defense against post-exploit lateral movement
RUN groupadd -r app --gid 10001 && \
    useradd -r -g app --uid 10001 --create-home --home-dir /home/app \
            --shell /usr/sbin/nologin app

COPY --from=mc /usr/bin/mc /usr/local/bin/mc
COPY --from=backend-build /install /usr/local

# Static UI files (read-only, served by FastAPI)
COPY --chown=app:app --from=frontend-build /app/out /app/static

# Backend source
COPY --chown=app:app backend/ /app/backend/

WORKDIR /app/backend
USER app

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://localhost:3000/healthz || exit 1

CMD ["uvicorn", "src.main:app", \
     "--host", "0.0.0.0", "--port", "3000", \
     "--workers", "2", \
     "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
