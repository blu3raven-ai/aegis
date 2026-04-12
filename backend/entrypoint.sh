#!/bin/sh
# Run database migrations before starting the app
echo "[entrypoint] Running database migrations..."
gosu app alembic upgrade head 2>&1 || echo "[entrypoint] WARNING: migrations failed (may already be up to date)"

exec gosu app "$@"
