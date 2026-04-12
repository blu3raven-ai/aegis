from __future__ import annotations

import asyncio
import logging
import os
import subprocess
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.auth.jwt import verify_internal_jwt
from src.db.engine import engine, get_session
from src.db.seed import seed_if_empty
from src.license.keys import EMBEDDED_PUBLIC_KEY
from src.license.middleware import resolve_current_tier
from src.license.store import read_license_key
from src.license.types import Tier
from src.dependencies.router import router as dependencies_router
from src.containers.router import router as container_scanning_router
from src.code_scanning.router import router as code_scanning_router
from src.secrets.router import router as secrets_router
from src.settings.roles_router import roles_router
from src.settings.organisations_router import organisations_router
from src.settings.router import router as settings_router
from src.settings.sources_router import sources_router
from src.settings.users_router import users_router
from src.license.router import router as license_router
from src.runner.admin_router import admin_router as runner_admin_router
from src.runner.router import router as runner_router
from src.notifications.router import router as notifications_router
from src.auth.internal_router import internal_auth_router
from src.shared.events_router import events_router
from src.shared.sbom_router import router as sbom_router
from src.graphql.schema import create_graphql_router


# Load .env.local into the process environment immediately so that 
# it's available during module-level initialization (like FastAPI(docs_url=...)).
# Real environment variables (already in os.environ) take priority over the file.
from src.shared.config import read_env_file
for _key, _value in read_env_file().items():
    os.environ.setdefault(_key, _value)


async def _reconcile_stale_runs() -> None:
    """Mark any runs left in an active state from a previous server session as cancelled.
    Container cleanup is handled by the runner's stale job detector."""
    from src.shared.paths import now_iso
    from src.db.models import ScanRun
    from src.storage import update_dependencies_run, update_secret_run, update_code_scanning_run, update_container_scanning_run
    from sqlalchemy import select

    STALE_STATUSES = {"queued", "running", "ingesting"}
    update_fn = {
        "dependencies": update_dependencies_run,
        "secrets": update_secret_run,
        "code_scanning": update_code_scanning_run,
        "container_scanning": update_container_scanning_run,
    }

    try:
        async with get_session() as session:
            result = await session.execute(
                select(ScanRun).where(ScanRun.status.in_(STALE_STATUSES))
            )
            stale_runs = [(r.tool, r.org, r.id) for r in result.scalars().all()]
    except Exception:
        return

    for tool, org, run_id in stale_runs:
        fn = update_fn.get(tool)
        if fn:
            try:
                fn(org, run_id, {"status": "cancelled", "finishedAt": now_iso(), "error": "Server restarted — scan did not complete"})
            except Exception:
                pass

    # Also mark secrets runs via state machine
    from src.secrets.scanner import mark_run_cancelled
    for tool, org, run_id in stale_runs:
        if tool == "secrets":
            try:
                mark_run_cancelled(org, run_id)
            except Exception:
                pass


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    # Run Alembic migrations
    subprocess.run(["alembic", "upgrade", "head"], cwd=os.path.dirname(os.path.dirname(__file__)), check=True)
    # Seed defaults if empty
    async with get_session() as session:
        await seed_if_empty(session)

    # Ensure MinIO bucket + runner service account exist (replaces minio-init container)
    from src.storage_init import ensure_minio_ready
    ensure_minio_ready()

    await _reconcile_stale_runs()

    # Cancel orphaned runner jobs from previous session
    from src.runner.jobs import cancel_stale_jobs
    cancelled = cancel_stale_jobs()
    if cancelled:
        logging.getLogger(__name__).info("Cancelled %d stale runner jobs from previous session", cancelled)

    from src.scheduler import get_scheduler
    get_scheduler().start(asyncio.get_running_loop())

    from src.shared.event_bus import get_event_bus
    get_event_bus().set_loop(asyncio.get_running_loop())

    from src.shared.retention import start_retention_background_loop
    start_retention_background_loop()

    import threading as _threading

    _previously_online_runners: set[str] = set()

    def _stale_job_cleanup_loop():
        """Periodically check for stale runner jobs and runner offline status."""
        import time as _time
        from src.runner.jobs import requeue_stale_jobs
        while True:
            try:
                requeued = requeue_stale_jobs()
                if requeued:
                    import logging
                    logging.getLogger(__name__).info("Re-queued %d stale jobs", len(requeued))
            except Exception:
                logging.getLogger(__name__).warning("Stale job cleanup failed", exc_info=True)

            # Check for runners that went offline since last check
            try:
                from src.runner.registry import list_runners_with_status
                from src.notifications.emitter import notify_runner_offline
                runners = list_runners_with_status()
                currently_online = set()
                for r in runners:
                    rid = r.get("id", "")
                    status = r.get("computedStatus", "offline")
                    if status == "online":
                        currently_online.add(rid)
                    elif rid in _previously_online_runners and status == "offline":
                        # Was online, now offline — notify
                        notify_runner_offline(rid, r.get("name", rid))
                _previously_online_runners.clear()
                _previously_online_runners.update(currently_online)
            except Exception:
                logging.getLogger(__name__).warning("Runner offline check failed", exc_info=True)

            _time.sleep(60)

    _stale_cleanup_thread = _threading.Thread(target=_stale_job_cleanup_loop, daemon=True, name="stale-job-cleanup")
    _stale_cleanup_thread.start()

    yield

    get_scheduler().stop()
    await engine.dispose()


def _is_docs_enabled() -> bool:
    return os.getenv("ENABLE_BACKEND_DOCS", "").lower() == "true"


logger = logging.getLogger(__name__)
logger.info("[+] Documentation enabled: %s", _is_docs_enabled())


app = FastAPI(
    title="Security Portal Backend",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if _is_docs_enabled() else None,
    redoc_url="/redoc" if _is_docs_enabled() else None,
    openapi_url="/openapi.json" if _is_docs_enabled() else None,
)


@app.middleware("http")
async def require_jwt(request: Request, call_next):
    # Health check and documentation paths (if enabled) are always open
    open_paths = {"/health", "/settings/api/sources/internal-orgs"}
    enabled = _is_docs_enabled()
    if enabled:
        # Include common variants and static assets needed by Swagger/ReDoc
        open_paths.update({
            "/docs", "/docs/",
            "/redoc", "/redoc/",
            "/openapi.json",
        })

    # Exact match for open paths or prefix match for openapi.json
    path = request.url.path
    if path in open_paths or (enabled and path.startswith("/openapi.json")):
        return await call_next(request)

    # Runner agent endpoints use their own auth (runner Bearer tokens, not JWT)
    if path.startswith("/runner/api/"):
        return await call_next(request)

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"error": "Unauthorized: Bearer token required"},
        )

    token = auth_header.split(" ")[1]
    try:
        claims = verify_internal_jwt(token)
        user_sub = claims.get("sub")
        if not user_sub:
            return JSONResponse(status_code=401, content={"error": "Unauthorized: missing user identity"})
        request.state.user_sub = user_sub
        request.state.user_role = claims.get("role")
        request.state.user_role_id = claims.get("roleId")
    except ValueError:
        return JSONResponse(
            status_code=401,
            content={"error": "Unauthorized"},
        )

    # License tier resolution
    license_key = read_license_key()
    tier, license_claims = resolve_current_tier(license_key, EMBEDDED_PUBLIC_KEY)
    request.state.tier = tier
    request.state.license_claims = license_claims

    return await call_next(request)


app.include_router(dependencies_router)
app.include_router(container_scanning_router)
app.include_router(code_scanning_router)
app.include_router(secrets_router)
app.include_router(roles_router)
app.include_router(settings_router)
app.include_router(organisations_router)
app.include_router(sources_router)
app.include_router(users_router)
app.include_router(runner_admin_router)
app.include_router(runner_router)
app.include_router(license_router)
app.include_router(notifications_router)
app.include_router(internal_auth_router)
app.include_router(events_router)
app.include_router(sbom_router)

# Test seed endpoint — non-production only
if os.getenv("TEST_SEED_ENABLED", "").lower() in ("1", "true", "yes") and \
   os.getenv("FASTAPI_ENV", "").lower() != "production":
    from src.test_seed.router import router as test_seed_router
    app.include_router(test_seed_router)

# GraphQL API
_graphql_router = create_graphql_router()
app.include_router(_graphql_router, prefix="/graphql")


@app.get("/health")
def health() -> dict[str, str]:
    return {"ok": "true"}
