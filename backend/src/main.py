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
from src.notifications.admin_router import router as notifications_admin_router
from src.notifications.rules_router import router as notification_rules_router
from src.notifications.signing_secrets_router import router as signing_secrets_router
from src.auth.internal_router import internal_auth_router
from src.shared.events_router import events_router
from src.shared.sbom_router import router as sbom_router
from src.argus.webhook import router as argus_webhook_router
from src.integrations.github_webhook import router as github_webhook_router
from src.integrations.gitlab_webhook import router as gitlab_webhook_router
from src.integrations.bitbucket_webhook import router as bitbucket_webhook_router
from src.graphql.schema import create_graphql_router
from src.correlation.router import router as chains_router
from src.correlation.admin_router import router as correlation_admin_router
from src.correlation.temporal_router import router as temporal_router
from src.health.router import router as health_router
from src.repos.router import router as repos_router
from src.argus.connector import get_argus_connector
from src.sbom.router import router as sbom_export_router
from src.api_keys.middleware import try_api_key_auth
from src.api_keys.router import router as api_keys_router
from src.audit_log.middleware import AuditMiddleware
from src.audit_log.router import router as audit_router
from src.onboarding.router import router as onboarding_router
from src.compliance.router import router as compliance_router
from src.search.router import router as search_router
from src.fleet.router import router as fleet_router
from src.sla.router import router as sla_router
from src.exports.router import router as exports_router
from src.findings.router import router as findings_router
from src.kev.router import router as kev_router
from src.epss.router import router as epss_router
from src.activity.router import router as activity_router
from src.decisions.router import router as decisions_router


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

    # Start the correlation engine when explicitly enabled. Defaults to dormant
    # so the existing behavior is fully preserved for unconfigured deployments.
    if os.getenv("AEGIS_CORRELATION_ENABLED", "false").lower() == "true":
        from src.correlation.engine import CorrelationEngine
        from src.correlation.rules import register_builtin_rules
        from src.shared.config import load_redis_stream_config
        _stream_cfg = load_redis_stream_config()
        _redis_cfg = {"url": os.getenv("REDIS_URL", "redis://localhost:6379/0")}
        _correlation_engine = CorrelationEngine(
            stream_config=_stream_cfg,
            redis_config=_redis_cfg,
            argus=get_argus_connector(),
        )
        register_builtin_rules(_correlation_engine)
        _correlation_engine.start()
        app.state.correlation_engine = _correlation_engine
        logging.getLogger(__name__).info("correlation.engine: started via AEGIS_CORRELATION_ENABLED")

    # Start the notification event router when explicitly enabled. Defaults to
    # dormant so deployments without Redis or external destinations are unaffected.
    if os.getenv("AEGIS_NOTIFICATIONS_ENABLED", "false").lower() == "true":
        from src.notifications.router_event import NotificationEventRouter
        from src.shared.config import load_redis_stream_config
        _notif_stream_cfg = load_redis_stream_config()
        _notification_router = NotificationEventRouter(_notif_stream_cfg)
        _notification_router.start()
        app.state.notification_router = _notification_router
        logging.getLogger(__name__).info("notification.router: started via AEGIS_NOTIFICATIONS_ENABLED")

    yield

    # Graceful shutdown for the notification router if it was started
    _notification_router_inst = getattr(app.state, "notification_router", None)
    if _notification_router_inst is not None:
        _notification_router_inst.stop()

    # Graceful shutdown for the correlation engine if it was started
    _correlation_engine_inst = getattr(app.state, "correlation_engine", None)
    if _correlation_engine_inst is not None:
        _correlation_engine_inst.stop()

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
    open_paths = {"/health", "/health/ready", "/health/live", "/settings/api/sources/internal-orgs"}
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

    # SCM webhook endpoints authenticate via HMAC signatures, not JWTs
    if path.startswith("/integrations/"):
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
        # JWT verification failed — try API key auth before giving up
        api_key_row = await try_api_key_auth(request, token)
        if api_key_row is None:
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


app.add_middleware(AuditMiddleware)

app.include_router(audit_router)
app.include_router(api_keys_router)
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
app.include_router(notifications_admin_router)
app.include_router(notification_rules_router)
app.include_router(signing_secrets_router)
app.include_router(internal_auth_router)
app.include_router(events_router)
app.include_router(sbom_router)
app.include_router(sbom_export_router)
app.include_router(argus_webhook_router)
app.include_router(github_webhook_router)
app.include_router(gitlab_webhook_router)
app.include_router(bitbucket_webhook_router)
app.include_router(chains_router)
app.include_router(correlation_admin_router)
app.include_router(temporal_router)
app.include_router(health_router)
app.include_router(onboarding_router)
app.include_router(sla_router)
app.include_router(repos_router)
app.include_router(compliance_router)
app.include_router(search_router)
app.include_router(fleet_router)
app.include_router(exports_router)
app.include_router(findings_router)
app.include_router(kev_router)
app.include_router(epss_router)
app.include_router(activity_router)
app.include_router(decisions_router)

# Test seed endpoint — non-production only
if os.getenv("TEST_SEED_ENABLED", "").lower() in ("1", "true", "yes") and \
   os.getenv("FASTAPI_ENV", "").lower() != "production":
    from src.test_seed.router import router as test_seed_router
    app.include_router(test_seed_router)

# GraphQL API
_graphql_router = create_graphql_router()
app.include_router(_graphql_router, prefix="/graphql")


