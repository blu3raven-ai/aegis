from __future__ import annotations

import asyncio
import logging
import os
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.responses import FileResponse
from starlette.staticfiles import StaticFiles

from src.db.engine import engine, get_session
from src.db.seed import seed_if_empty
from src.license.keys import EMBEDDED_PUBLIC_KEY
from src.license.middleware import resolve_current_tier
from src.license.store import read_license_key
from src.dependencies.router import router as dependencies_router
from src.containers.router import router as container_scanning_router
from src.code_scanning.router import router as code_scanning_router
from src.secrets.router import router as secrets_router
from src.settings.account_endpoints import account_router
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
from src.auth.login_router import login_router
from src.shared.events_router import events_router
from src.shared.sbom_router import router as sbom_router
from src.argus.webhook import router as argus_webhook_router
from src.integrations.github_webhook import router as github_webhook_router
from src.integrations.gitlab_webhook import router as gitlab_webhook_router
from src.integrations.bitbucket_webhook import router as bitbucket_webhook_router
from src.graphql.schema import create_graphql_router
from src.health.router import router as health_router
from src.images.router import router as images_router
from src.repos.router import router as repos_router
from src.scans.router import router as scans_router
from src.posture.router import router as posture_router
from src.releases.router import router as releases_router
from src.reports.router import router as reports_router
from src.sbom.router import router as sbom_export_router
from src.api_keys.middleware import try_api_key_auth
from src.api_keys.router import router as api_keys_router
from src.audit_log.middleware import AuditMiddleware
from src.audit_log.router import router as audit_router

from starlette.middleware.trustedhost import TrustedHostMiddleware

from src.auth.csrf import CSRFMiddleware
from src.auth.security_headers import SecurityHeadersMiddleware
from src.auth.session_gate import SessionAuthMiddleware
from src.auth.redirects import LegacyRedirectMiddleware
from src.auth.session import SessionService
from src.shared.config import get_session_secret
from src.db.engine import async_session_factory
from src.onboarding.router import router as onboarding_router
from src.compliance.router import router as compliance_router
from src.search.router import router as search_router
from src.sla.router import router as sla_router
from src.rules.router import router as rules_router
from src.exports.router import router as exports_router
from src.integrations.router import router as integrations_catalog_router
from src.findings.router import router as findings_router
from src.kev.router import router as kev_router
from src.epss.router import router as epss_router
from src.activity.router import router as activity_router
from src.decisions.router import router as decisions_router
from src.saved_views.router import router as saved_views_router
from src.assets.router import assets_router, scans_router as byo_scans_router
from src.shared.home_views import refresh_all_home_views
from src.shared.home_views_refresher import home_views_refresh_worker


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
            stale_runs = [
                (r.tool, (r.metadata_json or {}).get("org_label", ""), r.id)
                for r in result.scalars().all()
            ]
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

    if os.getenv("AEGIS_NOTIFICATIONS_ENABLED", "false").lower() == "true":
        from src.notifications.router_event import NotificationEventRouter
        _notification_router = NotificationEventRouter()
        _notification_router.start()
        app.state.notification_router = _notification_router

    # Warm the home dashboard MVs once at startup so the first request
    # doesn't see empty data, then start the event-driven refresh worker.
    await asyncio.to_thread(refresh_all_home_views)
    _home_views_refresh_task = asyncio.create_task(home_views_refresh_worker())

    yield

    # Graceful shutdown for the home views refresh worker
    _home_views_refresh_task.cancel()
    try:
        await _home_views_refresh_task
    except asyncio.CancelledError:
        pass

    # Graceful shutdown for the notification router if it was started
    _notification_router_inst = getattr(app.state, "notification_router", None)
    if _notification_router_inst is not None:
        _notification_router_inst.stop()

    get_scheduler().stop()
    await engine.dispose()


def _make_session_service() -> SessionService:
    """Per-middleware-call session service. Uses a fresh DB session.

    The auth gate runs before the request DB dependency, so it needs its own
    session. SessionAuthMiddleware owns the lifecycle and closes the underlying
    AsyncSession in a finally block — otherwise the pooled connection is only
    reclaimed when SQLAlchemy GCs the session, which logs a noisy warning.
    """
    db = async_session_factory()
    return SessionService(db=db)


def _compute_script_hashes() -> list[str]:
    """SHA-256 hashes of static script chunks for CSP allow-list.

    Reads STATIC_ROOT/_next/static/chunks/*.js at startup and returns the
    base64-encoded list. Falls back to an empty list if the static root or
    chunks dir is missing — keeps tests/dev workable without a built export.
    """
    from src.auth.csp import compute_inline_script_hashes

    chunks_dir = Path(os.getenv("STATIC_ROOT", "/app/static")) / "_next" / "static" / "chunks"
    if not chunks_dir.exists():
        return []
    return compute_inline_script_hashes(chunks_dir)


def _allowed_hosts() -> list[str]:
    """Hosts the app is willing to serve. Configure via ALLOWED_HOSTS env var."""
    raw = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,testserver")
    return [h.strip() for h in raw.split(",") if h.strip()]


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
    # Health check and documentation paths (if enabled) are always open.
    # /login and /pending are open so SessionAuthMiddleware's redirects can
    # resolve to the SPA shell without requiring a Bearer token.
    open_paths = {"/health", "/health/ready", "/health/live", "/settings/api/sources/internal-orgs",
                  "/auth/login", "/auth/login/verify", "/auth/logout",
                  "/login", "/pending"}
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

    # PR 4: static asset prefixes are public — browsers need these to load the
    # SPA shell before a session cookie exists.
    if path.startswith("/_next/") or path.startswith("/assets/"):
        return await call_next(request)

    # PR 3: SessionAuthMiddleware (outermost) already verified the session cookie
    # and attached request.state.session. Skip JWT verification — the session gate
    # is now the authoritative auth layer; JWT is being removed in Task 8.
    if getattr(request.state, "session", None) is not None:
        session = request.state.session
        request.state.user_sub = session.user_id
        request.state.user_role = session.user.role
        request.state.user_role_id = getattr(session.user, "role_id", None)
        # License tier resolution still applies
        license_key = read_license_key()
        tier, license_claims = resolve_current_tier(license_key, EMBEDDED_PUBLIC_KEY)
        request.state.tier = tier
        request.state.license_claims = license_claims
        return await call_next(request)

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"error": "Unauthorized: Bearer token required"},
        )

    token = auth_header.split(" ")[1]
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

# ── PR 3 cutover: FastAPI auth middlewares ────────────────────────────────────
# Stack runs OUTER -> INNER as: TrustedHost -> SecurityHeaders -> LegacyRedirect
# -> SessionAuth -> CSRF -> route handler. Because Starlette processes
# add_middleware in REVERSE order of dispatch, the registration order below
# is the inverse of the runtime order above.
app.add_middleware(CSRFMiddleware, secret=get_session_secret())
app.add_middleware(SessionAuthMiddleware, session_service_factory=_make_session_service)
app.add_middleware(LegacyRedirectMiddleware)
app.add_middleware(SecurityHeadersMiddleware, script_hashes=_compute_script_hashes())
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts())

app.include_router(audit_router)
app.include_router(api_keys_router)
app.include_router(dependencies_router)
app.include_router(container_scanning_router)
app.include_router(code_scanning_router)
app.include_router(secrets_router)
app.include_router(roles_router)
app.include_router(account_router)
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
app.include_router(login_router)
app.include_router(events_router)
app.include_router(sbom_router)
app.include_router(sbom_export_router)
app.include_router(argus_webhook_router)
app.include_router(github_webhook_router)
app.include_router(gitlab_webhook_router)
app.include_router(bitbucket_webhook_router)
app.include_router(health_router)
app.include_router(onboarding_router)
app.include_router(sla_router)
app.include_router(rules_router)
app.include_router(repos_router)
app.include_router(images_router)
app.include_router(scans_router)
app.include_router(posture_router)
app.include_router(releases_router)
app.include_router(reports_router)
app.include_router(compliance_router)
app.include_router(search_router)
app.include_router(exports_router)
app.include_router(integrations_catalog_router)
app.include_router(findings_router)
app.include_router(kev_router)
app.include_router(epss_router)
app.include_router(activity_router)
app.include_router(decisions_router)
app.include_router(saved_views_router)
app.include_router(assets_router)
app.include_router(byo_scans_router)

# Test seed endpoint — non-production only
if os.getenv("TEST_SEED_ENABLED", "").lower() in ("1", "true", "yes") and \
   os.getenv("FASTAPI_ENV", "").lower() != "production":
    from src.test_seed.router import router as test_seed_router
    app.include_router(test_seed_router)

# GraphQL API
_graphql_router = create_graphql_router()
app.include_router(_graphql_router, prefix="/api")

# ── PR 4: serve Next.js static export via FastAPI ────────────────────────────
_STATIC_ROOT = Path(os.getenv("STATIC_ROOT", "/app/static"))

if _STATIC_ROOT.exists():
    _next_dir = _STATIC_ROOT / "_next"
    if _next_dir.exists():
        app.mount(
            "/_next",
            StaticFiles(directory=_next_dir),
            name="next-static",
        )
    assets_dir = _STATIC_ROOT / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="public-assets")

    # SPA fallback — any GET not matched by FastAPI routes gets index.html.
    # MUST be the last route registered.
    @app.get("/{path:path}")
    async def spa_fallback(path: str) -> FileResponse:
        if ".." in path.split("/"):
            from fastapi import HTTPException
            raise HTTPException(status_code=400, detail="invalid path")
        candidate = _STATIC_ROOT / path
        if candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_STATIC_ROOT / "index.html", media_type="text/html")
