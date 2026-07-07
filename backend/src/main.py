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
from src.audit_log.router import router as audit_router
from src.history.releases.router import router as releases_router
from src.settings.audit_stream.router import audit_stream_router
from src.auth.account.email_router import email_router as account_email_router
from src.auth.account.profile_router import profile_router as account_profile_router
from src.auth.account.totp_router import totp_router as account_totp_router
from src.auth.workspace.grants_router import grants_router as workspace_grants_router
from src.auth.workspace.roles_router import roles_router as workspace_roles_router
from src.auth.workspace.teams_router import router as workspace_teams_router
from src.auth.workspace.users_router import users_router as workspace_users_router
from src.settings.auth_security.router import auth_security_router
from src.settings.scim.router import scim_settings_router
from src.settings.sso.router import sso_router
from src.settings.argus.router import router as argus_settings_router
from src.settings.llm.router import router as llm_settings_router
from src.settings.llm.usage_router import router as llm_usage_router
from src.settings.general.router import router as settings_router
from src.settings.organisations.router import router as organisations_router
from src.sources.source_connections_router import source_connections_router
from src.license.router import router as license_router
from src.runner.router import router as runner_router
from src.runner.admin_router import router as runner_admin_router
from src.notifications.router import router as notifications_router
from src.settings.notifications.router import config_router as notifications_config_router
from src.settings.notifications.signing_router import router as signing_secrets_router
from src.auth.authentication.login_router import login_router
from src.auth.federation.saml_router import saml_router
from src.auth.federation.oidc_router import oidc_router
from src.auth.federation.public_router import sso_public_router
from src.authz.roles.service import role_kind_from_id
from src.history.events_router import events_router
from src.connectors.webhooks.providers.argus import router as argus_webhook_router
from src.connectors.webhooks.providers.github import router as github_webhook_router
from src.connectors.webhooks.providers.gitlab import router as gitlab_webhook_router
from src.connectors.webhooks.providers.bitbucket import router as bitbucket_webhook_router
from src.connectors.webhooks.providers.azure_devops import router as azure_devops_webhook_router
from src.connectors.webhooks.providers.jenkins import router as jenkins_webhook_router
from src.graphql.schema import create_graphql_router
from src.health.router import router as health_router
from src.scans.router import router as scans_router
from src.sources.router import router as sources_router
from src.scans.manual_router import router as scans_manual_router
from src.scans.ci_router import router as scans_ci_router
from src.reports.router import router as reports_router
from src.sbom.router import router as sbom_router
from src.auth.credentials.middleware import try_api_key_auth
from src.auth.credentials.router import router as api_keys_router
from src.audit_log.middleware import AuditMiddleware
from src.audit_stream.poster import poster_loop
from src.notifications.retry_worker import retry_worker_loop
from src.pr_feedback.poster import poster_loop as pr_feedback_poster_loop

from starlette.middleware.trustedhost import TrustedHostMiddleware

from src.auth.authentication.csrf import CSRFMiddleware
from src.auth.authentication.security_headers import SecurityHeadersMiddleware
from src.auth.authentication.session_gate import SessionAuthMiddleware
from src.auth.authentication.redirects import LegacyRedirectMiddleware
from src.auth.authentication.session import SessionService
from src.shared.config import get_allowed_hosts, get_session_secret
from src.db.engine import async_session_factory
from src.compliance.router import router as compliance_router
from src.sla.router import router as sla_router
from src.rules.router import router as rules_router
from src.exports.router import router as exports_router
from src.settings.webhooks.router import router as webhook_endpoints_router
from src.findings.router import router as findings_router
from src.epss.router import router as epss_router
from src.decisions.router import router as decisions_router
from src.settings.saved_views.router import router as saved_views_router
from src.scans.byo_router import router as scans_byo_router
from src.shared.home_views import refresh_all_home_views
from src.shared.home_views_refresher import home_views_refresh_worker
from src.auth.identity.router import scim_router
from src.enrichment.router import router as enrichment_router


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
        "dependencies_scanning": update_dependencies_run,
        "secret_scanning": update_secret_run,
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
        if tool == "secret_scanning":
            try:
                mark_run_cancelled(org, run_id)
            except Exception:
                pass


_audit_stream_stop = asyncio.Event()
_audit_stream_task: asyncio.Task | None = None

_pr_feedback_stop = asyncio.Event()
_pr_feedback_task: asyncio.Task | None = None

_notif_retry_stop = asyncio.Event()
_notif_retry_task: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    # Warn early so misconfiguration surfaces at deploy time, not on first use.
    if not os.environ.get("APP_SECRET"):
        logger.warning(
            "APP_SECRET is not set; encrypted columns (source tokens, LLM/"
            "Argus/SSO/audit-streaming) and federation-state signing will use an "
            "ephemeral key that is lost on restart until it is set."
        )

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

    from src.connectors.webhooks.event_listener import WebhookScanDispatcher
    _webhook_dispatcher = WebhookScanDispatcher()
    _webhook_dispatcher.start()
    app.state.webhook_dispatcher = _webhook_dispatcher

    # Warm the home dashboard MVs once at startup so the first request
    # doesn't see empty data, then start the event-driven refresh worker.
    await asyncio.to_thread(refresh_all_home_views)
    _home_views_refresh_task = asyncio.create_task(home_views_refresh_worker())

    global _audit_stream_task
    _audit_stream_stop.clear()
    _audit_stream_task = asyncio.create_task(poster_loop(_audit_stream_stop))

    global _pr_feedback_task
    _pr_feedback_stop.clear()
    _pr_feedback_task = asyncio.create_task(pr_feedback_poster_loop(_pr_feedback_stop))

    global _notif_retry_task
    _notif_retry_stop.clear()
    _notif_retry_task = asyncio.create_task(retry_worker_loop(_notif_retry_stop))

    yield

    # Graceful shutdown for the notification retry worker
    _notif_retry_stop.set()
    if _notif_retry_task:
        try:
            await asyncio.wait_for(_notif_retry_task, timeout=10.0)
        except asyncio.TimeoutError:
            _notif_retry_task.cancel()

    # Graceful shutdown for the PR feedback poster
    _pr_feedback_stop.set()
    if _pr_feedback_task:
        try:
            await asyncio.wait_for(_pr_feedback_task, timeout=10.0)
        except asyncio.TimeoutError:
            _pr_feedback_task.cancel()

    # Graceful shutdown for the audit-stream poster
    _audit_stream_stop.set()
    if _audit_stream_task:
        try:
            await asyncio.wait_for(_audit_stream_task, timeout=10.0)
        except asyncio.TimeoutError:
            _audit_stream_task.cancel()

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

    _webhook_dispatcher_inst = getattr(app.state, "webhook_dispatcher", None)
    if _webhook_dispatcher_inst is not None:
        _webhook_dispatcher_inst.stop()

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


def _html_url_paths(rel: Path) -> list[str]:
    """Map an exported HTML file (relative to the export root) to the request
    path(s) it is served at. Mirrors spa_fallback: trailingSlash:false emits
    `<route>.html`, and index.html is the SPA shell served at `/`."""
    posix = rel.as_posix()
    if posix == "index.html":
        return ["/"]
    if posix.endswith("/index.html"):
        return ["/" + posix[: -len("/index.html")]]
    if posix.endswith(".html"):
        return ["/" + posix[: -len(".html")]]
    return []


def _resolve_export_html(static_root: Path, parts: list[str]) -> Path | None:
    """Resolve a request path to a prerendered HTML file under the static export.

    Matches Next.js route precedence segment by segment: a literal child wins
    over the "_" dynamic-route stub, with backtracking so a dynamic parent can
    still resolve a literal child. This handles routes with several dynamic
    segments (e.g. compliance/_/_.html for /compliance/<framework>/<controlId>),
    not just a single one — a one-segment-at-a-time replacement would never
    match the nested stub and would fall through to the 404 document.

    Returns the resolved HTML path, or None when no page or stub matches.
    ``static_root`` must already be resolved; every candidate is confirmed to
    stay within it so a "_" segment can't be abused to escape the export root.
    """
    def _walk(node: Path, segs: list[str]) -> Path | None:
        if not segs:
            return None
        seg, rest = segs[0], segs[1:]
        if not rest:
            # Terminal segment: prefer "<seg>.html", fall back to the stub.
            for name in (f"{seg}.html", "_.html"):
                try:
                    cand = (node / name).resolve()
                except (OSError, RuntimeError, ValueError):
                    continue
                if cand.is_file() and cand.is_relative_to(static_root):
                    return cand
            return None
        # Intermediate segment: descend into the literal dir first, then the
        # "_" stub dir, backtracking if the chosen branch dead-ends.
        for name in (seg, "_"):
            try:
                child = (node / name).resolve()
            except (OSError, RuntimeError, ValueError):
                continue
            if child.is_dir() and child.is_relative_to(static_root):
                found = _walk(child, rest)
                if found is not None:
                    return found
        return None

    return _walk(static_root, parts)


def _build_security_csp_args() -> dict[str, object]:
    """Per-page CSP for each exported HTML document, keyed by request path.

    Each page's policy hashes its own inline scripts + entry chunks (they
    differ per route). Non-HTML responses get a minimal script-less policy.
    Falls back to empty policies if no export is present — keeps tests/dev
    workable without a built frontend.
    """
    from src.auth.authentication.csp import inline_script_hashes_for_html
    from src.auth.authentication.security_headers import _build_csp

    static_root = Path(os.getenv("STATIC_ROOT", "/app/static"))
    base_csp = _build_csp([])
    html_csp_by_path: dict[str, str] = {}
    if static_root.exists():
        for html in static_root.glob("**/*.html"):
            try:
                hashes = inline_script_hashes_for_html(html.read_text(encoding="utf-8"))
            except OSError:
                continue
            csp = _build_csp(hashes)
            for url_path in _html_url_paths(html.relative_to(static_root)):
                html_csp_by_path[url_path] = csp
    return {
        "html_csp_by_path": html_csp_by_path,
        # Unmatched routes are served the 404 document by spa_fallback, so the
        # fallback CSP must carry 404.html's inline-script hashes — not the home
        # page's, whose hashes wouldn't match and would block the 404's scripts.
        "default_html_csp": html_csp_by_path.get("/404", base_csp),
        "base_csp": base_csp,
    }


def _is_docs_enabled() -> bool:
    return os.getenv("ENABLE_BACKEND_DOCS", "").lower() == "true"


logger = logging.getLogger(__name__)
logger.info("[+] Documentation enabled: %s", _is_docs_enabled())


app = FastAPI(
    title="Security Portal Backend",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url="/openapi.json" if _is_docs_enabled() else None,
)


if _is_docs_enabled():
    from fastapi.openapi.docs import get_swagger_ui_html

    # Self-hosted swagger-ui-dist@5.32.6 — keeps the strict CSP intact by
    # avoiding cdn.jsdelivr.net. Refresh with `curl https://cdn.jsdelivr.net/
    # npm/swagger-ui-dist@<ver>/{swagger-ui-bundle.js,swagger-ui.css,favicon-32x32.png}`.
    _swagger_assets = Path(__file__).parent / "swagger"
    app.mount("/swagger", StaticFiles(directory=_swagger_assets), name="swagger-ui")

    @app.get("/docs", include_in_schema=False)
    async def custom_swagger_ui_html():
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title="Security Portal Backend - Swagger UI",
            swagger_js_url="/swagger/swagger-ui-bundle.js",
            swagger_css_url="/swagger/swagger-ui.css",
            swagger_favicon_url="/swagger/favicon.png",
        )


def _is_integrations_webhook_path(path: str) -> bool:
    """SCM webhook receivers authenticate via HMAC signatures, not JWTs.

    Scoped to the receiver routes only so future /integrations/* admin/list
    endpoints still enforce the session/JWT gate.
    """
    return path.startswith("/integrations/") and path.endswith("/webhook")


_GQL_PATH = "/api/v1/graphql"


def _is_dev_graphiql_request(method: str, path: str) -> bool:
    """``/api/v1/graphql`` is open at the middleware layer when ``ENABLE_BACKEND_DOCS=true``.

    Matches Swagger UI's pattern: the route is reachable without a session so the
    in-browser explorer (GraphiQL on GET, introspection + queries on POST) is
    usable. Resolvers still gate real data via ``get_graphql_context`` so an
    unauthenticated POST surfaces a clean ``UNAUTHENTICATED`` GraphQL error
    instead of the FastAPI ``Bearer token required`` envelope.
    """
    return path == _GQL_PATH and method in ("GET", "POST") and _is_docs_enabled()


def _propagate_session_to_state(request: Request) -> None:
    """Copy session-derived auth onto request.state for downstream readers.

    SessionAuthMiddleware attaches request.state.session; resolvers, audit, and
    REST handlers all read user_sub/user_role/tier from request.state. Any
    branch in require_jwt that lets a request through without going via the
    Bearer-token path must call this so an authenticated request still arrives
    with a populated identity — otherwise GraphQL resolvers see user_sub=None
    and reject the request with UNAUTHENTICATED.
    """
    session = getattr(request.state, "session", None)
    if session is None:
        return
    request.state.user_sub = session.user_id
    request.state.user_role_id = getattr(session.user, "role_id", None)
    request.state.user_role = role_kind_from_id(request.state.user_role_id)
    request.state.user_org = "default"
    license_key = read_license_key()
    tier, license_claims = resolve_current_tier(license_key, EMBEDDED_PUBLIC_KEY)
    request.state.tier = tier
    request.state.license_claims = license_claims


@app.middleware("http")
async def require_jwt(request: Request, call_next):
    # Health check and documentation paths (if enabled) are always open.
    # /login and /pending are open so SessionAuthMiddleware's redirects can
    # resolve to the SPA shell without requiring a Bearer token.
    open_paths = {"/health",
                  "/api/v1/auth/login", "/api/v1/auth/login/verify", "/api/v1/auth/logout",
                  "/auth/sso/saml/login", "/auth/sso/saml/acs", "/auth/sso/saml/metadata",
                  "/auth/sso/saml/slo", "/auth/sso/saml/slo/initiate",
                  "/auth/sso/oidc/login", "/auth/sso/oidc/callback",
                  "/login", "/pending",
                  "/logo-brand.png",
                  "/api/v1/auth/sso/availability",
                  "/api/v1/settings/organisations/branding"}
    enabled = _is_docs_enabled()
    if enabled:
        open_paths.update({
            "/docs", "/docs/",
            "/openapi.json",
        })

    path = request.url.path
    if path in open_paths or (
        enabled and (path.startswith("/openapi.json") or path.startswith("/swagger/"))
    ):
        return await call_next(request)

    if _is_dev_graphiql_request(request.method, path):
        _propagate_session_to_state(request)
        return await call_next(request)

    # SCIM endpoints authenticate via their own bearer-token dependency
    if path.startswith("/scim/v2/"):
        return await call_next(request)

    # Runner agent endpoints use their own auth (runner Bearer tokens, not JWT)
    if path.startswith("/api/v1/agent/"):
        return await call_next(request)

    if _is_integrations_webhook_path(path):
        return await call_next(request)

    # PR 4: static asset prefixes are public — browsers need these to load the
    # SPA shell before a session cookie exists.
    if path.startswith("/_next/") or path.startswith("/assets/"):
        return await call_next(request)

    # PR 3: SessionAuthMiddleware (outermost) already verified the session cookie
    # and attached request.state.session. Skip JWT verification — the session gate
    # is now the authoritative auth layer; JWT is being removed in Task 8.
    if getattr(request.state, "session", None) is not None:
        _propagate_session_to_state(request)
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

# Stack runs OUTER -> INNER as: TrustedHost -> SecurityHeaders -> LegacyRedirect
# -> SessionAuth -> CSRF -> route handler. Because Starlette processes
# add_middleware in REVERSE order of dispatch, the registration order below
# is the inverse of the runtime order above.
app.add_middleware(CSRFMiddleware, secret=get_session_secret())
app.add_middleware(SessionAuthMiddleware, session_service_factory=_make_session_service)
app.add_middleware(LegacyRedirectMiddleware)
app.add_middleware(SecurityHeadersMiddleware, **_build_security_csp_args())
app.add_middleware(TrustedHostMiddleware, allowed_hosts=get_allowed_hosts())

app.include_router(api_keys_router)
app.include_router(audit_router)
app.include_router(releases_router)
app.include_router(audit_stream_router)
app.include_router(scim_settings_router)
app.include_router(sso_router)
app.include_router(auth_security_router)
app.include_router(account_email_router)
app.include_router(account_totp_router)
app.include_router(account_profile_router)
app.include_router(workspace_users_router)
app.include_router(workspace_roles_router)
app.include_router(workspace_grants_router)
app.include_router(workspace_teams_router)
app.include_router(llm_settings_router)
app.include_router(llm_usage_router)
app.include_router(argus_settings_router)
app.include_router(settings_router)
app.include_router(organisations_router)
app.include_router(source_connections_router)
app.include_router(runner_router)
app.include_router(runner_admin_router)
app.include_router(license_router)
app.include_router(notifications_router)
app.include_router(notifications_config_router)
app.include_router(signing_secrets_router)
app.include_router(login_router)
app.include_router(saml_router)
app.include_router(oidc_router)
app.include_router(sso_public_router)
app.include_router(events_router)
app.include_router(sbom_router)
app.include_router(argus_webhook_router)
app.include_router(github_webhook_router)
app.include_router(gitlab_webhook_router)
app.include_router(bitbucket_webhook_router)
app.include_router(azure_devops_webhook_router)
app.include_router(jenkins_webhook_router)
app.include_router(health_router)
app.include_router(sla_router)
app.include_router(rules_router)
app.include_router(sources_router)
app.include_router(scans_router)
app.include_router(scans_manual_router)
app.include_router(scans_ci_router)
app.include_router(reports_router)
app.include_router(compliance_router)
app.include_router(exports_router)
app.include_router(webhook_endpoints_router)
app.include_router(findings_router)
app.include_router(epss_router)
app.include_router(decisions_router)
app.include_router(saved_views_router)
app.include_router(scans_byo_router)
app.include_router(scim_router)
app.include_router(enrichment_router)

# GraphQL API
_graphql_router = create_graphql_router()
app.include_router(_graphql_router, prefix="/api/v1")

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

    # SPA fallback — serves prerendered pages, dynamic-route shells, and the
    # app index for "/". Genuinely unknown routes get the 404 document with a
    # 404 status. MUST be the last route registered.
    _STATIC_ROOT_RESOLVED = _STATIC_ROOT.resolve()

    @app.get("/{path:path}")
    async def spa_fallback(path: str) -> FileResponse:
        # Resolve the requested path against the static root and confirm it
        # still lives inside it — guards against URL-encoded traversal
        # (e.g. /%2e%2e/etc/passwd) and absolute paths that os.path.join
        # would silently honour.
        from fastapi import HTTPException
        try:
            candidate = (_STATIC_ROOT_RESOLVED / path).resolve()
        except (OSError, RuntimeError, ValueError):
            raise HTTPException(status_code=400, detail="invalid path")
        if not candidate.is_relative_to(_STATIC_ROOT_RESOLVED):
            raise HTTPException(status_code=400, detail="invalid path")
        if candidate.is_file():
            return FileResponse(candidate)
        # Next static export (trailingSlash: false) emits each prerendered
        # route as "<route>.html" at the export root. Serve that page when it
        # exists so routes outside the SPA shell (e.g. /login, /pending) render
        # their own document instead of falling through to the app index.
        html_candidate = candidate.parent / f"{candidate.name}.html"
        if html_candidate.is_file() and html_candidate.is_relative_to(_STATIC_ROOT_RESOLVED):
            return FileResponse(html_candidate, media_type="text/html")
        # Dynamic segments: Next.js generateStaticParams stubs use "_" as the
        # placeholder id (e.g. sources/_.html, sources/_/findings.html,
        # compliance/_/_.html). Walk the export tree to match dynamic route
        # shells at any nesting depth, so /sources/abc123 serves sources/_.html
        # and /compliance/iso27001/A.8.8 serves compliance/_/_.html instead of
        # falling through to the 404 document.
        parts = [p for p in path.strip("/").split("/") if p]
        stub_html = _resolve_export_html(_STATIC_ROOT_RESOLVED, parts)
        if stub_html is not None:
            return FileResponse(stub_html, media_type="text/html")
        # Root path is the SPA shell; serve the app index.
        if path in ("", "index.html"):
            return FileResponse(_STATIC_ROOT_RESOLVED / "index.html", media_type="text/html")
        # No prerendered page, dynamic stub, or shell matched — the route does
        # not exist. Serve the export's 404 document with a genuine 404 status
        # instead of silently rendering the home shell at 200.
        not_found = _STATIC_ROOT_RESOLVED / "404.html"
        if not_found.is_file():
            return FileResponse(not_found, media_type="text/html", status_code=404)
        raise HTTPException(status_code=404, detail="Not Found")
