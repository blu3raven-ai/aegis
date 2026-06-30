"""Root GraphQL schema — aggregates all tool resolvers under namespace types."""
from __future__ import annotations

import os
from typing import Optional

import strawberry
from strawberry.fastapi import GraphQLRouter
from strawberry.schema.config import StrawberryConfig

from src.graphql.auth import get_workspace_context
from src.graphql.resolver_utils import raise_bad_input, raise_permission_denied, unpack_ctx
from src.graphql.extensions import (
    AliasLimitExtension,
    DepthLimitExtension,
    ErrorMaskingExtension,
    IntrospectionBlocker,
    OperationNameRequiredExtension,
    QueryTimeoutExtension,
)
from src.search.resolvers import SearchResults, global_search as _global_search
from src.graphql.types import SeverityCounts
from src.scans.resolvers import (
    code_scanning_counts,
    container_scanning_counts,
    dependencies_scanning_counts,
    iac_scanning_counts,
    secret_scanning_counts,
)
from src.posture.resolvers import (
    PostureSnapshot, TeamPosture,
    home_analytics, posture_by_team, posture_snapshot, posture_trend,
)
from src.sbom.resolvers import (
    SbomComponentsConnection, SbomFilterOptions, SbomCrossRefResult, SbomBulkResult,
    SbomHistoryEntry, SbomDiffOrError, RepoComponentVulns, RiskyComponentsConnection, PackageRepo,
    sbom_search, sbom_filter_options, sbom_cross_references, sbom_bulk_lookup,
    sbom_history, sbom_diff, sbom_component_vulns, sbom_risky_components, sbom_package_repos,
)
from src.sla.resolvers import sla_breach_summary
from src.epss.resolvers import epss_top
from src.sources.resolvers import (
    image_sources as _image_sources,
    repo_sources as _repo_sources,
    source as _source,
)
from src.sources.scan_runs_resolvers import (
    scan_runs as _scan_runs,
    connection_scan_runs as _connection_scan_runs,
    ScanRun,
    ConnectionScanRun,
)
from src.findings.resolvers import (
    FindingsSearchResult,
    findings_search as _findings_search,
)
from src.history.resolvers import (
    HistoryConnection,
    history as _history,
    history_types as _history_types,
)
from src.settings.integrations.resolvers import (
    IntegrationsCatalog,
    integrations_catalog as _integrations_catalog,
)
from src.settings.webhooks.resolvers import (
    WebhookEndpointListResponse,
    webhook_endpoints as _webhook_endpoints,
)
from src.notifications.resolvers import (
    NotificationDelivery,
    NotificationDestination,
    NotificationRule,
    NotificationsInbox,
    notification_deliveries as _notification_deliveries,
    notification_destinations as _notification_destinations,
    notification_rules as _notification_rules,
    notifications_inbox as _notifications_inbox,
    notifications_unread_count as _notifications_unread_count,
)
from src.settings.saved_views.resolvers import (
    SavedView,
    saved_views as _saved_views,
)
from src.settings.auth_security.resolvers import (
    AuthSecuritySettings,
    auth_security_settings as _auth_security_settings,
)
from src.settings.sso.resolvers import (
    SsoSettings,
    sso_settings as _sso_settings,
)
from src.settings.scim.resolvers import (
    ScimSettings,
    scim_settings as _scim_settings,
)
from src.runner.resolvers import (
    HeartbeatEntryGQL,
    RunnerDetailResult,
    RunnersListResult,
    runner as _runner,
    runner_heartbeats as _runner_heartbeats,
    runners as _runners,
)
from src.auth.workspace.resolvers import (
    WorkspaceTeam, WorkspaceUserDirectoryEntry,
    teams as _teams,
    user_directory as _user_directory,
)
from src.graphql.types import (
    PostureTrendPoint, HomeAnalytics,
    BreachSummary, EpssTopResponse,
    RepoSourcesResponse, ImageSourcesResponse, SourceDetail,
)


# ============================================================
# Query namespace types
# ============================================================

@strawberry.type
class DependenciesScanningQuery:
    @strawberry.field
    async def counts(self, info: strawberry.types.Info) -> SeverityCounts:
        ctx, asset_ids = await unpack_ctx(info)
        return dependencies_scanning_counts(asset_ids=asset_ids, info_context=ctx)


@strawberry.type
class CodeScanningQuery:
    @strawberry.field
    async def counts(self, info: strawberry.types.Info) -> SeverityCounts:
        ctx, asset_ids = await unpack_ctx(info)
        return code_scanning_counts(asset_ids=asset_ids, info_context=ctx)


@strawberry.type
class ContainerScanningQuery:
    @strawberry.field
    async def counts(self, info: strawberry.types.Info) -> SeverityCounts:
        ctx, asset_ids = await unpack_ctx(info)
        return container_scanning_counts(asset_ids=asset_ids, info_context=ctx)


@strawberry.type
class SecretScanningQuery:
    @strawberry.field
    async def counts(self, info: strawberry.types.Info) -> SeverityCounts:
        ctx, asset_ids = await unpack_ctx(info)
        return secret_scanning_counts(asset_ids=asset_ids, info_context=ctx)


@strawberry.type
class IacScanningQuery:
    @strawberry.field
    async def counts(self, info: strawberry.types.Info) -> SeverityCounts:
        ctx, asset_ids = await unpack_ctx(info)
        return iac_scanning_counts(asset_ids=asset_ids, info_context=ctx)


@strawberry.type
class ScansQuery:
    @strawberry.field
    def dependencies_scanning(self) -> DependenciesScanningQuery:
        return DependenciesScanningQuery()

    @strawberry.field
    def code_scanning(self) -> CodeScanningQuery:
        return CodeScanningQuery()

    @strawberry.field
    def container_scanning(self) -> ContainerScanningQuery:
        return ContainerScanningQuery()

    @strawberry.field
    def secret_scanning(self) -> SecretScanningQuery:
        return SecretScanningQuery()

    @strawberry.field
    def iac_scanning(self) -> IacScanningQuery:
        return IacScanningQuery()


@strawberry.type
class FindingsQuery:
    @strawberry.field
    async def search(
        self,
        info: strawberry.types.Info,
        org: Optional[str] = None,
        severity: Optional[str] = None,
        scanner: Optional[str] = None,
        state: Optional[str] = None,
        q: Optional[str] = None,
        cve: Optional[str] = None,
        repo: Optional[str] = None,
        sort: str = "severity",
        direction: str = "desc",
        limit: int = 50,
        cursor: Optional[str] = None,
        page: int = 1,
        archived: Optional[bool] = None,
        first_seen_after: Optional[str] = None,
        cwe: Optional[str] = None,
        kev: Optional[bool] = None,
        epss_min: Optional[float] = None,
        risk_score_min: Optional[int] = None,
        bands: Optional[str] = None,
        assignee: Optional[str] = None,
        verdict: Optional[str] = None,
    ) -> FindingsSearchResult:
        ctx, asset_ids = await unpack_ctx(info)
        try:
            return await _findings_search(
                asset_ids=asset_ids, org=org,
                severity=severity, scanner=scanner, state=state,
                q=q, cve=cve, repo=repo,
                sort=sort, direction=direction,
                limit=limit, cursor=cursor, page=page,
                archived=archived, first_seen_after=first_seen_after,
                cwe=cwe, kev=kev, epss_min=epss_min,
                risk_score_min=risk_score_min, bands=bands,
                assignee=assignee, verdict=verdict,
            )
        except ValueError as exc:
            raise_bad_input(str(exc))

    @strawberry.field
    async def global_search(
        self,
        info: strawberry.types.Info,
        q: str,
        scopes: Optional[list[str]] = None,
        limit: int = 50,
    ) -> SearchResults:
        ctx, asset_ids = await unpack_ctx(info)
        request = info.context["request"]
        org_id = request.query_params.get("org_id") or None
        return await _global_search(
            q=q,
            scopes=scopes,
            limit=limit,
            org_id=org_id,
            asset_ids=asset_ids,
            info_context=ctx,
        )


@strawberry.type
class SbomQuery:
    @strawberry.field
    async def search(
        self,
        info: strawberry.types.Info,
        search: Optional[str] = None,
        ecosystems: Optional[list[str]] = None,
        source: Optional[str] = None,
        repos: Optional[list[str]] = None,
        version_op: Optional[str] = None,
        version_value: Optional[str] = None,
        version_value_end: Optional[str] = None,
        filter_logic: Optional[str] = None,
        vulnerable_only: Optional[bool] = None,
        license_categories: Optional[list[str]] = None,
        dependency: Optional[str] = None,
        page: int = 1,
        per_page: int = 50,
    ) -> SbomComponentsConnection:
        ctx, _ = await unpack_ctx(info)
        return sbom_search(
            search=search, ecosystems=ecosystems, source=source,
            repos=repos, version_op=version_op, version_value=version_value,
            version_value_end=version_value_end, filter_logic=filter_logic,
            vulnerable_only=vulnerable_only, license_categories=license_categories,
            dependency=dependency, page=page, per_page=per_page, info_context=ctx,
        )

    @strawberry.field
    async def filter_options(self, info: strawberry.types.Info) -> SbomFilterOptions:
        ctx, _ = await unpack_ctx(info)
        return sbom_filter_options(info_context=ctx)

    @strawberry.field
    async def cross_references(self, info: strawberry.types.Info, purl: str) -> SbomCrossRefResult:
        ctx, _ = await unpack_ctx(info)
        return sbom_cross_references(purl=purl, info_context=ctx)

    @strawberry.field
    async def component_vulns(self, info: strawberry.types.Info, repo: str) -> list[RepoComponentVulns]:
        ctx, _ = await unpack_ctx(info)
        return sbom_component_vulns(repo=repo, info_context=ctx)

    @strawberry.field
    async def bulk_lookup(self, info: strawberry.types.Info, queries: list[str]) -> SbomBulkResult:
        ctx, _ = await unpack_ctx(info)
        return sbom_bulk_lookup(queries=queries, info_context=ctx)

    @strawberry.field
    async def risky_components(
        self,
        info: strawberry.types.Info,
        search: Optional[str] = None,
        ecosystems: Optional[list[str]] = None,
        page: int = 1,
        per_page: int = 25,
    ) -> RiskyComponentsConnection:
        ctx, _ = await unpack_ctx(info)
        return sbom_risky_components(
            search=search, ecosystems=ecosystems, page=page, per_page=per_page, info_context=ctx
        )

    @strawberry.field
    async def package_repos(self, info: strawberry.types.Info, package_name: str) -> list[PackageRepo]:
        ctx, _ = await unpack_ctx(info)
        return sbom_package_repos(package_name=package_name, info_context=ctx)

    @strawberry.field
    async def history(
        self,
        info: strawberry.types.Info,
        repo: str,
        limit: int = 10,
    ) -> list[SbomHistoryEntry]:
        ctx, _ = await unpack_ctx(info)
        return sbom_history(repo=repo, limit=limit, info_context=ctx)

    @strawberry.field
    async def diff(
        self,
        info: strawberry.types.Info,
        repo_id: Optional[str] = None,
        from_run_id: Optional[str] = None,
        to_run_id: Optional[str] = None,
        image_digest_from: Optional[str] = None,
        image_digest_to: Optional[str] = None,
    ) -> SbomDiffOrError:
        ctx, _ = await unpack_ctx(info)
        return sbom_diff(
            repo_id=repo_id,
            from_run_id=from_run_id,
            to_run_id=to_run_id,
            image_digest_from=image_digest_from,
            image_digest_to=image_digest_to,
            info_context=ctx,
        )


@strawberry.type
class PostureQuery:
    @strawberry.field
    async def trend(self, info: strawberry.types.Info, days: int = 30) -> list[PostureTrendPoint]:
        ctx, _ = await unpack_ctx(info)
        return posture_trend(days=days, info_context=ctx)

    @strawberry.field
    async def snapshot(self, info: strawberry.types.Info) -> PostureSnapshot:
        ctx, _ = await unpack_ctx(info)
        return posture_snapshot(info_context=ctx)

    @strawberry.field
    async def by_team(self, info: strawberry.types.Info) -> list[TeamPosture]:
        ctx, _ = await unpack_ctx(info)
        return posture_by_team(info_context=ctx)

    @strawberry.field
    async def home_analytics(self, info: strawberry.types.Info) -> HomeAnalytics:
        ctx, _ = await unpack_ctx(info)
        return home_analytics(info_context=ctx)


@strawberry.type
class SourcesQuery:
    @strawberry.field
    async def repo_sources(
        self,
        info: strawberry.types.Info,
        since_days: Optional[int] = None,
        has_critical: Optional[bool] = None,
        limit: int = 100,
    ) -> RepoSourcesResponse:
        ctx, asset_ids = await unpack_ctx(info)
        return _repo_sources(
            asset_ids=asset_ids,
            info_context=ctx,
            since_days=since_days,
            has_critical=has_critical,
            limit=limit,
        )

    @strawberry.field
    async def image_sources(
        self,
        info: strawberry.types.Info,
        cursor: Optional[str] = None,
        limit: int = 50,
    ) -> ImageSourcesResponse:
        ctx, asset_ids = await unpack_ctx(info)
        return await _image_sources(
            asset_ids=asset_ids,
            info_context=ctx,
            cursor=cursor,
            limit=limit,
        )

    @strawberry.field
    async def source(
        self,
        info: strawberry.types.Info,
        asset_id: strawberry.ID,
    ) -> Optional[SourceDetail]:
        ctx, asset_ids = await unpack_ctx(info)
        return await _source(
            asset_id=str(asset_id),
            asset_ids=asset_ids,
            info_context=ctx,
        )

    @strawberry.field
    async def scan_runs(
        self,
        info: strawberry.types.Info,
        tool: str,
        limit: int = 10,
    ) -> list[ScanRun]:
        ctx, _ = await unpack_ctx(info)
        return await _scan_runs(tool=tool, limit=limit, info_context=ctx)

    @strawberry.field
    async def connection_scan_runs(
        self,
        info: strawberry.types.Info,
        connection_id: str,
        limit: int = 50,
    ) -> list[ConnectionScanRun]:
        ctx, _ = await unpack_ctx(info)
        return await _connection_scan_runs(
            connection_id=connection_id, limit=limit, info_context=ctx
        )


@strawberry.type
class SlaQuery:
    @strawberry.field
    async def breach_summary(self, info: strawberry.types.Info, org: Optional[str] = None) -> BreachSummary:
        ctx, asset_ids = await unpack_ctx(info)
        if not asset_ids:
            from src.graphql.types import SeverityBreachStat
            zero = SeverityBreachStat(open=0, breached=0, breached_pct=0.0)
            return BreachSummary(critical=zero, high=zero, medium=zero, low=zero)
        return sla_breach_summary(asset_ids=asset_ids, info_context=ctx)

    @strawberry.field
    async def epss_top(self, info: strawberry.types.Info, org: Optional[str] = None, limit: int = 20) -> EpssTopResponse:
        ctx, asset_ids = await unpack_ctx(info)
        if not asset_ids:
            return EpssTopResponse(findings=[], count=0)
        return epss_top(asset_ids=asset_ids, limit=limit, info_context=ctx)


@strawberry.type
class WorkspaceQuery:
    @strawberry.field
    async def teams(self, info: strawberry.types.Info) -> list[WorkspaceTeam]:
        ctx = await get_workspace_context(info.context["request"])
        return _teams(info_context=ctx)

    @strawberry.field
    async def user_directory(self, info: strawberry.types.Info) -> list[WorkspaceUserDirectoryEntry]:
        ctx = await get_workspace_context(info.context["request"])
        return _user_directory(info_context=ctx)


@strawberry.type
class RunnersQuery:
    @strawberry.field
    async def items(self, info: strawberry.types.Info) -> RunnersListResult:
        ctx = await get_workspace_context(info.context["request"])
        return _runners(info_context=ctx)

    @strawberry.field
    async def runner(
        self,
        info: strawberry.types.Info,
        runner_id: str,
    ) -> Optional[RunnerDetailResult]:
        ctx = await get_workspace_context(info.context["request"])
        return _runner(runner_id=runner_id, info_context=ctx)

    @strawberry.field
    async def heartbeats(
        self,
        info: strawberry.types.Info,
        runner_id: str,
    ) -> list[HeartbeatEntryGQL]:
        ctx = await get_workspace_context(info.context["request"])
        return _runner_heartbeats(runner_id=runner_id, info_context=ctx)


@strawberry.type
class HistoryQuery:
    @strawberry.field
    async def events(
        self,
        info: strawberry.types.Info,
        types: Optional[list[str]] = None,
        repo_id: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> HistoryConnection:
        ctx, _ = await unpack_ctx(info)
        return _history(
            types=types,
            repo_id=repo_id,
            since=since,
            until=until,
            limit=limit,
            cursor=cursor,
            info_context=ctx,
        )

    @strawberry.field
    async def types(self, info: strawberry.types.Info) -> list[str]:
        # Auth check still enforced so unauth callers can't enumerate the
        # supported-types list as a side channel.
        await unpack_ctx(info)
        return _history_types()


@strawberry.type
class SettingsQuery:
    @strawberry.field
    async def integrations_catalog(
        self, info: strawberry.types.Info,
    ) -> IntegrationsCatalog:
        from src.authz.enforcement import has_permission
        from src.authz.permissions.catalog import VIEW_SETTINGS
        await unpack_ctx(info)
        request = info.context["request"]
        if not has_permission(request, VIEW_SETTINGS):
            raise_permission_denied("Permission denied: view_settings")
        return _integrations_catalog()

    @strawberry.field
    async def auth_security(
        self, info: strawberry.types.Info,
    ) -> AuthSecuritySettings:
        ctx = await get_workspace_context(info.context["request"])
        return _auth_security_settings(info_context=ctx)

    @strawberry.field
    async def sso(self, info: strawberry.types.Info) -> SsoSettings:
        ctx = await get_workspace_context(info.context["request"])
        return _sso_settings(info_context=ctx)

    @strawberry.field
    async def scim(self, info: strawberry.types.Info) -> ScimSettings:
        ctx = await get_workspace_context(info.context["request"])
        return _scim_settings(info_context=ctx)

    @strawberry.field
    async def saved_views(
        self,
        info: strawberry.types.Info,
        surface: str,
    ) -> list[SavedView]:
        ctx, _ = await unpack_ctx(info)
        return _saved_views(info_context=ctx, surface=surface)

    @strawberry.field
    async def webhook_endpoints(
        self, info: strawberry.types.Info,
    ) -> WebhookEndpointListResponse:
        from src.authz.enforcement import has_permission
        from src.authz.permissions.catalog import MANAGE_SETTINGS
        await unpack_ctx(info)
        request = info.context["request"]
        if not has_permission(request, MANAGE_SETTINGS):
            raise_permission_denied("Permission denied: manage_settings")
        return _webhook_endpoints()


@strawberry.type
class NotificationsQuery:
    @strawberry.field
    async def destinations(
        self, info: strawberry.types.Info,
    ) -> list[NotificationDestination]:
        from src.authz.enforcement import has_permission
        from src.authz.permissions.catalog import MANAGE_SETTINGS
        await unpack_ctx(info)
        request = info.context["request"]
        if not has_permission(request, MANAGE_SETTINGS):
            raise_permission_denied("Permission denied: manage_settings")
        return _notification_destinations()

    @strawberry.field
    async def deliveries(
        self, info: strawberry.types.Info,
        destination_id: int,
        limit: int = 50,
    ) -> list[NotificationDelivery]:
        from src.authz.enforcement import has_permission
        from src.authz.permissions.catalog import MANAGE_SETTINGS
        await unpack_ctx(info)
        request = info.context["request"]
        if not has_permission(request, MANAGE_SETTINGS):
            raise_permission_denied("Permission denied: manage_settings")
        return _notification_deliveries(destination_id=destination_id, limit=limit)

    @strawberry.field
    async def rules(
        self, info: strawberry.types.Info,
    ) -> list[NotificationRule]:
        from src.authz.enforcement import has_permission
        from src.authz.permissions.catalog import MANAGE_SETTINGS
        await unpack_ctx(info)
        request = info.context["request"]
        if not has_permission(request, MANAGE_SETTINGS):
            raise_permission_denied("Permission denied: manage_settings")
        return _notification_rules()

    @strawberry.field
    async def inbox(
        self, info: strawberry.types.Info,
        unread_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> NotificationsInbox:
        await unpack_ctx(info)
        user_id = getattr(info.context["request"].state, "user_sub", "")
        if not user_id:
            raise_permission_denied("Unauthenticated")
        return _notifications_inbox(
            user_id=user_id, unread_only=unread_only,
            limit=limit, offset=offset,
        )

    @strawberry.field
    async def unread_count(
        self, info: strawberry.types.Info,
    ) -> int:
        await unpack_ctx(info)
        user_id = getattr(info.context["request"].state, "user_sub", "")
        if not user_id:
            raise_permission_denied("Unauthenticated")
        return _notifications_unread_count(user_id=user_id)


# ============================================================
# Root Query — namespace routers only
#
# There is no root Mutation. Every write moved to REST so HTTP-level audit,
# CSRF and rate-limit hooks apply uniformly. Add a Mutation root only when a
# multi-resource write genuinely benefits from GraphQL's single-round-trip
# composition — single-row PATCH/PUT/POST belongs on REST.
# ============================================================

@strawberry.type
class Query:
    @strawberry.field
    def scans(self) -> ScansQuery:
        return ScansQuery()

    @strawberry.field
    def findings(self) -> FindingsQuery:
        return FindingsQuery()

    @strawberry.field
    def sbom(self) -> SbomQuery:
        return SbomQuery()

    @strawberry.field
    def posture(self) -> PostureQuery:
        return PostureQuery()

    @strawberry.field
    def sources(self) -> SourcesQuery:
        return SourcesQuery()

    @strawberry.field
    def sla(self) -> SlaQuery:
        return SlaQuery()

    @strawberry.field
    def workspace(self) -> WorkspaceQuery:
        return WorkspaceQuery()

    @strawberry.field
    def runners(self) -> RunnersQuery:
        return RunnersQuery()

    @strawberry.field
    def history(self) -> HistoryQuery:
        return HistoryQuery()

    @strawberry.field
    def settings(self) -> SettingsQuery:
        return SettingsQuery()

    @strawberry.field
    def notifications(self) -> NotificationsQuery:
        return NotificationsQuery()


def create_graphql_router() -> GraphQLRouter:
    """Create the Strawberry FastAPI router with security extensions."""
    is_dev = os.getenv("ENABLE_BACKEND_DOCS", "").lower() == "true"

    schema_instance = strawberry.Schema(
        query=Query,
        extensions=[
            DepthLimitExtension,
            AliasLimitExtension,
            IntrospectionBlocker,
            OperationNameRequiredExtension,
            QueryTimeoutExtension,
            ErrorMaskingExtension,  # MUST be last so it sees others' errors
        ],
        config=StrawberryConfig(
            disable_field_suggestions=not is_dev,
        ),
    )

    return GraphQLRouter(
        schema_instance,
        path="/graphql",
        graphql_ide="graphiql" if is_dev else None,
        allow_queries_via_get=False,
        multipart_uploads_enabled=False,
    )
