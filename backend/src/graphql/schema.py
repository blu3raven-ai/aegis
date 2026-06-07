"""Root GraphQL schema — aggregates all tool resolvers."""
from __future__ import annotations

import os
import logging
from typing import Optional

import strawberry
from strawberry.fastapi import GraphQLRouter
from strawberry.extensions import SchemaExtension
from strawberry.schema.config import StrawberryConfig
from graphql import GraphQLError

from src.graphql.auth import get_graphql_context, GraphQLAuthError
from src.graphql.limits import check_query_depth
from src.graphql.types import SeverityCounts, FilterOptions, CodeScanningFilterOptions
from src.graphql.dependencies_resolvers import (
    DependenciesAnalytics, DependenciesFindingsConnection, DependenciesFindingDetail,
    dependencies_counts, dependencies_findings, dependencies_analytics,
    dependencies_filter_options, dependencies_finding_detail,
)
from src.graphql.code_scanning_resolvers import (
    CodeScanningAnalytics, CodeScanningFindingsConnection,
    code_scanning_counts, code_scanning_findings, code_scanning_analytics, code_scanning_filter_options,
)
from src.graphql.containers_resolvers import (
    ContainerAnalytics, ContainerFindingsConnection,
    container_counts, container_findings, container_analytics, container_filter_options,
)
from src.graphql.secrets_resolvers import (
    SecretFindingsConnection,
    secret_counts, secret_findings, secrets_overview, secrets_filter_options,
)
from src.graphql.posture_resolvers import posture_trend, home_analytics
from src.graphql.sbom_resolvers import (
    SbomComponentsConnection, SbomFilterOptions, SbomCrossReference, SbomBulkMatch,
    sbom_search, sbom_filter_options, sbom_cross_references, sbom_bulk_lookup,
)
from src.graphql.sla_resolvers import sla_breach_summary
from src.graphql.epss_resolvers import epss_top
from src.graphql.sources_resolvers import source_connections
from src.graphql.types import (
    SecretsOverview, SecretsFilterOptions, PostureTrendPoint, HomeAnalytics,
    BreachSummary, EpssTopResponse, SourceConnectionsResponse,
)

logger = logging.getLogger(__name__)


class DepthLimitExtension(SchemaExtension):
    """Reject queries exceeding max nesting depth."""
    def on_operation(self):
        from src.graphql.limits import check_query_depth
        query = self.execution_context.query
        if query:
            try:
                check_query_depth(query)
            except ValueError as e:
                raise GraphQLError(str(e))
        yield


class AliasLimitExtension(SchemaExtension):
    """Reject queries with excessive field aliases."""
    MAX_ALIASES = 10

    def on_operation(self):
        doc = self.execution_context.graphql_document
        if doc:
            alias_count = self._count_aliases(doc)
            if alias_count > self.MAX_ALIASES:
                raise GraphQLError(f"Too many aliases ({alias_count}). Max {self.MAX_ALIASES}.")
        yield

    def _count_aliases(self, doc) -> int:
        count = 0
        for definition in doc.definitions:
            selections = getattr(getattr(definition, "selection_set", None), "selections", None) or []
            for selection in selections:
                if getattr(selection, "alias", None):
                    count += 1
        return count



@strawberry.type
class Query:
    @strawberry.field
    async def dependencies_counts(self, info: strawberry.types.Info, org: Optional[str] = None) -> SeverityCounts:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return dependencies_counts(asset_ids=asset_ids, info_context=ctx)

    @strawberry.field
    async def dependencies_findings(
        self,
        info: strawberry.types.Info,
        org: Optional[str] = None,
        page: int = 1,
        per_page: int = 25,
        severity: Optional[str] = None,
        state: Optional[str] = None,
        ecosystem: Optional[list[str]] = None,
        repository: Optional[str] = None,
        organization: Optional[str] = None,
        package_search: Optional[str] = None,
        fix_availability: Optional[str] = None,
        cvss_range: Optional[str] = None,
        age_bucket: Optional[str] = None,
        search: Optional[str] = None,
        new_since_last_scan: Optional[bool] = None,
        last_scan_date: Optional[str] = None,
    ) -> DependenciesFindingsConnection:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return dependencies_findings(
            asset_ids=asset_ids, org=org, page=page, per_page=per_page,
            severity=severity, state=state,
            ecosystem=ecosystem, repository=repository, organization=organization,
            package_search=package_search, fix_availability=fix_availability,
            cvss_range=cvss_range, age_bucket=age_bucket, search=search,
            new_since_last_scan=new_since_last_scan, last_scan_date=last_scan_date,
            info_context=ctx,
        )

    @strawberry.field
    async def dependencies_analytics(self, info: strawberry.types.Info, org: Optional[str] = None) -> DependenciesAnalytics:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return dependencies_analytics(asset_ids=asset_ids, org=org, info_context=ctx)

    @strawberry.field
    async def dependencies_filter_options(self, info: strawberry.types.Info, org: Optional[str] = None) -> FilterOptions:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return dependencies_filter_options(asset_ids=asset_ids, org=org, info_context=ctx)

    @strawberry.field
    async def dependencies_finding_detail(
        self,
        info: strawberry.types.Info,
        org: Optional[str] = None,
        identity_key: str = "",
    ) -> Optional[DependenciesFindingDetail]:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return dependencies_finding_detail(asset_ids=asset_ids, org=org, identity_key=identity_key, info_context=ctx)

    @strawberry.field
    async def code_scanning_counts(self, info: strawberry.types.Info, org: Optional[str] = None) -> SeverityCounts:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return code_scanning_counts(asset_ids=asset_ids, info_context=ctx)

    @strawberry.field
    async def code_scanning_findings(
        self,
        info: strawberry.types.Info,
        org: Optional[str] = None,
        page: int = 1,
        per_page: int = 25,
        severity: Optional[str] = None,
        state: Optional[str] = None,
        language: Optional[str] = None,
        reachability: Optional[str] = None,
        confidence: Optional[str] = None,
        rule_id: Optional[str] = None,
        repository: Optional[str] = None,
        age_bucket: Optional[str] = None,
        search: Optional[str] = None,
        new_since_last_scan: Optional[bool] = None,
        last_scan_date: Optional[str] = None,
    ) -> CodeScanningFindingsConnection:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return code_scanning_findings(
            asset_ids=asset_ids, org=org, page=page, per_page=per_page,
            severity=severity, state=state,
            language=language, reachability=reachability, confidence=confidence,
            rule_id=rule_id, repository=repository, age_bucket=age_bucket,
            search=search, new_since_last_scan=new_since_last_scan,
            last_scan_date=last_scan_date, info_context=ctx,
        )

    @strawberry.field
    async def code_scanning_analytics(self, info: strawberry.types.Info, org: Optional[str] = None) -> CodeScanningAnalytics:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return code_scanning_analytics(asset_ids=asset_ids, org=org, info_context=ctx)

    @strawberry.field
    async def code_scanning_filter_options(self, info: strawberry.types.Info, org: Optional[str] = None) -> CodeScanningFilterOptions:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return code_scanning_filter_options(asset_ids=asset_ids, org=org, info_context=ctx)

    @strawberry.field
    async def container_counts(self, info: strawberry.types.Info, org: Optional[str] = None) -> SeverityCounts:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return container_counts(asset_ids=asset_ids, info_context=ctx)

    @strawberry.field
    async def container_findings(
        self,
        info: strawberry.types.Info,
        org: Optional[str] = None,
        page: int = 1,
        per_page: int = 25,
        severity: Optional[str] = None,
        state: Optional[str] = None,
        ecosystem: Optional[list[str]] = None,
        repository: Optional[str] = None,
        organization: Optional[str] = None,
        package_search: Optional[str] = None,
        fix_availability: Optional[str] = None,
        cvss_range: Optional[str] = None,
        age_bucket: Optional[str] = None,
        search: Optional[str] = None,
        new_since_last_scan: Optional[bool] = None,
        last_scan_date: Optional[str] = None,
    ) -> ContainerFindingsConnection:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return container_findings(
            asset_ids=asset_ids, org=org, page=page, per_page=per_page,
            severity=severity, state=state,
            ecosystem=ecosystem, repository=repository, organization=organization,
            package_search=package_search, fix_availability=fix_availability,
            cvss_range=cvss_range, age_bucket=age_bucket, search=search,
            new_since_last_scan=new_since_last_scan, last_scan_date=last_scan_date,
            info_context=ctx,
        )

    @strawberry.field
    async def container_analytics(self, info: strawberry.types.Info, org: Optional[str] = None) -> ContainerAnalytics:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return container_analytics(asset_ids=asset_ids, org=org, info_context=ctx)

    @strawberry.field
    async def container_filter_options(self, info: strawberry.types.Info, org: Optional[str] = None) -> FilterOptions:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return container_filter_options(asset_ids=asset_ids, org=org, info_context=ctx)

    @strawberry.field
    async def secret_counts(self, info: strawberry.types.Info, org: Optional[str] = None) -> SeverityCounts:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return secret_counts(asset_ids=asset_ids, info_context=ctx)

    @strawberry.field
    async def secret_findings(
        self,
        info: strawberry.types.Info,
        org: Optional[str] = None,
        page: int = 1,
        per_page: int = 25,
        severity: Optional[str] = None,
        state: Optional[str] = None,
        review_status: Optional[str] = None,
        detector: Optional[str] = None,
        repository: Optional[str] = None,
        organization: Optional[str] = None,
        source: Optional[str] = None,
        search: Optional[str] = None,
        classification: Optional[str] = None,
        age_bucket: Optional[str] = None,
        new_since_last_scan: Optional[bool] = None,
        last_scan_date: Optional[str] = None,
    ) -> SecretFindingsConnection:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return secret_findings(
            asset_ids=asset_ids, org=org, page=page, per_page=per_page,
            severity=severity, state=state,
            review_status=review_status, detector=detector,
            repository=repository, organization=organization,
            source=source, search=search,
            classification=classification, age_bucket=age_bucket,
            new_since_last_scan=new_since_last_scan, last_scan_date=last_scan_date,
            info_context=ctx,
        )

    @strawberry.field
    async def secrets_overview(self, info: strawberry.types.Info, org: Optional[str] = None) -> SecretsOverview:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return secrets_overview(asset_ids=asset_ids, org=org, info_context=ctx)

    @strawberry.field
    async def secrets_filter_options(self, info: strawberry.types.Info, org: Optional[str] = None) -> SecretsFilterOptions:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        return secrets_filter_options(asset_ids=asset_ids, org=org, info_context=ctx)

    @strawberry.field
    async def posture_trend(self, info: strawberry.types.Info, days: int = 30) -> list[PostureTrendPoint]:
        ctx = await get_graphql_context(info.context["request"])
        return posture_trend(days=days, info_context=ctx)

    @strawberry.field
    async def home_analytics(self, info: strawberry.types.Info) -> HomeAnalytics:
        ctx = await get_graphql_context(info.context["request"])
        return home_analytics(info_context=ctx)

    @strawberry.field
    async def sbom_search(
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
        page: int = 1,
        per_page: int = 50,
    ) -> SbomComponentsConnection:
        ctx = await get_graphql_context(info.context["request"])
        return sbom_search(
            search=search, ecosystems=ecosystems, source=source,
            repos=repos, version_op=version_op, version_value=version_value,
            version_value_end=version_value_end, filter_logic=filter_logic,
            page=page, per_page=per_page, info_context=ctx,
        )

    @strawberry.field
    async def sbom_filter_options(self, info: strawberry.types.Info) -> SbomFilterOptions:
        ctx = await get_graphql_context(info.context["request"])
        return sbom_filter_options(info_context=ctx)

    @strawberry.field
    async def sbom_cross_references(self, info: strawberry.types.Info, purl: str) -> list[SbomCrossReference]:
        ctx = await get_graphql_context(info.context["request"])
        return sbom_cross_references(purl=purl, info_context=ctx)

    @strawberry.field
    async def sbom_bulk_lookup(self, info: strawberry.types.Info, queries: list[str]) -> list[SbomBulkMatch]:
        ctx = await get_graphql_context(info.context["request"])
        return sbom_bulk_lookup(queries=queries, info_context=ctx)

    @strawberry.field
    async def sla_breach_summary(self, info: strawberry.types.Info, org: Optional[str] = None) -> BreachSummary:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        if not asset_ids:
            from src.graphql.types import SeverityBreachStat
            zero = SeverityBreachStat(open=0, breached=0, breached_pct=0.0)
            return BreachSummary(critical=zero, high=zero, medium=zero, low=zero)
        return sla_breach_summary(asset_ids=asset_ids, info_context=ctx)

    @strawberry.field
    async def epss_top(self, info: strawberry.types.Info, org: Optional[str] = None, limit: int = 20) -> EpssTopResponse:
        ctx = await get_graphql_context(info.context["request"])
        asset_ids = ctx.get("asset_ids") or []
        if not asset_ids:
            return EpssTopResponse(findings=[], count=0)
        return epss_top(asset_ids=asset_ids, limit=limit, info_context=ctx)

    @strawberry.field
    async def source_connections(self, info: strawberry.types.Info, category: Optional[str] = None) -> SourceConnectionsResponse:
        ctx = await get_graphql_context(info.context["request"])
        return source_connections(info_context=ctx, category=category)


def create_graphql_router() -> GraphQLRouter:
    """Create the Strawberry FastAPI router with security extensions."""
    is_dev = os.getenv("ENABLE_BACKEND_DOCS", "").lower() == "true"

    class IntrospectionBlocker(SchemaExtension):
        """Block introspection queries in production."""
        def on_operation(self):
            query = self.execution_context.query or ""
            if not is_dev and ("__schema" in query or "__type" in query):
                raise GraphQLError("Introspection is disabled")
            yield

    schema_instance = strawberry.Schema(
        query=Query,
        extensions=[DepthLimitExtension, AliasLimitExtension, IntrospectionBlocker],
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
