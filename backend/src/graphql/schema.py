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
from src.graphql.types import SecretsOverview, SecretsFilterOptions, PostureTrendPoint, HomeAnalytics

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
    def dependencies_counts(self, info: strawberry.types.Info, org: Optional[str] = None) -> SeverityCounts:
        ctx = get_graphql_context(info.context["request"])
        if org:
            return dependencies_counts(org=org, info_context=ctx)
        # No org specified — sum across all user orgs
        from src.graphql.types import SeverityCounts as SC
        totals = SC(total=0, critical=0, high=0, medium=0, low=0)
        for user_org in ctx.get("orgs", []):
            c = dependencies_counts(org=user_org, info_context=ctx)
            totals.total += c.total
            totals.critical += c.critical
            totals.high += c.high
            totals.medium += c.medium
            totals.low += c.low
        return totals

    @strawberry.field
    def dependencies_findings(
        self,
        info: strawberry.types.Info,
        org: str,
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
        ctx = get_graphql_context(info.context["request"])
        return dependencies_findings(
            org=org, page=page, per_page=per_page,
            severity=severity, state=state,
            ecosystem=ecosystem, repository=repository, organization=organization,
            package_search=package_search, fix_availability=fix_availability,
            cvss_range=cvss_range, age_bucket=age_bucket, search=search,
            new_since_last_scan=new_since_last_scan, last_scan_date=last_scan_date,
            info_context=ctx,
        )

    @strawberry.field
    def dependencies_analytics(self, info: strawberry.types.Info, org: str) -> DependenciesAnalytics:
        ctx = get_graphql_context(info.context["request"])
        return dependencies_analytics(org=org, info_context=ctx)

    @strawberry.field
    def dependencies_filter_options(self, info: strawberry.types.Info, org: str) -> FilterOptions:
        ctx = get_graphql_context(info.context["request"])
        return dependencies_filter_options(org=org, info_context=ctx)

    @strawberry.field
    def dependencies_finding_detail(
        self,
        info: strawberry.types.Info,
        org: str,
        identity_key: str,
    ) -> Optional[DependenciesFindingDetail]:
        ctx = get_graphql_context(info.context["request"])
        return dependencies_finding_detail(org=org, identity_key=identity_key, info_context=ctx)

    @strawberry.field
    def code_scanning_counts(self, info: strawberry.types.Info, org: Optional[str] = None) -> SeverityCounts:
        ctx = get_graphql_context(info.context["request"])
        if org:
            return code_scanning_counts(org=org, info_context=ctx)
        from src.graphql.types import SeverityCounts as SC
        totals = SC(total=0, critical=0, high=0, medium=0, low=0)
        for user_org in ctx.get("orgs", []):
            c = code_scanning_counts(org=user_org, info_context=ctx)
            totals.total += c.total
            totals.critical += c.critical
            totals.high += c.high
            totals.medium += c.medium
            totals.low += c.low
        return totals

    @strawberry.field
    def code_scanning_findings(
        self,
        info: strawberry.types.Info,
        org: str,
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
        ctx = get_graphql_context(info.context["request"])
        return code_scanning_findings(
            org=org, page=page, per_page=per_page,
            severity=severity, state=state,
            language=language, reachability=reachability, confidence=confidence,
            rule_id=rule_id, repository=repository, age_bucket=age_bucket,
            search=search, new_since_last_scan=new_since_last_scan,
            last_scan_date=last_scan_date, info_context=ctx,
        )

    @strawberry.field
    def code_scanning_analytics(self, info: strawberry.types.Info, org: str) -> CodeScanningAnalytics:
        ctx = get_graphql_context(info.context["request"])
        return code_scanning_analytics(org=org, info_context=ctx)

    @strawberry.field
    def code_scanning_filter_options(self, info: strawberry.types.Info, org: str) -> CodeScanningFilterOptions:
        ctx = get_graphql_context(info.context["request"])
        return code_scanning_filter_options(org=org, info_context=ctx)

    @strawberry.field
    def container_counts(self, info: strawberry.types.Info, org: Optional[str] = None) -> SeverityCounts:
        ctx = get_graphql_context(info.context["request"])
        if org:
            return container_counts(org=org, info_context=ctx)
        from src.graphql.types import SeverityCounts as SC
        totals = SC(total=0, critical=0, high=0, medium=0, low=0)
        for user_org in ctx.get("orgs", []):
            c = container_counts(org=user_org, info_context=ctx)
            totals.total += c.total
            totals.critical += c.critical
            totals.high += c.high
            totals.medium += c.medium
            totals.low += c.low
        return totals

    @strawberry.field
    def container_findings(
        self,
        info: strawberry.types.Info,
        org: str,
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
        ctx = get_graphql_context(info.context["request"])
        return container_findings(
            org=org, page=page, per_page=per_page,
            severity=severity, state=state,
            ecosystem=ecosystem, repository=repository, organization=organization,
            package_search=package_search, fix_availability=fix_availability,
            cvss_range=cvss_range, age_bucket=age_bucket, search=search,
            new_since_last_scan=new_since_last_scan, last_scan_date=last_scan_date,
            info_context=ctx,
        )

    @strawberry.field
    def container_analytics(self, info: strawberry.types.Info, org: str) -> ContainerAnalytics:
        ctx = get_graphql_context(info.context["request"])
        return container_analytics(org=org, info_context=ctx)

    @strawberry.field
    def container_filter_options(self, info: strawberry.types.Info, org: str) -> FilterOptions:
        ctx = get_graphql_context(info.context["request"])
        return container_filter_options(org=org, info_context=ctx)

    @strawberry.field
    def secret_counts(self, info: strawberry.types.Info, org: Optional[str] = None) -> SeverityCounts:
        ctx = get_graphql_context(info.context["request"])
        if org:
            return secret_counts(org=org, info_context=ctx)
        from src.graphql.types import SeverityCounts as SC
        totals = SC(total=0, critical=0, high=0, medium=0, low=0)
        for user_org in ctx.get("orgs", []):
            c = secret_counts(org=user_org, info_context=ctx)
            totals.total += c.total
            totals.critical += c.critical
            totals.high += c.high
            totals.medium += c.medium
            totals.low += c.low
        return totals

    @strawberry.field
    def secret_findings(
        self,
        info: strawberry.types.Info,
        org: str,
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
        ctx = get_graphql_context(info.context["request"])
        return secret_findings(
            org=org, page=page, per_page=per_page,
            severity=severity, state=state,
            review_status=review_status, detector=detector,
            repository=repository, organization=organization,
            source=source, search=search,
            classification=classification, age_bucket=age_bucket,
            new_since_last_scan=new_since_last_scan, last_scan_date=last_scan_date,
            info_context=ctx,
        )

    @strawberry.field
    def secrets_overview(self, info: strawberry.types.Info, org: str) -> SecretsOverview:
        ctx = get_graphql_context(info.context["request"])
        return secrets_overview(org=org, info_context=ctx)

    @strawberry.field
    def secrets_filter_options(self, info: strawberry.types.Info, org: str) -> SecretsFilterOptions:
        ctx = get_graphql_context(info.context["request"])
        return secrets_filter_options(org=org, info_context=ctx)

    @strawberry.field
    def posture_trend(self, info: strawberry.types.Info, days: int = 30) -> list[PostureTrendPoint]:
        ctx = get_graphql_context(info.context["request"])
        return posture_trend(days=days, info_context=ctx)

    @strawberry.field
    def home_analytics(self, info: strawberry.types.Info) -> HomeAnalytics:
        ctx = get_graphql_context(info.context["request"])
        return home_analytics(info_context=ctx)

    @strawberry.field
    def sbom_search(
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
        ctx = get_graphql_context(info.context["request"])
        return sbom_search(
            search=search, ecosystems=ecosystems, source=source,
            repos=repos, version_op=version_op, version_value=version_value,
            version_value_end=version_value_end, filter_logic=filter_logic,
            page=page, per_page=per_page, info_context=ctx,
        )

    @strawberry.field
    def sbom_filter_options(self, info: strawberry.types.Info) -> SbomFilterOptions:
        ctx = get_graphql_context(info.context["request"])
        return sbom_filter_options(info_context=ctx)

    @strawberry.field
    def sbom_cross_references(self, info: strawberry.types.Info, purl: str) -> list[SbomCrossReference]:
        ctx = get_graphql_context(info.context["request"])
        return sbom_cross_references(purl=purl, info_context=ctx)

    @strawberry.field
    def sbom_bulk_lookup(self, info: strawberry.types.Info, queries: list[str]) -> list[SbomBulkMatch]:
        ctx = get_graphql_context(info.context["request"])
        return sbom_bulk_lookup(queries=queries, info_context=ctx)


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
        path="/api",
        graphql_ide="graphiql" if is_dev else None,
        allow_queries_via_get=False,
        multipart_uploads_enabled=False,
    )
