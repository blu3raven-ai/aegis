"""Canonical permission catalog. All authorization decisions reference these
constants - never raw strings. A typo at the call site is now an ImportError,
not a silent deny.
"""

# View permissions
VIEW_SETTINGS = "view_settings"
VIEW_FINDINGS = "view_findings"
VIEW_DASHBOARDS = "view_dashboards"
VIEW_SOURCES = "view_sources"
VIEW_ROLES = "view_roles"
VIEW_RULES = "view_rules"
VIEW_USERS = "view_users"

# Management permissions (static)
MANAGE_SETTINGS = "manage_settings"
MANAGE_ORGANISATIONS = "manage_organisations"
MANAGE_USERS = "manage_users"
MANAGE_ROLES = "manage_roles"
MANAGE_SOURCES = "manage_sources"
MANAGE_ACCESS_SCOPE = "manage_access_scope"
MANAGE_RUNNERS = "manage_runners"

# Scan operations
RUN_SCANS = "run_scans"
CANCEL_SCANS = "cancel_scans"

# Finding lifecycle
REVIEW_FINDINGS = "review_findings"
# Disclosing a finding's raw secret value is more sensitive than triage, so it
# is its own permission — triage access (review_findings) does NOT imply it.
REVEAL_SECRET = "reveal_secret"

# Rule-category management (dynamic - selected by rule category at runtime)
MANAGE_SLA_RULES = "manage_sla_rules"
MANAGE_SCANNER_COVERAGE_RULES = "manage_scanner_coverage_rules"
MANAGE_AUTO_DISMISS_RULES = "manage_auto_dismiss_rules"
MANAGE_DATA_RETENTION_RULES = "manage_data_retention_rules"

# NEW in v0.4.6 - Stream C uses this to replace inline `role == "owner"` checks
MANAGE_OWNER_ROLE = "manage_owner_role"

# Dynamic dispatch helper - moved from rules/router.py
MANAGE_PERMISSION_BY_RULE_CATEGORY = {
    "sla": MANAGE_SLA_RULES,
    "scanner_coverage": MANAGE_SCANNER_COVERAGE_RULES,
    "auto_dismiss": MANAGE_AUTO_DISMISS_RULES,
    "data_retention": MANAGE_DATA_RETENTION_RULES,
}

ALL_PERMISSIONS = frozenset({
    VIEW_SETTINGS, VIEW_FINDINGS, VIEW_DASHBOARDS, VIEW_SOURCES, VIEW_ROLES, VIEW_RULES,
    VIEW_USERS,
    MANAGE_SETTINGS, MANAGE_ORGANISATIONS, MANAGE_USERS, MANAGE_ROLES, MANAGE_SOURCES,
    MANAGE_ACCESS_SCOPE, MANAGE_RUNNERS,
    RUN_SCANS, CANCEL_SCANS,
    REVIEW_FINDINGS, REVEAL_SECRET,
    MANAGE_SLA_RULES, MANAGE_SCANNER_COVERAGE_RULES, MANAGE_AUTO_DISMISS_RULES,
    MANAGE_DATA_RETENTION_RULES,
    MANAGE_OWNER_ROLE,
})
