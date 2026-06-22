"""GraphQL resolvers for the workspace surface.

Only two read fields are exposed via GQL — ``workspace.teams`` and
``workspace.userDirectory``. Every write and all the other reads moved to
REST under /api/v1/workspace/* (see the ``*_router.py`` siblings in this
package). The shared business logic lives in ``service.py``; this module is
a thin re-export so ``src.graphql.schema`` can wire the GQL fields without
reaching into the bounded context's service layer directly.
"""
from src.auth.workspace.service import (
    WorkspaceTeam,
    WorkspaceTeamAsset,
    WorkspaceTeamMember,
    WorkspaceUserDirectoryEntry,
    teams,
    user_directory,
)

__all__ = [
    "WorkspaceTeam",
    "WorkspaceTeamAsset",
    "WorkspaceTeamMember",
    "WorkspaceUserDirectoryEntry",
    "teams",
    "user_directory",
]
