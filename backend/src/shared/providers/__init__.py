"""Provider strategy registry — single dispatch point for source_type-specific behavior.

## Adding a new SCM provider

1. Add a class to `src/shared/providers/repos.py`:
   ```python
   class MySCMRepoProvider:
       source_type = "myscm"
       def clone_url(self, org: str, repo: str, instance_url: str) -> str:
           return f"{instance_url or 'https://default.myscm.com'}/{org}/{repo}.git"
   ```
2. Add it to the `for _cls in (...)` registration tuple at the bottom of `repos.py`.
3. Add parametrized cases to `tests/test_providers_repos.py`.

## Adding a new image registry

Same shape under `src/shared/providers/registries.py` and `tests/test_providers_registries.py`.

## Out of scope

This module handles *URL construction* per provider. It does NOT handle:
- Auth/token resolution (still in `shared/config.py::get_token_for_org`)
- API calls to fetch repos/orgs/teams (provider-specific clients like `shared/github.py`)
- Scanner-side discovery logic (still in per-tool scanners)

Those are intentional separate concerns — the URL-construction abstraction is
the smallest useful refactor; expanding scope would conflate it with token
management and API clients that have different lifetimes and dependencies.
"""
