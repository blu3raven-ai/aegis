# Integrating Argus

Argus ships the *brain*: a complete dependency→advisory matching engine plus the
LLM verification/correlation services. An integrator supplies two things — the
**premium data feed** and the **auth configuration** — and connects over HTTP.
Nothing in the engine needs to change.

```
your premium feed ──▶ argus.feed ──▶ match store ──▶ matcher ──▶ /v1/match
                                                   (univers version semantics)
```

## 1. Endpoints

All are `POST`, bearer-authenticated, JSON in/out.

| Endpoint | Purpose |
|---|---|
| `/v1/match` | Match SBOM components against the premium advisory feed. |
| `/v1/verify` | LLM verification of a finding (SAST / IaC / secrets). |
| `/v1/correlate` | Cross-scanner correlation (toxic-combination chains). |
| `/health` | Liveness. |

## 2. Models

### Request — `MatchComponent` (`argus/models.py`)
```jsonc
{
  "purl": "pkg:pypi/django@4.2.0",   // minimum: purl + version
  "version": "4.2.0",
  "name": "django",                  // optional — send for an exact match
  "ecosystem": "PyPI"                // optional — OSV ecosystem name
}
```
`purl` + `version` is the minimum; Argus derives the ecosystem and canonical
package name from the purl. If you already hold the canonical coordinate (most
SBOM tooling does), also send `name` and `ecosystem` — they take precedence and
skip purl parsing.

Request body: `{ "surface": "deps", "components": [ MatchComponent, ... ] }`.

### Response — `MatchItem`
```jsonc
{
  "package": { "name": "django", "ecosystem": "PyPI" },
  "version": "4.2.0",
  "advisory": {                      // the public advisory payload
    "id": "GHSA-...", "cve_id": "CVE-...", "severity": "high",
    "cvss_score": 7.5, "vulnerable_version_range": ">=4.0,<4.2.1",
    "first_patched_version": "4.2.1", "...": "..."
  },
  "intel": {                         // the PREMIUM delta — the moat
    "exploit_maturity": "in_the_wild|poc|none",
    "affected_functions": ["..."],
    "package_reputation": "...",
    "epss_score": 0.42, "epss_provenance": "...",
    "kev_listed": true,
    "aliases": ["CVE-...", "GHSA-..."],
    "source": "...", "last_synced": "..."
  }
}
```
Response body: `{ "matches": [ MatchItem, ... ] }`. The existing `advisory`
fields mirror the free OSV match; `intel` is additive — free consumers ignore
it, premium consumers prioritise on it.

### Feed record — `PremiumAdvisoryRecord` (`argus/matching/models.py`)
What your feed produces; see `argus/matching/sample_advisories.json`.
```jsonc
{
  "ecosystem": "PyPI",               // OSV ecosystem name
  "package": "django",               // canonical package name
  "advisory": { "id": "GHSA-...", "...": "..." },     // -> MatchAdvisory
  "ranges": [ { "introduced": "4.0", "fixed": "4.2.1", "last_affected": null } ],
  "intel": { "exploit_maturity": "poc", "...": "..." }  // -> PremiumIntel
}
```
Versions in `ranges` follow OSV half-open semantics and are compared with the
ecosystem's real scheme (`univers`): a component is affected when
`version >= introduced` and (when set) `version < fixed` and
`version <= last_affected`.

## 3. Integration steps

1. **Supply the premium data.** Implement a `PremiumFeedSource`
   (`argus/feed/sources.py`) whose `fetch()` returns `PremiumAdvisoryRecord`s
   from your intel pipeline, and return it from `default_feed_source()`
   (`argus/feed/refresh.py`) — the single swap point. Until you do, the default
   source is empty and `/v1/match` returns no hits (the free OSV match is
   unaffected). For local trials, `JsonFileFeedSource` loads a static file.

   *Keep it fresh.* Schedule `run_refresh` (`argus/feed/refresh.py`) on an
   interval — it pulls only what changed since the last cursor (`RefreshState`)
   and upserts into the store. Persist the returned `RefreshState` between runs
   and point the refresh at the same backing store `load_premium_store` reads, so
   a refresh is immediately visible to `/v1/match`. Freshness is the moat.

2. **Configure auth.** Set `ARGUS_OIDC_ISSUER` (and optionally
   `ARGUS_OIDC_AUDIENCE` / `ARGUS_OIDC_JWKS_URI`) to verify real signed tokens
   against your IdP's JWKS. The token's org claim is the tenant boundary. With
   no issuer set, the dev verifier accepts a shared `ARGUS_TOKEN` (never use in
   production).

   *Optional — gate premium behind a paid tier.* Auth decides *who* a caller is;
   **entitlement** (`argus/matching/entitlement.py`) decides *whether* that org's
   subscription covers premium results. The default entitles every authenticated
   org. Return a subscription-backed checker from `default_entitlement_checker`
   to gate it — an unentitled org transparently gets an empty premium response
   (it falls back to the free OSV match), never an error.

3. **Configure the LLM** (for `/v1/verify` and `/v1/correlate`): `LLM_API_KEY`,
   `LLM_API_BASE_URL`, `LLM_API_MODEL`.

4. **Deploy.** `uvicorn argus.service:app` (deps in `argus/requirements.txt`).

5. **Connect from the client.** The Aegis backend stores an `ArgusConnection`
   (endpoint, `token_endpoint`, `client_id`, refresh token); it mints a
   short-lived access token per scan and ships it to the runner, which calls the
   endpoints above. No code change on the Aegis side beyond configuring the
   connection.
