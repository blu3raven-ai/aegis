# FastAPI Backend

This FastAPI service provides the backend API for the Security Portal.

## Architecture

The Next.js frontend proxies the FastAPI-owned product routes via rewrites in `next.config.ts`.

## API Styles

The backend exposes two API styles. Both speak HTTP + JSON, but they answer different shapes of question.

| | REST | GraphQL |
|---|---|---|
| **URL** | One per resource: `/api/v1/findings`, `/api/v1/scans`, `/api/v1/users` | One endpoint: `/api/v1/graphql` |
| **HTTP method** | `POST` create, `GET` read, `PUT` update, `DELETE` delete | All operations are POST; intent lives in the body (`query` vs `mutation`) |
| **Request body** | Resource payload | `{"query": "...", "variables": {...}, "operationName": "..."}` |
| **Response shape** | Fixed by the endpoint | Exactly the fields the client asked for |
| **Status codes** | HTTP status carries meaning (404, 401, 422) | Almost always `200`; failures live in `errors[]` with `extensions.code` (e.g. `UNAUTHENTICATED`, `DEPTH_LIMIT_EXCEEDED`) |
| **Discovery** | OpenAPI at `/openapi.json`, Swagger UI at `/docs` | Introspection at runtime, GraphiQL at `/api/v1/graphql` |
| **Versioning** | URL-versioned (`/v1`) | Single evolving schema with `@deprecated` |
| **Caching** | HTTP cache + CDN friendly | Harder — every POST body differs |

Both `/docs` (Swagger) and `/api/v1/graphql` (GraphiQL) are gated behind `ENABLE_BACKEND_DOCS=true` — disabled in production.

### When to use which

**Use REST for:**
- State-changing actions — create a scan, dismiss a finding, invite a user, rotate a key
- Single-resource CRUD — fetch/update one user, one runner config
- Webhooks and external callers — third parties don't speak GraphQL
- File upload / download / streaming (multipart, SSE)
- Auth flows — login, logout, CSRF, session cookies
- Cacheable reads with stable URLs

**Use GraphQL for:**
- Dashboard and list views that join across scanners (findings + repo + last scan status + asset count) in one round-trip
- Tables with user-controlled columns and filters — client picks fields, server doesn't over-fetch
- Nested drill-downs — `finding → repository → owner → policy violations` in one query instead of 4 sequential REST calls
- Read views where the frontend iterates fast — adding a column doesn't need a backend endpoint change

**Default:** if you can answer it with one SQL query and one endpoint, it's REST. If the frontend would otherwise call 3 endpoints and stitch the results, it's GraphQL. Writes default to REST so HTTP-level audit, CSRF, and rate-limit hooks apply uniformly.

### GraphQL schema layout

- `backend/src/graphql/schema.py` — root `Query` (72 fields) and `Mutation` (34 fields)
- `backend/src/graphql/*_resolvers.py` — per-scanner resolver modules
- `backend/src/graphql/resolver_utils.py` — shared helpers (pagination, age/CVSS bucketing, search, org filter, error raises)
- `backend/src/graphql/extensions.py` — depth limit (5), alias limit (10), introspection block, query timeout, error masking. Depth, alias, and introspection checks are skipped when `ENABLE_BACKEND_DOCS=true` so GraphiQL can introspect the schema.

## Development

Run the full stack (from repo root):

```bash
npm run dev:all
```

Or run services separately:

```bash
# Terminal 1: Backend
cd backend && uvicorn src.main:app --reload --port 8000

# Terminal 2: Frontend
npm run dev
```

The service reads the existing repo-local `data/` layout from the repository root.
