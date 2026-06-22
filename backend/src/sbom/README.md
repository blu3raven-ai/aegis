# `src.sbom` — bounded-context layout

Every SBOM-related surface lives under this tree: the REST router that
serves exports and downloads, the GraphQL resolver, the exporter, the
diff, and the MinIO storage primitives.

## Layout

```
src/sbom/
├── router.py             /api/v1/sboms/* REST endpoints (export, repo,
│                         image, download) — tag "sboms"
├── exporter.py           CycloneDX/SPDX format renderer
├── diff.py               SBOM-to-SBOM diff computation
├── storage.py            MinIO bucket helpers and component indexer
└── resolvers.py          GraphQL resolver for the `sbom` namespace
                          (added in the GraphQL consolidation PR)
```

## URL surface

The REST surface lives at `/api/v1/sboms/*` (plural, matching REST
resource-collection convention). All four endpoints share the single
tag `sboms`.

- `GET /api/v1/sboms/download?org=&repo=` — query-param download for the
  frontend Export button
- `GET /api/v1/sboms/export?repo=…&format=…` — flexible-params export
- `GET /api/v1/sboms/repo/{repo_id:path}` — export by repo path-segment
- `GET /api/v1/sboms/image/{image_digest:path}` — export by image digest

## Scanner-side stores live with their scanners

`containers/sbom_store.py` and `dependencies/sbom_store.py` stay in their
scanner packages. They are write-side ingest paths owned by each
scanner; `sbom/` consumes them at read time. Moving them here would
couple the read surface to scanner-specific DB-row shapes, and the
"files that change together live together" principle says the row
shape and the writer belong in the same package.

## Dependency direction

```
sbom/ ──→ containers/, dependencies/, db/, shared/, license/, authz/   ✓ allowed
containers/    ──→ sbom/                                                ✗ forbidden
dependencies/  ──→ sbom/                                                ✗ forbidden
db/            ──→ sbom/                                                ✗ forbidden
graphql/       ──→ sbom/                                                ✓ allowed
                                                                        (schema.py
                                                                        imports the
                                                                        moved resolver)
```

- Scanner packages own their own data layer; `sbom/` consumes it.
- `db/models.py` defines `Sbom`, `SbomComponent`; `sbom/` reads via
  SQLAlchemy. Models never import `sbom`.

## Data models stay in `db/`

`Sbom`, `SbomComponent`, `ContainerSbom`, `DependencySbom`, and the
related SBOM-history tables live in `db/models.py`. Only the access
code lives here.
