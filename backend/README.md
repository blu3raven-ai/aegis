# FastAPI Backend

This FastAPI service provides the backend API for the Security Portal.

## Architecture

- **SCA (Software Composition Analysis)**: `/sca/api/*` - Dependabot alerts, cache management
- **Secrets Scanning**: `/api/v1/secrets/*` - snapshot, lifecycle, code preview, and review updates

The Next.js frontend proxies the FastAPI-owned product routes via rewrites in `next.config.ts`.
Secrets scan start/cancel, latest run polling, and active run probing are now backend-owned in FastAPI.

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
