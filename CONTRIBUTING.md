# Contributing to Aegis

Thanks for your interest in contributing. This guide covers everything you need to get started.

## Getting Started

1. Fork the repository
2. Clone your fork and set up the development environment ([docs/development.md](docs/development.md))
3. Create a feature branch from `main`
4. Make your changes
5. Run the tests
6. Open a pull request

## Branch Naming

Use descriptive prefixes:

```
feat/add-iac-scanner
fix/container-digest-check
docs/update-architecture
refactor/graphql-resolvers
```

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add EPSS score display to dependency findings
fix: prevent duplicate scan jobs when source re-syncs
docs: add runner configuration guide
refactor(graphql): extract shared filter logic
test: add contract tests for dependencies API
chore: update Grype to v0.93.0
```

Scope is optional but encouraged for targeted changes (e.g., `fix(runner):`, `feat(ui):`).

## Pull Requests

- Keep PRs focused — one feature or fix per PR
- Include a clear description of what changed and why
- Add or update tests for any behavior changes
- Ensure all tests pass before requesting review
- Link related issues with `Closes #123` or `Fixes #123`

### PR checklist

- [ ] Tests pass (`npm run test:frontend && npm run test:backend`)
- [ ] No new lint warnings
- [ ] Commit messages follow conventions
- [ ] PR description explains the change

## Code Style

### Python (backend)

- Python 3.11+
- Use type hints for function signatures
- Use `logging` module (not print)
- Follow existing patterns in `backend/src/` — routers, stores, shared utilities

### TypeScript (frontend)

- Strict TypeScript — no `any` unless unavoidable
- React functional components with hooks
- CSS variables for theming (see `app/globals.css`)
- Use existing shared components from `components/shared/`

### General

- No commented-out code in PRs
- No placeholder TODOs — if something is incomplete, open an issue instead
- Prefer editing existing files over creating new ones
- Keep changes minimal — don't refactor unrelated code in the same PR

## Testing

```bash
# Backend (pytest)
npm run test:backend

# Frontend (node:test)
npm run test:frontend

# Contract tests
npm run test:contracts

# E2E (Playwright)
npm run test:e2e
```

See [docs/development.md](docs/development.md) for details on the test setup.

## Reporting Issues

- Search existing issues first to avoid duplicates
- Use a clear, descriptive title
- Include steps to reproduce for bugs
- Include expected vs actual behavior
- Mention your environment (OS, Docker version, browser) if relevant

## Security Vulnerabilities

If you discover a security vulnerability, please report it responsibly. Do **not** open a public issue. Email security@blu3raven.com with details.

## Community

- Be respectful and constructive in all interactions
- Focus on the technical merits of contributions
- Help others learn — code review is a collaborative process
