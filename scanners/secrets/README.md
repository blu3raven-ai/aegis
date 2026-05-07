# GitHub Secrets Scanner

A Docker-based tool for scanning GitHub repositories for secrets using multiple scanning tools with concurrent processing support.

## Features

- **JSON Output**: Saves findings as JSON files for each repository
- **Flexible Scanning**: Can scan all commits or limit to commits from a specified start date
- **Multiple Organizations**: Can scan one or multiple GitHub organizations
- **Secure**: Uses credential helpers to avoid exposing tokens in URLs
- **Concurrent Scanning**: Scans multiple repositories in parallel for faster results (default: 4 concurrent scans)
- **Automatic Cleanup**: Removes empty result files and directories

## Usage

### Setup .env

1. Copy the example environment file and configure it:
   ```bash
   cp .env.example .env
   # Edit .env with your GitHub token and organization(s)
   ```

### Building and Running with Docker

1. Build the Docker image:
```bash
docker build -t github-secrets .
```

2. Run the container:
```bash
# Using .env file
docker run --rm --env-file .env -v "$(pwd)/output:/scanner/output" github-secrets

# Or pass environment variables directly
docker run --rm \
  -e GITHUB_TOKEN=your_token \
  -e GITHUB_ORG=organization-name \
  -v "$(pwd)/output:/scanner/output" \
  github-secrets
```

### Environment Variables

- `GITHUB_TOKEN` (required): Your GitHub personal access token with `repo` and `read:org` scopes
- `GITHUB_ORG` (required): The GitHub organization(s) to scan (comma-separated for multiple)
- `SCAN_START_DATE` (optional): Start date for scanning in YYYY-MM-DD format
- `CONCURRENCY` (optional): Number of repositories to scan in parallel (default: 4)

### Examples

```bash
# Basic scan with default concurrency (4)
docker run --rm \
  -e GITHUB_TOKEN=your_token \
  -e GITHUB_ORG=organization-name \
  -v "$(pwd)/output:/scanner/output" \
  github-secrets

# Scan multiple organizations with higher concurrency
docker run --rm \
  -e GITHUB_TOKEN=your_token \
  -e GITHUB_ORG="org1,org2,org3" \
  -e CONCURRENCY=8 \
  -v "$(pwd)/output:/scanner/output" \
  github-secrets

# Scan from a specific date with custom concurrency
docker run --rm \
  -e GITHUB_TOKEN=your_token \
  -e GITHUB_ORG="org1,org2" \
  -e SCAN_START_DATE="2024-01-01" \
  -e CONCURRENCY=6 \
  -v "$(pwd)/output:/scanner/output" \
  github-secrets
```

### Building and Pushing to GHCR

1. **Set your GitHub Personal Access Token** (with `write:packages` scope):
   ```bash
   export GHCR_TOKEN=ghp_your_actual_token_here
   ```

2. **Build and push the Docker image**:
   ```bash
   make push
   ```

#### Makefile Targets

- `make build` - Build the Docker image
- `make push` - Build and push to GHCR (requires `GHCR_TOKEN`)
- `make tag` - Tag image as `latest`
- `make version` - Show version information
- `make clean` - Remove temporary files

#### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GHCR_TOKEN` | GitHub PAT with `write:packages` scope | **Required** |
| `REGISTRY` | Docker registry | `ghcr.io` |
| `OWNER` | GitHub username/org | Current system user |
| `REPOSITORY` | Repository name | Current directory name |
| `IMAGE_NAME` | Image name | `secret-scanner` |
| `VERSION` | Image version | `dev` |
| `TAG` | Image tag | Same as `VERSION` |

#### Example

```bash
# Set credentials (never hardcode these!)
export GHCR_TOKEN=ghp_your_token_here

# Build and push (uses current user and directory name by default)
make push

# Or customize:
export OWNER=my-org
export VERSION=v1.0.0
make push
```

### Running the Scripts Directly

If you want to run the scripts directly (outside of Docker):

1. Install the required tools: TruffleHog, BetterLeaks, GitHub CLI, and GNU parallel
2. Set environment variables and run the script:
   ```bash
   export GITHUB_TOKEN=your_token
   export GITHUB_ORG=organization-name
   export CONCURRENCY=4  # Optional: set concurrency level (default: 4)
   ./run-secrets.sh
   ```

## Performance Tuning

### Concurrency Settings

- **Default**: 4 concurrent repository scans
- **Recommended for small organizations (≤20 repos)**: 2-4
- **Recommended for medium organizations (20-100 repos)**: 4-8
- **Recommended for large organizations (100+ repos)**: 8-16

Note: Higher concurrency values will scan more repositories simultaneously but use more CPU and memory resources. Adjust based on your system capabilities.

### Resource Requirements

- **Minimum**: 2 CPU cores, 2GB RAM
- **Recommended**: 4 CPU cores, 4GB RAM for CONCURRENCY=4
- **High performance**: 8+ CPU cores, 8GB+ RAM for CONCURRENCY=8+

## Troubleshooting

1. **GitHub API Rate Limits**: The script handles rate limits automatically
2. **Permission Issues**: Ensure your GitHub token has `repo` and `read:org` scopes
3. **Empty Results**: Empty JSON files are automatically removed
4. **No Commits in Specified Period**: Repositories with no commits in the specified period are skipped
5. **Concurrency Issues**:
   - If you experience high memory usage, reduce the CONCURRENCY value
   - If scans are failing randomly, try reducing CONCURRENCY to avoid overwhelming GitHub's API
   - For very large organizations, consider running scans during off-peak hours

## License

This project is licensed under the MIT License.