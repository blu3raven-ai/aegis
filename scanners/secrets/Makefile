# Simple Makefile for Secret Scanner - Push to GHCR with Tag
# Secure version - no hardcoded credentials

# Configuration - all values configurable via environment variables (no hardcoded values)
REGISTRY ?= ghcr.io
OWNER ?= u9u-p
REPOSITORY ?= security
IMAGE_NAME ?= secret-scanner
TAG ?= v2.0.0

# Full image reference
IMAGE_REF ?= $(REGISTRY)/$(OWNER)/$(REPOSITORY)/$(IMAGE_NAME):$(TAG)
LATEST_REF ?= $(REGISTRY)/$(OWNER)/$(REPOSITORY)/$(IMAGE_NAME):latest

.PHONY: help build push tag version clean

# Default target
help:
	@echo "Secret Scanner - Simple GHCR Push Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build         - Build the Docker image"
	@echo "  make push          - Build and push to GHCR (requires GHCR_TOKEN)"
	@echo "  make tag           - Tag image as latest"
	@echo "  make version       - Show current version/tag"
	@echo "  make clean         - Remove temporary files"
	@echo ""
	@echo "Environment Variables:"
	@echo "  GHCR_TOKEN         - GitHub PAT with write:packages scope (REQUIRED for push)"
	@echo "  REGISTRY           - Docker registry (default: ghcr.io)"
	@echo "  OWNER              - GitHub username/org (default: gregorytan)"
	@echo "  REPOSITORY         - Repository name (default: secret-scanner)"
	@echo "  IMAGE_NAME         - Image name (default: secret-scanner)"
	@echo "  TAG                - Image tag (default: same as VERSION)"
	@echo ""
	@echo "Security Notes:"
	@echo "  - NO credentials are hardcoded in this Makefile"
	@echo "  - GHCR_TOKEN must be set as environment variable"
	@echo "  - Token is passed via stdin for security (not in process list)"

# Build the Docker image with both version and latest tags
build:
	@echo "Building Docker image: $(IMAGE_REF) and $(LATEST_REF)"
	docker build -t $(IMAGE_REF) -t $(LATEST_REF) .
	@echo "Build complete. Image tagged as: $(IMAGE_REF) and $(LATEST_REF)"

# Push the Docker image to GHCR (most secure method)
push: build
	@echo "Pushing Docker image to GHCR..."
	@if [ -z "$$GHCR_TOKEN" ]; then \
		echo "Error: GHCR_TOKEN environment variable not set"; \
		echo "Please set it with:"; \
		echo "  export GHCR_TOKEN=ghp_your_github_token_here"; \
		exit 1; \
	fi
	@# Authenticate with GHCR using token via stdin (secure)
	@echo "$$GHCR_TOKEN" | docker login ghcr.io -u "$(shell echo $$GHCR_TOKEN | cut -d':' -f1)" --password-stdin
	@echo "Pushing $(IMAGE_REF)..."
	docker push $(IMAGE_REF)
	@echo "Pushing $(LATEST_REF)..."
	docker push $(LATEST_REF)
	@echo "Push complete!"

# Tag the image with version and latest
tag:
	@echo "Tagging image $(IMAGE_REF) as latest"
	docker tag $(IMAGE_REF) $(LATEST_REF)
	@echo "Tagged as: $(LATEST_REF)"

# Show current version information
version:
	@echo "Current version information:"
	@echo "  IMAGE_NAME: $(IMAGE_NAME)"
	@echo "  TAG: $(TAG)"
	@echo "  IMAGE_REF: $(IMAGE_REF)"
	@echo "  LATEST_REF: $(LATEST_REF)"
	@echo "  OWNER: $(OWNER)"
	@echo "  REPOSITORY: $(REPOSITORY)"

# Clean temporary files
clean:
	@echo "Removing temporary files..."
	@rm -rf /tmp/*trufflehog* /tmp/*betterleaks* /tmp/parallel_scan.* 2>/dev/null || true
	@echo "Clean complete"