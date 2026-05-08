REGISTRY ?= ghcr.io
OWNER ?= u9u-p
REPOSITORY ?= security
IMAGE_NAME ?= code-scanning-scanner
TAG ?= v2.0.0

IMAGE_REF ?= $(REGISTRY)/$(OWNER)/$(REPOSITORY)/$(IMAGE_NAME):$(TAG)
LATEST_REF ?= $(REGISTRY)/$(OWNER)/$(REPOSITORY)/$(IMAGE_NAME):latest

.PHONY: help build push tag version clean

help:
	@echo "Code Scanning Scanner - Simple GHCR Push Makefile"
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
	@echo "  OWNER              - GitHub username/org (default: $$USER)"
	@echo "  REPOSITORY         - Repository name (default: directory name)"
	@echo "  IMAGE_NAME         - Image name (default: code-scanning-scanner)"
	@echo "  VERSION            - Image version (default: dev)"
	@echo "  TAG                - Image tag (default: same as VERSION)"

build:
	@echo "Building Docker image: $(IMAGE_REF) and $(LATEST_REF)"
	docker build -t $(IMAGE_REF) -t $(LATEST_REF) .
	@echo "Build complete. Image tagged as: $(IMAGE_REF) and $(LATEST_REF)"

push: build
	@echo "Pushing Docker image to GHCR..."
	@if [ -z "$$GHCR_TOKEN" ]; then \
		echo "Error: GHCR_TOKEN environment variable not set"; \
		echo "Please set it with:"; \
		echo "  export GHCR_TOKEN=ghp_your_github_token_here"; \
		exit 1; \
	fi
	@echo "$$GHCR_TOKEN" | docker login ghcr.io -u "$(shell echo $$GHCR_TOKEN | cut -d':' -f1)" --password-stdin
	docker push $(IMAGE_REF)
	docker push $(LATEST_REF)
	@echo "Push complete!"

tag:
	docker tag $(IMAGE_REF) $(LATEST_REF)

version:
	@echo "IMAGE_REF: $(IMAGE_REF)"
	@echo "LATEST_REF: $(LATEST_REF)"

clean:
	@rm -rf /tmp/parallel_scan.* /tmp/trivy-cache.* 2>/dev/null || true
