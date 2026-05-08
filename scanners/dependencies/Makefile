REGISTRY ?= ghcr.io
OWNER ?= u9u-p
REPOSITORY ?= security
IMAGE_NAME ?= dependencies-scanner
TAG ?= v3.0.0

IMAGE_REF ?= $(REGISTRY)/$(OWNER)/$(REPOSITORY)/$(IMAGE_NAME):$(TAG)
LATEST_REF ?= $(REGISTRY)/$(OWNER)/$(REPOSITORY)/$(IMAGE_NAME):latest

.PHONY: help build push tag version test clean

help:
	@echo "Dependencies Scanner"

build:
	docker build -t $(IMAGE_REF) -t $(LATEST_REF) .

push: build
	@if [ -z "$$GHCR_TOKEN" ]; then echo "Error: GHCR_TOKEN environment variable not set"; exit 1; fi
	@echo "$$GHCR_TOKEN" | docker login ghcr.io -u "$(shell echo $$GHCR_TOKEN | cut -d':' -f1)" --password-stdin
	docker push $(IMAGE_REF)
	docker push $(LATEST_REF)

tag:
	docker tag $(IMAGE_REF) $(LATEST_REF)

version:
	@echo "IMAGE_REF: $(IMAGE_REF)"
	@echo "LATEST_REF: $(LATEST_REF)"

test:
	@bash scripts/test-smoke.sh
	@bash scripts/test-normalize.sh
	@bash scripts/test-raw-artifacts.sh
	@bash scripts/test-lifecycle.sh
	@bash scripts/test-commit-selection.sh

clean:
	@rm -rf /tmp/*syft* /tmp/*grype* /tmp/parallel_scan.* 2>/dev/null || true
