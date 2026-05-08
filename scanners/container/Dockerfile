FROM debian:bookworm-slim

LABEL "io.aegis.security.container-scanner.signature"="aegis-container-scanner"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl jq parallel python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Syft (pinned version, separate layer for caching)
ARG SYFT_VERSION=1.24.0
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
    sh -s -- -b /usr/local/bin v${SYFT_VERSION}

# Install Grype (pinned version, separate layer for caching)
ARG GRYPE_VERSION=0.92.0
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
    sh -s -- -b /usr/local/bin v${GRYPE_VERSION}

# Scanner user (UID 1000) for shared volume security
RUN groupadd -g 1000 scanner && useradd -u 1000 -g 1000 -m scanner
RUN mkdir -p /home/scanner/.cache/grype && chown -R 1000:1000 /home/scanner/.cache

COPY container/scripts/ /scanner/scripts/
COPY container/run.sh /scanner/run.sh
COPY shared/manifest.py /scanner/manifest.py
COPY shared/lib.sh /scanner/shared/lib.sh
RUN chmod +x /scanner/run.sh /scanner/scripts/*.py /scanner/shared/lib.sh
RUN chown -R 1000:1000 /scanner

USER scanner
WORKDIR /scanner

ENTRYPOINT ["/scanner/run.sh"]
