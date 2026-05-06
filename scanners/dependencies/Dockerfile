FROM debian:bookworm-slim

LABEL "io.aegis.security.dependencies-scanner.signature"="aegis-dependencies-scanner"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq parallel python3 python3-pip pipx \
    && rm -rf /var/lib/apt/lists/*

# Install Syft
ARG SYFT_VERSION=1.24.0
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
    sh -s -- -b /usr/local/bin v${SYFT_VERSION}

# Install Grype (SBOM matching)
ARG GRYPE_VERSION=0.92.0
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
    sh -s -- -b /usr/local/bin v${GRYPE_VERSION}

# Install grype-db (custom advisory DB builder)
ARG GRYPE_DB_VERSION=0.53.3
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype-db/main/install.sh | \
    sh -s -- -b /usr/local/bin v${GRYPE_DB_VERSION}

# Install vunnel (advisory data fetcher) — pip3 instead of pipx so binary lands in PATH for UID 1000
RUN pip3 install --break-system-packages --no-cache-dir vunnel

# boto3 for MinIO access (advisories_only mode downloads SBOMs)
RUN pip3 install --break-system-packages --no-cache-dir boto3

# Node.js 22.x runtime for cdxgen (requires >=20)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# cdxgen — CycloneDX SBOM generator (resolves transitive dependency tree)
# npm auto-installs correct platform-specific plugin binaries for amd64/arm64
ARG CDXGEN_VERSION=12.3.0
RUN npm install -g @cyclonedx/cdxgen@${CDXGEN_VERSION} && \
    npm cache clean --force && \
    rm -rf /tmp/* /root/.npm

# CycloneDX CLI for merging SBOMs (arch-aware download)
ARG CDXCLI_VERSION=0.27.1
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then CDX_ARCH="linux-arm64"; else CDX_ARCH="linux-x64"; fi && \
    curl -fsSL "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v${CDXCLI_VERSION}/cyclonedx-${CDX_ARCH}" \
    -o /usr/local/bin/cyclonedx && chmod +x /usr/local/bin/cyclonedx

# Create scanner user (UID 1000) for shared volume security
RUN groupadd -g 1000 scanner && useradd -u 1000 -g 1000 -m scanner
RUN mkdir -p /home/scanner/.cache/grype && chown -R 1000:1000 /home/scanner/.cache

WORKDIR /scanner
COPY dependencies/run.sh /scanner/
COPY dependencies/scripts/ /scanner/scripts/
COPY shared/manifest.py /scanner/manifest.py
COPY shared/lib.sh /scanner/shared/lib.sh
RUN chmod +x /scanner/run.sh /scanner/scripts/*.sh
RUN chown -R 1000:1000 /scanner

USER 1000

ENTRYPOINT ["/scanner/run.sh"]
