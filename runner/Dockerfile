# syntax=docker/dockerfile:1.7

# ─── Builder stage ────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

ARG SYFT_VERSION=1.24.0
ARG CDXGEN_VERSION=12.3.0
ARG CDXCLI_VERSION=0.27.1
ARG TRUFFLEHOG_VERSION=3.95.2
ARG SEMGREP_RULES_SHA=311ca4e9ba59d700624539bf658e3d29b134ee77
ARG NODE_MAJOR=22
ARG RUNSC_RELEASE=20260714.0

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg git \
    && rm -rf /var/lib/apt/lists/*

# Node.js 22 for cdxgen (requires >=20)
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Syft — CycloneDX/SPDX SBOM generator (Anchore install script). The runner
# produces SBOMs only; vulnerability matching runs backend-side against the OSV
# mirror, so grype / grype-db are no longer installed.
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
        sh -s -- -b /usr/local/bin v${SYFT_VERSION}

# cdxgen — CycloneDX SBOM generator (arch-aware plugin binaries installed by npm)
RUN npm install -g @cyclonedx/cdxgen@${CDXGEN_VERSION} && \
    npm cache clean --force && \
    rm -rf /tmp/* /root/.npm

# CycloneDX CLI — arch-aware single binary
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then CDX_ARCH="linux-arm64"; else CDX_ARCH="linux-x64"; fi && \
    curl -fsSL "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v${CDXCLI_VERSION}/cyclonedx-${CDX_ARCH}" \
        -o /usr/local/bin/cyclonedx && chmod +x /usr/local/bin/cyclonedx

# TruffleHog — arch-aware tarball
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then TH_ARCH="arm64"; else TH_ARCH="amd64"; fi && \
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TH_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog

# gVisor runsc: daemon-free OCI runtime for the detonation tier that runs where
# nested rootless podman cannot (Docker Desktop's LinuxKit VM blocks nested
# multi-ID userns). sha512-verified from the pinned release. arch dir matches
# uname -m (aarch64 / x86_64).
RUN ARCH=$(uname -m) && \
    BASE="https://storage.googleapis.com/gvisor/releases/release/${RUNSC_RELEASE}/${ARCH}" && \
    curl -fsSL "${BASE}/runsc" -o /usr/local/bin/runsc && \
    curl -fsSL "${BASE}/runsc.sha512" -o /tmp/runsc.sha512 && \
    cd /usr/local/bin && \
    printf '%s  runsc\n' "$(awk '{print $1}' /tmp/runsc.sha512)" | sha512sum -c - && \
    chmod +x /usr/local/bin/runsc && rm -f /tmp/runsc.sha512

# semgrep-rules — pinned SHA, security subset only, .git stripped
RUN git clone --no-checkout --filter=blob:none \
        https://github.com/semgrep/semgrep-rules.git /opt/semgrep-rules && \
    cd /opt/semgrep-rules && \
    git sparse-checkout init --cone && \
    git sparse-checkout set \
        python/lang/security \
        javascript/lang/security \
        typescript/lang/security \
        java/lang/security \
        go/lang/security \
        ruby/lang/security \
        php/lang/security \
        generic && \
    git checkout "${SEMGREP_RULES_SHA}" && \
    rm -rf /opt/semgrep-rules/.git && \
    rm -f /opt/semgrep-rules/.pre-commit-config.yaml \
          /opt/semgrep-rules/metadata-schema.yaml.schm \
          /opt/semgrep-rules/template.yaml \
          /opt/semgrep-rules/Makefile \
          /opt/semgrep-rules/Pipfile \
          /opt/semgrep-rules/Pipfile.lock

# Python deps installed from the lockfile so the runtime image pins the same
# transitive graph that local `uv sync` resolves to.
RUN pip install --no-cache-dir uv==0.9.21

WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv export --frozen --no-dev --no-emit-project --output-file=/tmp/requirements.txt && \
    uv pip install --system --prefix=/install -r /tmp/requirements.txt

# ─── Detonation base rootfs stages ──────────────────────────────────────────────
# Baked, per-ecosystem base filesystems for the gVisor detonation tier. The tier
# overlays the target repo at /app and runs the setup entry directly against these
# (no nested container build), so detonation works on hosts where nested podman
# cannot build (Docker Desktop). Bases match the podman-tier detonation Dockerfiles.
FROM node:20-slim AS rootfs-npm
FROM python:3.12-slim AS rootfs-python
FROM debian:stable-slim AS rootfs-shell

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SEMGREP_RULES_PATH=/opt/semgrep-rules \
    RUNNER_WORKSPACE=/workspace

# Minimal runtime deps:
#   git        — repository clone
#   libstdc++6 — cdxgen native bits
#   libicu76   — cyclonedx-cli (.NET) globalization
#   procps     — pgrep, used by the HEALTHCHECK below
#   iptables   — the opt-in detonation honeypot uses this image as its own sidecar
#                and needs iptables to redirect the target's outbound TCP; the
#                gVisor tier also uses it (with iproute2) to pin egress inside a
#                throwaway network namespace
#   iproute2   - `ip` for the gVisor tier's per-detonation network namespace
# podman + rootless deps let the runner run the sandbox (runtime verification /
# detonation) self-contained — nested rootless containers, no host Docker socket
# to mount (that socket is host-root-equivalent, so avoiding it is a security win).
#   podman crun     — daemonless, rootless OCI runtime
#   fuse-overlayfs   — rootless overlay storage (falls back to vfs where unavailable)
#   passt/slirp4netns — rootless container networking (podman prefers pasta, from
#                       the passt package; slirp4netns kept as a fallback)
#   uidmap           — newuidmap/newgidmap for the user-namespace setup
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git libstdc++6 libicu76 procps iptables iproute2 \
        podman crun fuse-overlayfs passt slirp4netns uidmap \
    && rm -rf /var/lib/apt/lists/*

# Default the runner to its embedded podman. The code default stays "docker" for
# anyone running outside this image; here we point at the bundled rootless runtime.
ENV CONTAINER_CLI=podman

# Rootless podman in a container: cgroupfs (no systemd), and vfs storage — the most
# portable driver when /dev/fuse isn't present. A host that provides /dev/fuse can
# switch to fuse-overlayfs for speed. If the kernel blocks nested user namespaces,
# runtime_available() graceful-skips and the sandbox is simply not used.
RUN mkdir -p /etc/containers && \
    printf '[engine]\ncgroup_manager = "cgroupfs"\n[storage]\ndriver = "vfs"\n' > /etc/containers/containers.conf && \
    printf '[storage]\ndriver = "vfs"\n' > /etc/containers/storage.conf

# The detonation honeypot ships as a self-contained OCI archive baked in below
# (loaded into the embedded podman at startup, no registry pull). Enabling
# detonation then needs only RUNTIME_VERIFY=1.

# Scanner CLIs + gVisor runsc (daemon-free detonation runtime)
COPY --from=builder \
    /usr/local/bin/syft \
    /usr/local/bin/cyclonedx \
    /usr/local/bin/trufflehog \
    /usr/local/bin/runsc \
    /usr/local/bin/

# Semgrep rules bundle
COPY --from=builder /opt/semgrep-rules /opt/semgrep-rules

# Baked detonation base rootfs, keyed by ecosystem (see runner/sandbox/gvisor.py).
COPY --from=rootfs-npm / /opt/aegis-rootfs/npm/
COPY --from=rootfs-python / /opt/aegis-rootfs/python/
COPY --from=rootfs-shell / /opt/aegis-rootfs/shell/

# Node.js runtime for cdxgen
COPY --from=builder /usr/bin/node /usr/bin/node
COPY --from=builder /usr/lib/node_modules /usr/lib/node_modules
RUN ln -s /usr/lib/node_modules/@cyclonedx/cdxgen/bin/cdxgen.js /usr/local/bin/cdxgen

# Python deps from builder prefix
COPY --from=builder /install /usr/local


# Application code (build context is the runner/ directory; mounted as /app/runner)
WORKDIR /app
COPY . /app/runner/

# Baked honeypot OCI archive: CI writes runner/.honeypot/image.tar before the
# build, so the runner loads the honeypot at startup with no registry pull
# (airgap-capable). A committed .keep keeps the dir present for bare local builds
# where the archive is absent — there the runner rebuilds the honeypot at runtime.
COPY .honeypot/ /opt/aegis-honeypot/

# Non-root user. The subuid/subgid ranges are what rootless podman maps into a
# nested container's user namespace — without them it cannot start one.
RUN useradd --create-home --shell /bin/bash --uid 10001 aegis && \
    mkdir -p /workspace /home/aegis/.vuln-runner && \
    echo "aegis:100000:65536" > /etc/subuid && \
    echo "aegis:100000:65536" > /etc/subgid && \
    chown -R aegis:aegis /app /workspace /home/aegis

# Shrink the privilege-escalation surface: strip setuid from every binary except
# newuidmap/newgidmap, which rootless podman needs setuid to map the nested
# container's user namespace.
RUN find / -xdev -perm -4000 -type f ! -name newuidmap ! -name newgidmap \
        -exec chmod u-s {} + 2>/dev/null || true

USER aegis

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD pgrep -f "runner.agent" > /dev/null || exit 1

CMD ["python", "-c", "import logging, warnings; logging.basicConfig(level=logging.INFO, format='%(message)s'); logging.getLogger('httpx').setLevel(logging.WARNING); logging.getLogger('httpcore').setLevel(logging.WARNING); logging.getLogger('urllib3.connection').setLevel(logging.ERROR); warnings.filterwarnings('ignore', message='Failed to parse headers'); from runner.agent import RunnerAgent, load_config; a = RunnerAgent(load_config()); a.start()"]
