# The trusted detonation honeypot sidecar. CI builds this and bakes it into the
# runner image as an OCI archive, which the runner `podman load`s at startup — no
# registry pull, so detonation is airgap-capable and shares the runner's signed
# provenance. When the archive is absent (a bare local build) the runner rebuilds
# it from this same file as a dev fallback. Either way it ships WITH the runner;
# nothing external is fetched at detonation time.
FROM python:3.11-slim

# iptables installs the PREROUTING REDIRECT that lands the target's outbound TCP
# on the honeypot's catch port; python runs the stdlib-only egress logger.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

# The honeypot logger is pure stdlib; the runner package is copied whole so
# `python -m runner.sandbox.honeypot` resolves. The build context is the runner
# package dir, mirroring the main runner image's own `COPY . /app/runner/`.
COPY . /app/runner/
ENV PYTHONPATH=/app
WORKDIR /app
