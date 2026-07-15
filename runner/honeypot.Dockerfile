# syntax=docker/dockerfile:1.7
#
# Honeypot sidecar image for detonation mode (runner/sandbox/detonation.py).
#
# The honeypot is TRUSTED: it runs on the egress-denied `--internal` detonation
# network as the target's DNS resolver + TCP catch-all and logs every egress the
# detonated target attempts. It needs `iptables` to REDIRECT the target's outbound
# TCP to the logger's catch port, and CAP_NET_ADMIN (granted by the runner via
# `--cap-add=NET_ADMIN`) to do so.
#
# Built FROM the runner image so `python -m runner.sandbox.honeypot` and its deps
# are already present. Pass the runner image tag at build time:
#
#     docker build -f runner/honeypot.Dockerfile \
#       --build-arg RUNNER_IMAGE=<your-runner-tag> -t aegis-honeypot:latest runner/
#
# The runner references this image via HONEYPOT_IMAGE (default aegis-honeypot:latest).
# NOTE: this is a deployment artifact — build it in your runner environment and run
# the detonation smoke test (SMOKE_TEST.md) before enabling DETONATE; it is not
# exercised by unit CI.
ARG RUNNER_IMAGE=aegis-runner:latest
FROM ${RUNNER_IMAGE}

# Trusted, ephemeral, egress-denied sidecar — runs as root so iptables can install
# the redirect (paired with the NET_ADMIN cap the runner grants).
USER root

RUN apt-get update && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

# The runner supplies the command at run time (iptables REDIRECT + the logger),
# so no ENTRYPOINT/CMD override is needed here.
