"""Hardened sandbox for executing untrusted target code during runtime
verification. The runtime is pluggable (Docker floor → gVisor → Firecracker/Kata
via a --runtime flag) but the *cheap controls* — no network, no secrets, read-only
rootfs, dropped capabilities, resource caps — are mandatory on every invocation,
because they eliminate exfiltration/persistence/DoS at zero performance cost
regardless of which runtime the host supports."""
