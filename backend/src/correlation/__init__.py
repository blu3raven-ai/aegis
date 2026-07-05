"""Correlation engine — Phase 3a.

Subscribes to the durable event bus and runs deterministic rules that turn
raw findings + intel events into derived chain findings and chain edges.

The engine ships dormant: CorrelationEngine.start() is callable but nothing
in the production app startup calls it yet. Wiring it in is gated by an env
var and is a follow-up "flip the switch" step.
"""
