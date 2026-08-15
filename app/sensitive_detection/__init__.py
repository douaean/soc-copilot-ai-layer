"""
Sensitive-data detection layer.

Detector-specific output schemas (Presidio, TruffleHog) live here and never
escape into ``app.agents.state``. ``adapters`` is the boundary: it converts
raw detector findings into the normalized state models the orchestration
layer consumes.
"""
