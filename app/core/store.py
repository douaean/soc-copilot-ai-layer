from typing import Any, Dict, List

# Simple in-memory store for demo purposes. Not durable across process restarts.
_store: List[Dict[str, Any]] = []


def add_investigation(result: Dict[str, Any]) -> None:
    """Append a new investigation result to the in-memory store."""
    _store.insert(0, result)  # newest first


def list_investigations(limit: int = 50) -> List[Dict[str, Any]]:
    """Return the most recent investigation results."""
    return _store[:limit]
