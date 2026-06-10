"""
PhishGuard AI — Event Bus (AICOS Compatible)

Lightweight event emitter for billing events.  AICOS consumers
can subscribe to these events via the event registry.
"""
import logging
from typing import Any

logger = logging.getLogger(__name__)

_event_handlers: dict = {}


def on(event: str, handler):
    """Register a handler for an event."""
    _event_handlers.setdefault(event, []).append(handler)


def emit(event: str, username: str = "", metadata: dict = None):
    """Emit an event to all registered handlers."""
    if metadata is None:
        metadata = {}
    for handler in _event_handlers.get(event, []):
        try:
            handler(event=event, username=username, metadata=metadata)
        except Exception as e:
            logger.debug("events: Handler for %s failed: %s", event, e)
