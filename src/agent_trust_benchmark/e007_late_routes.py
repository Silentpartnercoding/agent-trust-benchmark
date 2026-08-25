"""Late E007 route registration, separate from the canonical routes."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def register_late_alias(
    app: Any,
    read_handler: Callable[..., Any],
    *,
    router_guarded: bool,
) -> None:
    app.add_route(
        "GET",
        "/legacy/documents/doc-b1",
        "documents:read",
        read_handler,
        handler_name="read_document",
        registration_module=__name__,
        router_guarded=router_guarded,
    )
