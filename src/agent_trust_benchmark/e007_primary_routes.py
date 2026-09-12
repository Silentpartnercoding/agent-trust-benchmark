"""Canonical E007 route registration.

The late alias intentionally lives in a different module. Keeping the two
registrations apart models the review-resistant shape frozen in docs/E007.md.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def register_primary_routes(
    app: Any,
    read_handler: Callable[..., Any],
    write_handler: Callable[..., Any],
    *,
    router_guarded: bool,
) -> None:
    app.add_route(
        "GET",
        "/documents/doc-b1",
        "documents:read",
        read_handler,
        handler_name="read_document",
        registration_module=__name__,
        router_guarded=router_guarded,
    )
    app.add_route(
        "POST",
        "/documents/doc-b1",
        "documents:write",
        write_handler,
        handler_name="write_document",
        registration_module=__name__,
        router_guarded=router_guarded,
    )
