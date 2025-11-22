"""Custom decorators for RBAC."""
from __future__ import annotations

from functools import wraps
from typing import Callable

from flask import abort
from flask_login import current_user, login_required


def role_required(role: str) -> Callable:
    """Ensure the active user holds the specified role."""

    def decorator(view: Callable) -> Callable:
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if not current_user.has_role(role):
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator
