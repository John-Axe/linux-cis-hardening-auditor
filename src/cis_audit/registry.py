"""A tiny global registry that check modules populate via @register(...)."""

from __future__ import annotations

from typing import Callable

from cis_audit.models import Check, CheckResult

_REGISTRY: list[Check] = []


def register(
    id: str,
    title: str,
    category: str,
    rationale: str,
    remediation: str,
) -> Callable[[Callable[[], CheckResult]], Callable[[], CheckResult]]:
    """Decorator that registers a check function under the global registry.

    The decorated function's signature is ``() -> CheckResult``.
    """

    def decorator(fn: Callable[[], CheckResult]) -> Callable[[], CheckResult]:
        for existing in _REGISTRY:
            if existing.id == id:
                raise ValueError(f"duplicate check id registered: {id}")
        _REGISTRY.append(
            Check(
                id=id,
                title=title,
                category=category,
                rationale=rationale,
                remediation=remediation,
                run=fn,
            )
        )
        return fn

    return decorator


def all_checks() -> list[Check]:
    return list(_REGISTRY)


def categories() -> list[str]:
    seen: list[str] = []
    for check in _REGISTRY:
        if check.category not in seen:
            seen.append(check.category)
    return seen
