from collections.abc import Callable
from functools import wraps
from typing import TypeVar

T = TypeVar("T")


def cache_fast(func: Callable[[], T]) -> Callable[[], T]:
    """Decorator to cache the result of a function for faster access."""
    cached_value: T | None = None

    @wraps(func)
    def wrapper():
        nonlocal cached_value
        if cached_value is None:
            cached_value = func()
        return cached_value

    return wrapper
