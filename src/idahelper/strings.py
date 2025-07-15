import functools
import sys

from idautils import Strings

CACHED_STRINGS_ATTR = "_ida_strings"


@functools.cache
def strings():
    # Cache it somewhere else, to avoid build strings every time we reload our plugin
    main_module = sys.modules["__main__"]
    if hasattr(main_module, CACHED_STRINGS_ATTR):
        return getattr(main_module, CACHED_STRINGS_ATTR)

    strings_obj = Strings()
    setattr(main_module, CACHED_STRINGS_ATTR, strings_obj)
    return strings_obj


def find_str(content: str) -> Strings.StringItem:
    try:
        return next(s for s in strings() if str(s) == content)
    except StopIteration:
        raise ValueError(f"Could not find string {content}")  # noqa: B904


def find_strs(content: str) -> list[Strings.StringItem]:
    """find all the strings with the given content"""
    return [s for s in strings() if str(s) == content]
