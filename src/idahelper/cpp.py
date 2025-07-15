from collections.abc import Iterable, Iterator
from dataclasses import dataclass

import ida_funcs
import idc
from ida_typeinf import tinfo_t

from idahelper import functions, memory, tif


def demangle(symbol: str, strict: bool = False) -> str | None:
    """Demangle cpp symbol."""
    res = idc.demangle_name(symbol, idc.get_inf_attr(idc.INF_SHORT_DEMNAMES))
    if strict:
        return res
    return res or symbol


def demangle_name_only(symbol: str, strict: bool = False) -> str | None:
    """Demangle cpp symbol, return name of the function (including class)"""
    res = demangle(symbol, strict)
    if res is not None:
        return res.split("(")[0]
    return None


def demangle_class_only(symbol: str, strict: bool = False) -> str | None:
    """Demangle cpp symbol, return name of the class"""
    class_and_name = demangle_class_and_name(symbol, strict)
    if class_and_name is None:
        return None
    return class_and_name[0]


def demangle_class_and_name(symbol: str, strict: bool = False) -> tuple[str, str] | None:
    """Demangle cpp symbol, return tuple of class name and method"""
    name = demangle_name_only(symbol, strict)
    if name is None:
        return None
    # Expected Class::methodName or Class::innerClass::methodName
    last_double_colon = name.rfind("::")
    if last_double_colon == -1:
        return None
    return name[:last_double_colon], name[last_double_colon + 2 :]


def vtable_location_from_type(cpp_type: tinfo_t) -> int | None:
    """Find the location of the "\\`vtable'TYPE" for the given `cpp_type`"""
    # noinspection PyTypeChecker
    type_name: str = cpp_type.get_type_name()  # pyright: ignore[reportAssignmentType]
    return memory.ea_from_name(f"__ZTV{len(type_name)}{type_name}")


def class_name_from_vtable_name(symbol: str) -> str | None:
    """Given the name of the vtable symbol, return the class name"""
    vtable_demangled_name = demangle(symbol)
    if vtable_demangled_name and vtable_demangled_name.startswith("`vtable for'"):
        return vtable_demangled_name[12:]
    else:
        return None


def type_from_vtable_name(symbol: str) -> tinfo_t | None:
    """Given the name of the vtable symbol, return the cpp type"""
    cls_name = class_name_from_vtable_name(symbol)
    return tif.from_struct_name(cls_name) if cls_name else None


def iterate_vtables(skip_metaclass: bool = True) -> Iterator[tuple[str, int]]:
    """Iterate over all vtables in the database, yielding class name and vtable ea."""
    for ea, name in memory.names():
        cls = class_name_from_vtable_name(name)
        if cls is not None and (skip_metaclass or not cls.endswith("::MetaClass")):
            yield cls, ea


def get_all_cpp_classes() -> list[tuple[tinfo_t, int]]:
    """Return map between cpp type to its vtable ea"""
    d: list[tuple[tinfo_t, int]] = []
    for class_name, vtable_ea in iterate_vtables():
        cls = tif.from_struct_name(class_name)
        if cls is not None:
            d.append((cls, vtable_ea))
    return d


@dataclass
class VTableItem:
    index: int
    vtable_offset: int
    func_ea: int
    func_name: str
    demangled_func_name: str


def iterate_vtable(vtable_ea: int, skip_reserved: bool = True, raise_on_error: bool = False) -> Iterable[VTableItem]:
    """Iterate over the vtable at `vtable_ea`, yielding VTableItem for each function."""
    if memory.qword_from_ea(vtable_ea) != 0:
        error_msg = f"Expected null on offset 0, received: {memory.qword_from_ea(vtable_ea):X}"
        if raise_on_error:
            raise MemoryError()
        return

    current_ea = vtable_ea + 2 * memory.PTR_SIZE
    i = 0
    while (func_addr := memory.qword_from_ea(current_ea)) != 0:
        if ida_funcs.get_func(func_addr):
            mangled_name = memory.name_from_ea(func_addr)
        elif not (mangled_name := memory.name_from_imported_ea(func_addr)):
            error_msg = f"{vtable_ea:X}: Failed to get func from vtable at {current_ea:X}. Data: {func_addr:X}"
            if raise_on_error:
                raise MemoryError(error_msg)
            print(f"[Error] {error_msg}")
            return

        demangled_func_name = demangle_name_only(mangled_name, strict=False) or ""
        if not skip_reserved or "::_RESERVED" not in demangled_func_name:
            yield VTableItem(
                index=i,
                vtable_offset=current_ea - vtable_ea,
                func_ea=func_addr,
                func_name=mangled_name,
                demangled_func_name=demangled_func_name,
            )
            i += 1

        current_ea += memory.PTR_SIZE


def vtable_methods_count(cls: tinfo_t, skip_reserved: bool) -> int:
    """Given a class, return the number of entries in it."""
    vtable_ea = vtable_location_from_type(cls)
    if vtable_ea is None:
        return -1

    # Use the iterate_vtable function to count methods if we want to skip reserved methods
    if skip_reserved:
        last_method: VTableItem | None = None
        for method in iterate_vtable(vtable_ea, skip_reserved):
            last_method = method

        if last_method is None:
            return 0

        return last_method.index + 1
    else:
        # If we don't skip reserved methods, we can just count the number of entries in the vtable
        current_ea = vtable_ea + 2 * memory.PTR_SIZE
        i = 0
        while memory.qword_from_ea(current_ea) != 0:
            i += 1
            current_ea += memory.PTR_SIZE
        return i


def vtable_func_at(cls: tinfo_t, offset: int) -> int | None:
    """Given a class and an offset to vtable entry, return the ea at the given offset."""
    vtable_ea = vtable_location_from_type(cls)
    if vtable_ea is None:
        return None

    # Read the func at the relevant offset
    vtable_entry = vtable_ea + (2 * memory.PTR_SIZE + offset)
    vtable_func_ea = memory.qword_from_ea(vtable_entry)
    return vtable_func_ea if functions.is_in_function(vtable_func_ea) else None
