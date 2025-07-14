__all__ = ["PacClient", "VtableXrefTuple"]

from abc import ABC, abstractmethod
from typing import NamedTuple

import idaapi
from ida_loader import find_plugin
from ida_typeinf import tinfo_t

from idahelper import cpp, instructions, memory

MAX_PREVIOUS_OPCODES_FOR_MOVK_SCAN = 10
MAX_NEXT_OPCODES_FOR_BLR_SCAN = MAX_PREVIOUS_OPCODES_FOR_MOVK_SCAN
PACXPLORER_PLUGIN_NAME = "pacxplorer"


class VtableXrefTuple(NamedTuple):
    xref_to: int
    vtable_addr: int
    vtable_entry_addr: int
    offset: int
    pac: int


class PacClient(ABC):
    """Client for PacExplorer plugin for querying PAC xrefs."""

    @staticmethod
    def is_pac_plugin_installed() -> bool:
        """Check if the PAC plugin is installed"""
        return find_plugin(PACXPLORER_PLUGIN_NAME) is not None

    @staticmethod
    def ensure_pac_plugin_installed():
        """Raise an exception if the PAC plugin is not installed"""
        if not PacClient.is_pac_plugin_installed():
            raise AssertionError(
                "PacExplorer plugin is not installed, please install from https://github.com/yoavst/PacXplorer/tree/patch-1"
            )

    @abstractmethod
    def _pac_candidates_from_movk(self, movk_ea: int) -> list[VtableXrefTuple]:
        """Given the EA of a movk, return possible functions that could be called using this movk"""

    def pac_candidates_from_movk(self, movk_ea: int) -> list[int]:
        """Given the EA of a movk, return possible functions that could be called using this movk"""
        return [item.xref_to for item in self._pac_candidates_from_movk(movk_ea)]

    def pac_candidates_for_call(self, call_ea: int) -> list[int]:
        """Given the EA of a call, return possible functions that could be called from this call"""
        movk_ea = self.get_previous_movk(call_ea)
        if movk_ea is None:
            return []
        return self.pac_candidates_from_movk(movk_ea)

    def pac_class_candidates_from_movk(self, movk_ea: int) -> list[tinfo_t]:
        """Given the EA of a movk, return the classes that implements the function that could be called using this movk"""
        candidates = self._pac_candidates_from_movk(movk_ea)
        if candidates is None:
            return []

        types: list[tinfo_t] = []
        for candidate in candidates:
            vtable_addr = candidate.vtable_addr
            vtable_name = memory.name_from_ea(vtable_addr)
            if vtable_name is None:
                print(f"[Error] vtable name is none at {vtable_addr:X}, aborting PAC solver.")
                return []
            original_type = cpp.type_from_vtable_name(vtable_name)
            if original_type is None:
                print(f"[Error] failed to convert vtable to type. Vtable at {vtable_addr:X}, name: {vtable_name}")
                return []
            types.append(original_type)
        return types

    @abstractmethod
    def pac_xrefs_to_func(self, func_ea: int) -> list[int]:
        """Get all xrefs to the given PAC function EA"""

    def pac_calls_xrefs_to_func(self, func_ea: int) -> list[int]:
        """Get the call instructions that use the PAC xrefs to the given function EA"""
        movks = self.pac_xrefs_to_func(func_ea)
        calls = []
        for movk in movks:
            call = self.get_next_blr(movk)
            if call is not None:
                calls.append(call)
        return calls

    @staticmethod
    def get_previous_movk(call_ea: int) -> int | None:
        """Given a call, search previous instructions to find a movk call"""
        insn = instructions.decode_instruction(call_ea)
        if not insn:
            return None

        if insn.get_canon_mnem() not in ("BLR", "BR"):
            return None

        # Get the register for PAC code
        movk_reg = insn[1].reg
        # BLR with just one register is unauthenticated, so there will be no PAC xref
        if movk_reg == 0:
            return None

        for _ in range(MAX_PREVIOUS_OPCODES_FOR_MOVK_SCAN):
            insn = instructions.decode_previous_instruction(insn)
            # No more instructions in this execution flow
            if insn is None:
                break
            if insn.get_canon_mnem() == "MOVK" and insn[0].reg == movk_reg:
                return insn.ea
        return None

    @staticmethod
    def get_next_blr(movk_ea: int) -> int | None:
        """Given a movk, search next instructions to find a call"""
        insn = instructions.decode_instruction(movk_ea)
        if not insn:
            return None

        if insn.get_canon_mnem() != "MOVK":
            return None

        movk_reg = insn[0].reg
        func = idaapi.get_func(insn.ea)
        if func is None:
            return None

        for _ in range(MAX_NEXT_OPCODES_FOR_BLR_SCAN):
            insn = instructions.decode_next_instruction(insn, func)
            # No more instructions in this execution flow
            if insn is None:
                break
            if insn.get_canon_mnem() in ("BLR", "BR") and insn[1].reg == movk_reg:
                return insn.ea
        return None
