__all__ = ["RemotePacClient"]

import json
from typing import TypedDict

import idaapi
from netnode import Netnode

from .pac_interface import PacClient, VtableXrefTuple

PACXPLORER_PLUGIN_NAME = "pacxplorer"
PACXPLORER_ACTION_MOVK_CANDIDATES = 5
PACXPLORER_ACTION_FUNCTION_XREFS = 6


class VtableXrefDict(TypedDict):
    xref_to: int
    vtable_addr: int
    vtable_entry_addr: int
    offset: int
    pac: int


class RemotePacClient(PacClient):
    """Client for PacExplorer plugin for querying PAC xrefs via remote calls."""

    def _pac_candidates_from_movk(self, movk_ea: int) -> list[VtableXrefTuple]:
        result: list[VtableXrefDict] | None = self._pac_plugin_call(movk_ea, PACXPLORER_ACTION_MOVK_CANDIDATES)
        if result is None:
            return []

        return [
            VtableXrefTuple(x["xref_to"], x["vtable_addr"], x["vtable_entry_addr"], x["offset"], x["pac"])
            for x in result
        ]

    def pac_xrefs_to_func(self, func_ea: int) -> list[int]:
        result: list[tuple[int, ...]] | None = self._pac_plugin_call(func_ea, PACXPLORER_ACTION_FUNCTION_XREFS)
        if result is None:
            return []
        return [item[0] for item in result]

    @staticmethod
    def pac_plugin_netnode() -> Netnode:
        PacClient.ensure_pac_plugin_installed()
        return Netnode("$ pacxplorer_io")

    @staticmethod
    def _pac_plugin_call(input_data: int, action: int) -> list | None:
        n = RemotePacClient.pac_plugin_netnode()
        n["input"] = input_data
        idaapi.load_and_run_plugin(PACXPLORER_PLUGIN_NAME, action)
        output = n.get("output")
        if output is None:
            return None
        return json.loads(output)
