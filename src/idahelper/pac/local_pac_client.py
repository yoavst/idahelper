__all__ = ["LocalPacClient"]

import sys
from collections import namedtuple
from typing import Protocol

from .._utils import cache_fast
from .pac_interface import PacClient, VtableXrefTuple

MovkCodeTuple = namedtuple("MovkCodeTuple", ["pac_tuple", "movk_addr", "trace"])


class VtableAnalyzerProtocol(Protocol):
    def codes_from_func_addr(self, ea: int) -> list: ...

    def func_from_pac_tuple(self, pac_tuple: MovkCodeTuple) -> list[VtableXrefTuple]: ...


class MovkAnalyzerProtocol(Protocol):
    def pac_tuple_from_ea(self, ea: int) -> MovkCodeTuple: ...

    def movks_from_pac_codes(self, pac_codes) -> list[tuple]: ...


class PacxplorerPluginProtocol(Protocol):
    vtable_analyzer: VtableAnalyzerProtocol
    movk_analyzer: MovkAnalyzerProtocol
    analysis_done: bool

    def analyze(self, only_cached=False) -> None: ...


class LocalPacClient(PacClient):
    """Client that initiates an instance of the PAC plugin and queries it directly."""

    PLUGIN_NAME_CACHED = "pacxplorer_plugin"

    @staticmethod
    @cache_fast
    def _get_pac_plugin() -> PacxplorerPluginProtocol:
        # Cache it somewhere else, to avoid analyzing every time we reload our plugin
        main_module = sys.modules["__main__"]
        if hasattr(main_module, LocalPacClient.PLUGIN_NAME_CACHED):
            return getattr(main_module, LocalPacClient.PLUGIN_NAME_CACHED)

        PacClient.ensure_pac_plugin_installed()
        # noinspection PyUnresolvedReferences
        import pacxplorer  # pyright: ignore [reportMissingImports]

        plugin: PacxplorerPluginProtocol = pacxplorer.PacxplorerPlugin()
        plugin.analyze(False)
        if not plugin.analysis_done:
            raise AssertionError("PacExplorer plugin analysis not done, please run the analysis first")
        setattr(main_module, LocalPacClient.PLUGIN_NAME_CACHED, plugin)
        return plugin

    def _pac_candidates_from_movk(self, movk_ea: int) -> list[VtableXrefTuple]:
        pac_plugin = self._get_pac_plugin()
        return pac_plugin.vtable_analyzer.func_from_pac_tuple(pac_plugin.movk_analyzer.pac_tuple_from_ea(movk_ea))

    def pac_xrefs_to_func(self, func_ea: int) -> list[int]:
        pac_plugin = self._get_pac_plugin()
        pac_codes = pac_plugin.vtable_analyzer.codes_from_func_addr(func_ea)
        if pac_codes is None:
            return []
        movks = pac_plugin.movk_analyzer.movks_from_pac_codes(pac_codes)
        return [addr for addr, code in movks]
