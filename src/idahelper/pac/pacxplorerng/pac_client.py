from .. import PacClient
from .definitions import ExplorerProtocol, VtableXrefTuple, get_explorer_instance


class PacXplorerNGPacClient(PacClient):
    plugin_name = "pacxplorerng"

    def __init__(self):
        self.ensure_pac_plugin_installed()
        self.explorer: ExplorerProtocol = get_explorer_instance()
        self.explorer.analyze(True)

    def _pac_candidates_from_movk(self, movk_ea: int) -> list[VtableXrefTuple]:
        return self.explorer.movk_to_functions(movk_ea)

    def pac_xrefs_to_func(self, func_ea: int) -> list[int]:
        return self.explorer.function_to_movks(func_ea)
