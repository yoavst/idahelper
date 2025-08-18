__all__ = ["PacClient", "VtableXrefTuple", "client"]

from .pac_interface import PacClient, VtableXrefTuple
from .pacxplorer import PacXplorerClient
from .pacxplorerng import PacXplorerNGPacClient


class StubClient(PacClient):
    def __init__(self):
        self.__client: PacClient | None = None

    def _client(self) -> PacClient:
        if self.__client is not None:
            return self.__client

        if PacXplorerNGPacClient.is_pac_plugin_installed():
            self.__client = PacXplorerNGPacClient()
        elif PacXplorerClient.is_pac_plugin_installed():
            self.__client = PacXplorerClient()
        else:
            PacXplorerNGPacClient.ensure_pac_plugin_installed()
        return self.__client

    def _pac_candidates_from_movk(self, movk_ea: int) -> list[VtableXrefTuple]:
        return self._client()._pac_candidates_from_movk(movk_ea)

    def pac_xrefs_to_func(self, func_ea: int) -> list[int]:
        return self._client().pac_xrefs_to_func(func_ea)

    @classmethod
    def is_pac_plugin_installed(cls) -> bool:
        return PacXplorerNGPacClient.is_pac_plugin_installed() or PacXplorerClient.is_pac_plugin_installed()


client: PacClient = StubClient()
