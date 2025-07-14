__all__ = ["PacClient", "local", "remote"]

from .pac_interface import PacClient, VtableXrefTuple


class StubClient(PacClient):
    def __init__(self, is_local: bool = False):
        self._is_local = is_local
        self.__client: PacClient | None = None

    def _client(self) -> PacClient:
        if self.__client is not None:
            return self.__client

        self.ensure_pac_plugin_installed()
        if self._is_local:
            from .local_pac_client import LocalPacClient

            self.__client = LocalPacClient()
        else:
            from .remote_pac_client import RemotePacClient

            self.__client = RemotePacClient()
        return self.__client

    def _pac_candidates_from_movk(self, movk_ea: int) -> list[VtableXrefTuple]:
        return self._client()._pac_candidates_from_movk(movk_ea)

    def pac_xrefs_to_func(self, func_ea: int) -> list[int]:
        return self._client().pac_xrefs_to_func(func_ea)


local: PacClient = StubClient(is_local=True)
"""PAC client that initiates a new instance of PACExplorer plugin. Slow startup but faster queries"""
remote: PacClient = StubClient(is_local=False)
"""PAC client that communicate with the running PAC plugin. Immediate startup but slower queries"""
