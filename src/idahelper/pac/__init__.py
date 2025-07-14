__all__ = ["PacClient", "local", "remote"]

from .pac_interface import PacClient, VtableXrefTuple


class StubClient(PacClient):
    def _pac_candidates_from_movk(self, movk_ea: int) -> list[VtableXrefTuple]:
        raise ValueError("PAC plugin not installed, cannot query PAC candidates from movk")

    def pac_xrefs_to_func(self, func_ea: int) -> list[int]:
        raise ValueError("PAC plugin not installed, cannot query PAC xrefs to func")


local: PacClient
"""PAC client that initiates a new instance of PACExplorer plugin. Slow startup but faster queries"""
remote: PacClient
"""PAC client that communicate with the running PAC plugin. Immediate startup but slower queries"""

if not PacClient.is_pac_plugin_installed():
    print("[Warning] PAC plugin not installed, cannot use PAC features")
    local = remote = StubClient()
else:
    from .local_pac_client import LocalPacClient
    from .remote_pac_client import RemotePacClient

    local = LocalPacClient()
    remote = RemotePacClient()
