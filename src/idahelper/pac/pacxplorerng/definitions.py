from typing import NamedTuple, Protocol

from ..pac_interface import VtableXrefTuple


class PacTuple(NamedTuple):
    """
    ```
    LDR     X8, [X0]            ; load vtable address
    LDRA    X9, [X8,#0x18]!     ; X8 = vtbl + offset
    MOVK    X8, #0x68DA,LSL#48  ; set the hash
    BLRAA   X9, X8              ; virtual call
    ```

    This tuple represents the PAC (Pointer Authentication Code) information
    extracted from the MOVK instruction.
    It contains the offset within the vtable and the PAC value.
    The offset is the immediate value used in the MOVK instruction,
    """

    offset: int
    pac: int


class MovkCodeTuple(NamedTuple):
    """This tuple represents the MOVK instruction and its associated PAC information."""

    pac_tuple: PacTuple
    movk_addr: int


class ExplorerProtocol(Protocol):
    def analyze(self, only_cached: bool = False) -> None:
        """
        Analyze the current IDA database.

        If only_cached is True, only cached values will be used. An exception will be raised if no cached values are available.
        If not, the analysis will be performed and results will be cached.
        """

    def movk_to_functions(self, movk_ea: int) -> list[VtableXrefTuple]:
        """Get the possible function candidates for a given MOVK instruction address."""

    def function_to_movks(self, func_ea: int) -> list[int]:
        """Get the possible MOVK candidates for a given function."""

    def is_pac_function(self, func_ea: int) -> bool:
        """Check if the function at the given address is a PAC function."""

    @staticmethod
    def get_instance() -> "ExplorerProtocol":
        """Get the singleton instance of the Explorer."""


def get_explorer_instance() -> ExplorerProtocol:
    """Get the singleton instance of the Explorer."""
    # noinspection PyUnresolvedReferences
    from pacxplorerng.explorer import Explorer

    return Explorer.get_instance()
