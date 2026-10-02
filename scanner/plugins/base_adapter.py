import abc
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class AstNode:
    type: str  # 'import', 'call', 'definition', 'assignment', 'instantiation'
    name: str  # identifier or module name
    args: List[str]
    kwargs: Dict[str, str]
    line: int
    column: int
    raw_code: str
    target: Optional[str] = None  # variable name being assigned to

class BaseAdapter(abc.ABC):
    """
    Abstract Base Adapter for universal AST & syntax extraction.
    Provides standard hooks for tree-sitter or native AST extraction.
    """
    def __init__(self, language: str):
        self.language = language

    @abc.abstractmethod
    def parse_nodes(self, filepath: str, source: str) -> List[AstNode]:
        """
        Extract cryptographic-relevant nodes (imports, calls, assignments).
        """
        pass
