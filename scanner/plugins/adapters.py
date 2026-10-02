import re
from typing import List
from .base_adapter import BaseAdapter, AstNode

class UniversalTreeSitterAdapter(BaseAdapter):
    """
    Adapter that parses code into standardized AstNodes.
    Uses tree-sitter when available, falling back gracefully to robust syntax-aware parsing.
    """
    def __init__(self, language: str):
        super().__init__(language)
        self.ts_parser = None
        self._init_tree_sitter()

    def _init_tree_sitter(self):
        try:
            import tree_sitter_languages
            self.ts_parser = tree_sitter_languages.get_parser(self.language)
        except Exception:
            self.ts_parser = None

    def parse_nodes(self, filepath: str, source: str) -> List[AstNode]:
        nodes: List[AstNode] = []
        if self.ts_parser:
            try:
                tree = self.ts_parser.parse(bytes(source, "utf8"))
                # Traverse tree-sitter AST and collect nodes
                self._traverse_ts_node(tree.root_node, source, nodes)
                if nodes:
                    return nodes
            except Exception:
                pass
        
        # Robust fallback parser extracting calls, imports, and assignments
        return self._fallback_parse(source)

    def _traverse_ts_node(self, ts_node, source: str, out_nodes: List[AstNode]):
        # Check node type
        ntype = ts_node.type
        line = ts_node.start_point[0] + 1
        col = ts_node.start_point[1] + 1
        raw_code = source[ts_node.start_byte:ts_node.end_byte]

        if "import" in ntype or "use_declaration" in ntype or "include" in ntype:
            out_nodes.append(AstNode(
                type="import",
                name=raw_code.strip(),
                args=[],
                kwargs={},
                line=line,
                column=col,
                raw_code=raw_code
            ))
        elif "call" in ntype or "invocation" in ntype or "expression" in ntype:
            if "(" in raw_code:
                fn_name = raw_code.split("(", 1)[0].strip()
                out_nodes.append(AstNode(
                    type="call",
                    name=fn_name,
                    args=[raw_code],
                    kwargs={},
                    line=line,
                    column=col,
                    raw_code=raw_code
                ))

        for child in ts_node.children:
            self._traverse_ts_node(child, source, out_nodes)

    def _fallback_parse(self, source: str) -> List[AstNode]:
        nodes: List[AstNode] = []
        lines = source.split("\n")

        # Regex patterns for universal AST node extraction
        import_patterns = {
            "typescript": [r"^\s*import\s+.*from\s+['\"]([^'\"]+)['\"]", r"^\s*const\s+.*=\s*require\(['\"]([^'\"]+)['\"]\)"],
            "java": [r"^\s*import\s+([\w\.\*]+);"],
            "go": [r"^\s*import\s+['\"]([^'\"]+)['\"]", r"^\s*import\s*\(([\s\S]*?)\)"],
            "c": [r"^\s*#include\s*[<\"']([^>\"']+)[\">']"],
            "cpp": [r"^\s*#include\s*[<\"']([^>\"']+)[\">']"],
            "csharp": [r"^\s*using\s+([\w\.]+);"],
            "rust": [r"^\s*use\s+([\w\:\*]+);"],
            "php": [r"^\s*use\s+([\w\\]+);", r"^\s*(?:require|include)(?:_once)?\s*['\"]([^'\"]+)['\"]"],
            "ruby": [r"^\s*require\s+['\"]([^'\"]+)['\"]"],
            "kotlin": [r"^\s*import\s+([\w\.\*]+)"],
        }

        # 1. Parse imports
        patterns = import_patterns.get(self.language, [r"^\s*(?:import|use|require|#include)\s+([^\n;]+)"])
        for idx, line in enumerate(lines, start=1):
            for pat in patterns:
                for match in re.finditer(pat, line):
                    val = match.group(1).strip()
                    nodes.append(AstNode(
                        type="import",
                        name=val,
                        args=[],
                        kwargs={},
                        line=idx,
                        column=match.start() + 1,
                        raw_code=line.strip()
                    ))

        # 2. Parse invocations / calls / instantiations
        call_pattern = re.compile(r"([A-Za-z0-9_\.:\$]+(?:\.[A-Za-z0-9_]+)*)\s*\(([^)]*)\)")
        for idx, line in enumerate(lines, start=1):
            if line.strip().startswith(("//", "#", "/*", "*")):
                continue
            for match in call_pattern.finditer(line):
                call_name = match.group(1)
                args_str = match.group(2)
                args = [a.strip() for a in args_str.split(",") if a.strip()]
                nodes.append(AstNode(
                    type="call",
                    name=call_name,
                    args=args,
                    kwargs={},
                    line=idx,
                    column=match.start() + 1,
                    raw_code=line.strip()
                ))

        # 3. Parse variable declarations / assignments
        assign_pattern = re.compile(r"(?:let|const|var|val|byte\[\]|String|auto)?\s*([a-zA-Z0-9_]+)\s*=\s*(.+)")
        for idx, line in enumerate(lines, start=1):
            if line.strip().startswith(("//", "#", "/*", "*")):
                continue
            match = assign_pattern.search(line)
            if match:
                var_name = match.group(1)
                val_expr = match.group(2).rstrip(";")
                nodes.append(AstNode(
                    type="assignment",
                    name=var_name,
                    args=[val_expr],
                    kwargs={},
                    line=idx,
                    column=match.start() + 1,
                    raw_code=line.strip(),
                    target=var_name
                ))

        return nodes
