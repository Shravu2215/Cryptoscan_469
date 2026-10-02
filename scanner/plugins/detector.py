import os
import re
from typing import Optional

class LanguageDetector:
    """
    Detects language using file extension, shebang, and content heuristics.
    """
    EXTENSION_MAP = {
        # TypeScript / JavaScript
        ".ts": "typescript",
        ".tsx": "typescript",
        ".mts": "typescript",
        ".cts": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        
        # Python
        ".py": "python",
        ".pyw": "python",
        
        # Java
        ".java": "java",
        
        # Go
        ".go": "go",
        
        # C / C++
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cxx": "cpp",
        ".cc": "cpp",
        ".hpp": "cpp",
        ".hxx": "cpp",
        ".hh": "cpp",
        
        # C#
        ".cs": "csharp",
        
        # Rust
        ".rs": "rust",
        
        # PHP
        ".php": "php",
        ".phtml": "php",
        ".php3": "php",
        ".php4": "php",
        ".php5": "php",
        ".php7": "php",
        
        # Ruby
        ".rb": "ruby",
        ".rake": "ruby",
        ".gemspec": "ruby",
        
        # Kotlin
        ".kt": "kotlin",
        ".kts": "kotlin",
    }

    SHEBANG_MAP = [
        (re.compile(r"^#!\s*/usr/bin/env\s+python.*", re.MULTILINE), "python"),
        (re.compile(r"^#!\s*/usr/bin/python.*", re.MULTILINE), "python"),
        (re.compile(r"^#!\s*/usr/bin/env\s+node.*", re.MULTILINE), "javascript"),
        (re.compile(r"^#!\s*/usr/bin/node.*", re.MULTILINE), "javascript"),
        (re.compile(r"^#!\s*/usr/bin/env\s+ruby.*", re.MULTILINE), "ruby"),
        (re.compile(r"^#!\s*/usr/bin/ruby.*", re.MULTILINE), "ruby"),
        (re.compile(r"^#!\s*/usr/bin/env\s+php.*", re.MULTILINE), "php"),
        (re.compile(r"^#!\s*/usr/bin/php.*", re.MULTILINE), "php"),
        (re.compile(r"^#!\s*/usr/bin/env\s+ts-node.*", re.MULTILINE), "typescript"),
    ]

    CONTENT_PATTERNS = [
        (re.compile(r"^\s*package\s+[\w\.]+\s*;", re.MULTILINE), "java"),
        (re.compile(r"^\s*package\s+[a-z0-9_]+(?:\s*;)?\s*$", re.MULTILINE), "go"),
        (re.compile(r"^\s*import\s+[\"']package:[^\"']+[\"']", re.MULTILINE), "dart"),
        (re.compile(r"^\s*<\?php", re.MULTILINE), "php"),
        (re.compile(r"^\s*using\s+System(?:\.[\w\.]+)?\s*;", re.MULTILINE), "csharp"),
        (re.compile(r"^\s*fn\s+main\s*\(\s*\)", re.MULTILINE), "rust"),
        (re.compile(r"^\s*#include\s+<[\w\./]+>", re.MULTILINE), "cpp"),
    ]

    @classmethod
    def detect(cls, filepath: str, source: Optional[str] = None) -> Optional[str]:
        ext = os.path.splitext(filepath)[1].lower()
        if ext in cls.EXTENSION_MAP:
            return cls.EXTENSION_MAP[ext]

        if not source:
            return None

        # 2. Check shebang
        first_line = source.split("\n", 1)[0].strip()
        if first_line.startswith("#!"):
            for pattern, lang in cls.SHEBANG_MAP:
                if pattern.match(first_line):
                    return lang

        # 3. Check content heuristics
        for pattern, lang in cls.CONTENT_PATTERNS:
            if pattern.search(source[:2000]):
                return lang

        return None
