from typing import Dict
from .base_adapter import BaseAdapter
from .adapters import UniversalTreeSitterAdapter

class PluginRegistry:
    """
    Registry for language adapters.
    """
    _adapters: Dict[str, BaseAdapter] = {}

    @classmethod
    def get_adapter(cls, language: str) -> BaseAdapter:
        if language not in cls._adapters:
            cls._adapters[language] = UniversalTreeSitterAdapter(language)
        return cls._adapters[language]

    @classmethod
    def register_adapter(cls, language: str, adapter: BaseAdapter):
        cls._adapters[language] = adapter
