from abc import ABC, abstractmethod
from typing import Any, Optional

class Module(ABC):
    name: str = "Unnamed"

    @abstractmethod
    def run(self, context: dict[str, Any]) -> tuple[bool, bool, Optional[str], Optional[dict[str, Any]]]:
        ...
