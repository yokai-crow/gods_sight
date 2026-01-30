from abc import ABC, abstractmethod
from typing import List
from core.findings import Finding
from core.results import ScanResult

class Plugin(ABC):
    name: str = "BasePlugin"

    @abstractmethod
    def run(self, results: List[ScanResult]) -> List[Finding]:
        pass
