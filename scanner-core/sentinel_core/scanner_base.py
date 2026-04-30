from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

from .finding import Finding


@dataclass
class ScanTarget:
    url: str           
    scan_id: str       
    domain: str       


@dataclass
class ScanConfig:
    max_requests_per_second: int = 5
    request_timeout: int = 10
    respect_robots_txt: bool = True


class Scanner(ABC):

    @abstractmethod
    def scan(self, target: ScanTarget, config: ScanConfig) -> List[Finding]:
        """
        Verilen hedefi tara, bulunan güvenlik açıklarını Finding listesi olarak dön.
        Bu metodu implement etmek zorunlu — etmezsen TypeError alırsın.
        """
        ...

    def name(self) -> str:
        """Scanner'ın adı — log mesajlarında ve monitoring'de kullanılır"""
        return self.__class__.__name__
