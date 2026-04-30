from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    severity: Severity = Severity.INFO

    owasp_category: Optional[str] = None

    title: str = ""

    description: str = ""

    evidence: Optional[str] = None

    remediation: Optional[str] = None

    cvss_score: Optional[float] = None

    scan_id: Optional[str] = None
