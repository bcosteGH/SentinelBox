from enum import Enum
from dataclasses import dataclass
from typing import Optional, Any
from datetime import datetime

class AuditStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"

class ModuleState(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"

@dataclass
class ModuleResult:
    name: str
    state: ModuleState
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    fatal: bool
    message: Optional[str]
    data: Optional[dict[str, Any]]
