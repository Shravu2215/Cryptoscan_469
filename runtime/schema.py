"""
Runtime Event Data Model and Validation Schema for CryptoScan.
Defines the structure for all intercepted runtime cryptographic operations.
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
import uuid
from typing import Optional, Dict, Any

from runtime.normalize import normalize_algorithm, VALID_OPERATIONS

VALID_LANGUAGES = {"python", "node"}


@dataclass
class RuntimeEvent:
    event_id: str
    run_id: str
    timestamp: str
    language: str
    library: str
    operation: str
    algorithm: str
    key_size: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    curve: Optional[str] = None
    call_file: str = ""
    call_line: int = 0
    call_function: str = ""
    matched_finding_id: Optional[str] = None

    def __post_init__(self):
        if not self.event_id:
            self.event_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        
        self.algorithm = normalize_algorithm(self.algorithm)
        
        if self.language not in VALID_LANGUAGES:
            raise ValueError(f"Invalid language: '{self.language}'. Must be one of {VALID_LANGUAGES}")
        
        if self.operation not in VALID_OPERATIONS:
            raise ValueError(f"Invalid operation: '{self.operation}'. Must be one of {VALID_OPERATIONS}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def validate_event_dict(event_data: Dict[str, Any]) -> RuntimeEvent:
    """
    Validates a raw dictionary against the RuntimeEvent schema and returns a typed RuntimeEvent instance.
    Raises ValueError on validation failure.
    """
    required_fields = [
        "run_id", "language", "library", "operation", "algorithm"
    ]
    for req in required_fields:
        if req not in event_data or event_data[req] is None:
            raise ValueError(f"Missing required field: '{req}'")

    return RuntimeEvent(
        event_id=str(event_data.get("event_id") or uuid.uuid4()),
        run_id=str(event_data["run_id"]),
        timestamp=str(event_data.get("timestamp") or datetime.now(timezone.utc).isoformat()),
        language=str(event_data["language"]),
        library=str(event_data["library"]),
        operation=str(event_data["operation"]),
        algorithm=str(event_data["algorithm"]),
        key_size=int(event_data["key_size"]) if event_data.get("key_size") is not None else None,
        mode=str(event_data["mode"]) if event_data.get("mode") else None,
        padding=str(event_data["padding"]) if event_data.get("padding") else None,
        curve=str(event_data["curve"]) if event_data.get("curve") else None,
        call_file=str(event_data.get("call_file") or ""),
        call_line=int(event_data.get("call_line") or 0),
        call_function=str(event_data.get("call_function") or ""),
        matched_finding_id=str(event_data["matched_finding_id"]) if event_data.get("matched_finding_id") else None,
    )
