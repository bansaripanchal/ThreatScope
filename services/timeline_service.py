"""
ThreatScope V2 - Timeline Service
Manages step-by-step audit logging of reconnaissance pipeline execution.
Records real timestamps, durations, statuses, and factual telemetry events.
"""

from typing import Dict, List, Any
from database.repository import TimelineRepository

class TimelineService:
    @staticmethod
    def record(investigation_id: str, operation: str, status: str, 
               duration_ms: int = 0, message: str = ""):
        """Appends a verified reconnaissance timeline event to the persistent database."""
        TimelineRepository.add_event(
            investigation_id=investigation_id,
            operation=operation,
            status=status.upper(),
            duration_ms=duration_ms,
            message=message
        )

    @staticmethod
    def get_timeline(investigation_id: str) -> List[Dict[str, Any]]:
        """Retrieves chronological timeline events for an investigation."""
        return TimelineRepository.get_by_investigation(investigation_id)
