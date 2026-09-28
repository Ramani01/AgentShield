"""
Execution Telemetry & Safety Metrics Collector.
"""

from typing import Dict, Any

class ExecutionTelemetry:
    """Tracks aggregated runtime statistics for threat detection and block counts."""

    def __init__(self):
        self.metrics = {
            "total_requests": 0,
            "blocked_injections": 0,
            "blocked_jailbreaks": 0,
            "blocked_policies": 0,
            "sanitized_pii": 0,
            "detected_secrets": 0,
            "blocked_tools": 0
        }

    def record_event(self, event_name: str, count: int = 1):
        """Increments telemetry metric count."""
        if event_name in self.metrics:
            self.metrics[event_name] += count
        else:
            self.metrics[event_name] = count

    def get_summary(self) -> Dict[str, Any]:
        """Returns current telemetry metrics dictionary."""
        return self.metrics.copy()
