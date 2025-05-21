"""This Enum is used to track all the metrics that are being used in the application."""

from enum import Enum
from typing import Any, Dict


class Metrics(Enum):
    DVA_REQUEST_LATENCY = "{dva}.request.latency"
    DVA_REQUEST_COUNT = "{dva}.request.count"
    DVA_REQUEST_ATTEMPT_COUNT = "{dva}.request.attempt_count.{attempt_number}"
    DVA_RESPONSE_SIZE = "{dva}.response.size"

    def format_key(self, placeholders: Dict[str, Any]) -> str:
        return self.value.format(**placeholders)
