"""Typed results shared by network detection, controller, and UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class NetworkStatus(str, Enum):
    CONNECTED = "CONNECTED"
    SUSPECTED_OFFLINE = "SUSPECTED_OFFLINE"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    NETWORK_UNAVAILABLE = "NETWORK_UNAVAILABLE"


@dataclass(frozen=True)
class DetectionResult:
    status: NetworkStatus
    consecutive_public_failures: int
    message: str
    portal_url: str | None = field(default=None, repr=False)
