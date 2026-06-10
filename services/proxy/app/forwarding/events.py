from dataclasses import dataclass
from typing import Any

from fastapi import Request

from app.forwarding.schemas import ForwardMediaResourceRequestHeaders


@dataclass(frozen=True)
class RequestInit:
    request: Request
    headers: ForwardMediaResourceRequestHeaders
    upstream_headers: dict[str, Any]
    trace_id: str


@dataclass(frozen=True)
class RequestFinished:
    upstream_headers: dict[str, Any]
    trace_id: str
    status_code: int
    response_headers: dict[str, Any]


@dataclass(frozen=True)
class RequestTimeout:
    upstream_headers: dict[str, Any]
    trace_id: str
    status_code: int
