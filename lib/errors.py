"""
lib/errors.py — Centralized error taxonomy (plan Phase 14)

ErrorCode enum: NETWORK, AUTH, RATE_LIMIT, PARSE, TOOL_MISSING
"""
from __future__ import annotations

import sys
from enum import Enum


class ErrorCode(str, Enum):
    NETWORK     = "network"       # Connection refused, timeout, DNS failure
    AUTH        = "auth"          # 401/403, credential failure
    RATE_LIMIT  = "rate_limit"    # 429, too many requests
    PARSE       = "parse"         # Malformed JSON/XML/output
    TOOL_MISSING = "tool_missing" # Required binary not in PATH
    DISK        = "disk"          # Insufficient disk space / write failure
    CONFIG      = "config"        # Invalid or missing configuration
    SCOPE       = "scope"         # Target not in scope
    UNKNOWN     = "unknown"       # Catch-all


class FrameworkError(Exception):
    """Base exception for Dark Recon Framework errors."""

    def __init__(self, code: ErrorCode, message: str, context: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.context = context or {}

    def to_dict(self) -> dict:
        return {"error_code": self.code.value, "message": self.message, "context": self.context}


class NetworkError(FrameworkError):
    def __init__(self, message: str, **ctx):
        super().__init__(ErrorCode.NETWORK, message, ctx)


class AuthError(FrameworkError):
    def __init__(self, message: str, **ctx):
        super().__init__(ErrorCode.AUTH, message, ctx)


class RateLimitError(FrameworkError):
    def __init__(self, message: str, **ctx):
        super().__init__(ErrorCode.RATE_LIMIT, message, ctx)


class ParseError(FrameworkError):
    def __init__(self, message: str, **ctx):
        super().__init__(ErrorCode.PARSE, message, ctx)


class ToolMissingError(FrameworkError):
    def __init__(self, tool_name: str, **ctx):
        super().__init__(ErrorCode.TOOL_MISSING, f"Required tool '{tool_name}' not found in PATH", {"tool": tool_name, **ctx})


class DiskError(FrameworkError):
    def __init__(self, message: str, **ctx):
        super().__init__(ErrorCode.DISK, message, ctx)


class ConfigError(FrameworkError):
    def __init__(self, message: str, **ctx):
        super().__init__(ErrorCode.CONFIG, message, ctx)


class ScopeError(FrameworkError):
    def __init__(self, target: str, **ctx):
        super().__init__(ErrorCode.SCOPE, f"Target '{target}' is out of scope", {"target": target, **ctx})


def classify_http_error(status_code: int) -> ErrorCode:
    """Map an HTTP status code to the appropriate ErrorCode."""
    if status_code == 401 or status_code == 403:
        return ErrorCode.AUTH
    if status_code == 429:
        return ErrorCode.RATE_LIMIT
    if status_code >= 500:
        return ErrorCode.NETWORK
    return ErrorCode.UNKNOWN


def classify_exception(exc: Exception) -> ErrorCode:
    """Best-effort mapping of a Python exception to an ErrorCode."""
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    if "connectionerror" in name or "timeout" in name or "connection" in msg:
        return ErrorCode.NETWORK
    if "permission" in msg or "unauthorized" in msg or "forbidden" in msg:
        return ErrorCode.AUTH
    if "rate" in msg and "limit" in msg:
        return ErrorCode.RATE_LIMIT
    if "json" in name or "parse" in name or "decode" in name:
        return ErrorCode.PARSE
    if "filenotfound" in name or "notfound" in name:
        return ErrorCode.TOOL_MISSING
    if "disk" in msg or "nospace" in msg or "enospc" in msg:
        return ErrorCode.DISK
    return ErrorCode.UNKNOWN
