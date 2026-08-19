"""
Dark Recon Framework — Unified Data Schema (schema_version 1.0.2)

Every phase reads and writes these Pydantic v2 models.  Persistence is JSON;
use model.to_json() to serialise and Model.from_json() to deserialise.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Version constant
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "1.0.2"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AssetType(str, Enum):
    WEB = "web"
    API = "api"
    INFRA = "infra"


class Criticality(str, Enum):
    PROD = "prod"
    STAGING = "staging"
    DEV = "dev"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    NEW = "new"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"


class CredentialType(str, Enum):
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    CERTIFICATE = "certificate"


class ScanStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


# ---------------------------------------------------------------------------
# Asset
# ---------------------------------------------------------------------------


class Asset(BaseModel):
    """A unique discovered entity in the target environment."""

    id: str = Field(default_factory=_new_uuid)
    domain: Optional[str] = Field(default=None)
    ip: Optional[str] = Field(default=None)
    asn: Optional[str] = Field(default=None)
    type: AssetType = Field(description="Asset category: web, api, or infra")
    criticality: Criticality = Field(description="Environment criticality: prod, staging, or dev")
    tags: list[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=_utcnow)
    source: Optional[str] = Field(default=None, description="Tool or phase that discovered this asset")

    def to_json(self, *, indent: int | None = None) -> str:
        return self.model_dump_json(indent=indent)

    @classmethod
    def from_json(cls, data: str | bytes) -> "Asset":
        return cls.model_validate_json(data)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """A security observation attached to an asset."""

    id: str = Field(default_factory=_new_uuid)
    asset_id: str = Field(description="FK → Asset.id")
    title: str = Field(description="Short human-readable title")
    description: str = Field(default="")
    severity: FindingSeverity = Field(description="Severity classification")
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence score 0.0–1.0",
    )
    status: FindingStatus = Field(default=FindingStatus.NEW)
    phase: Optional[str] = Field(default=None, description="Framework phase that produced this finding")
    tool: Optional[str] = Field(default=None, description="Tool that produced this finding")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Raw evidence captured at detection time")
    fingerprint: Optional[str] = Field(default=None, description="Deduplication fingerprint")
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    def to_json(self, *, indent: int | None = None) -> str:
        return self.model_dump_json(indent=indent)

    @classmethod
    def from_json(cls, data: str | bytes) -> "Finding":
        return cls.model_validate_json(data)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


class Endpoint(BaseModel):
    """A specific HTTP endpoint discovered on an asset."""

    id: str = Field(default_factory=_new_uuid)
    asset_id: str = Field(description="FK → Asset.id")
    url: str = Field(description="Full URL, e.g. 'https://api.example.com/v1/users'")
    method: str = Field(default="GET", description="HTTP method")
    status_code: Optional[int] = Field(default=None)
    content_type: Optional[str] = Field(default=None)
    parameters: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=_utcnow)

    @field_validator("method")
    @classmethod
    def _upper_method(cls, v: str) -> str:
        return v.upper()

    def to_json(self, *, indent: int | None = None) -> str:
        return self.model_dump_json(indent=indent)

    @classmethod
    def from_json(cls, data: str | bytes) -> "Endpoint":
        return cls.model_validate_json(data)


# ---------------------------------------------------------------------------
# Credential
# ---------------------------------------------------------------------------


class Credential(BaseModel):
    """A discovered credential.  Plaintext is never stored; only its SHA-256 hash."""

    id: str = Field(default_factory=_new_uuid)
    asset_id: str = Field(description="FK → Asset.id where this credential was found")
    type: CredentialType = Field(description="Credential category")
    value_hash: str = Field(
        description="SHA-256 hex digest of the credential value — never store plaintext"
    )
    source: Optional[str] = Field(default=None, description="File/URL/tool where credential was found")
    discovered_at: datetime = Field(default_factory=_utcnow)
    rotation_age_days: Optional[int] = Field(
        default=None, description="Days since the credential was last rotated"
    )

    @staticmethod
    def hash_value(plaintext: str) -> str:
        """Return the SHA-256 hex digest of *plaintext*.  Use this instead of storing raw values."""
        return hashlib.sha256(plaintext.encode()).hexdigest()

    def to_json(self, *, indent: int | None = None) -> str:
        return self.model_dump_json(indent=indent)

    @classmethod
    def from_json(cls, data: str | bytes) -> "Credential":
        return cls.model_validate_json(data)


# ---------------------------------------------------------------------------
# ScanRun
# ---------------------------------------------------------------------------


class ScanRun(BaseModel):
    """Top-level container for one complete (or in-progress) scan execution."""

    id: str = Field(default_factory=_new_uuid)
    target: str = Field(description="Primary target domain or IP for this scan run")
    profile: Optional[str] = Field(default=None, description="Scan profile used, e.g. 'prod', 'dev'")
    started_at: Optional[datetime] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)
    phases_run: list[str] = Field(default_factory=list, description="Ordered list of phases executed")
    findings_count: int = Field(default=0)
    status: ScanStatus = Field(default=ScanStatus.RUNNING)
    schema_version: str = Field(default=SCHEMA_VERSION)

    def to_json(self, *, indent: int | None = None) -> str:
        return self.model_dump_json(indent=indent)

    @classmethod
    def from_json(cls, data: str | bytes) -> "ScanRun":
        return cls.model_validate_json(data)
