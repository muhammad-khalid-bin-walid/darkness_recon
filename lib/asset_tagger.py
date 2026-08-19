"""
lib/asset_tagger.py — Asset criticality auto-tagging (plan Phase 21)

Classifies assets as prod/staging/dev, auth-gated/public, API/web.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# Patterns indicating environment criticality
_STAGING_PATTERNS = re.compile(
    r'(?:^|\.)(?:staging|stage|stg|uat|qa|test|demo|sandbox|preview|pre[-_]prod|preprod)(?:\.|$)', re.I
)
_DEV_PATTERNS = re.compile(
    r'(?:^|\.)(?:dev|development|local|localhost|alpha|beta|feature|feat[-_]|wip|canary)(?:\.|$)', re.I
)

# API indicator patterns
_API_PATTERNS = re.compile(r'(?:^|\.)api\.|/api/|/graphql|/rest/|/v\d+/', re.I)
_API_HOST_PATTERNS = re.compile(r'(?:^|\.)(?:api|graphql|gql|rest|gateway)(?:\.|$)', re.I)

# Auth-gate indicators from headers / response metadata
_AUTH_HEADERS = {"authorization", "www-authenticate", "x-api-key", "x-auth-token"}


def tag_criticality(domain: str, url: str = "") -> str:
    """
    Classify an asset as prod/staging/dev based on domain/URL patterns.
    Returns: "prod" | "staging" | "dev"
    """
    target = domain.lower() if domain else (urlparse(url).netloc.lower() if url else "")
    if _DEV_PATTERNS.search(target):
        return "dev"
    if _STAGING_PATTERNS.search(target):
        return "staging"
    return "prod"


def tag_type(domain: str, url: str = "", headers: dict | None = None) -> str:
    """
    Classify an asset as web/api/infra.
    Returns: "web" | "api" | "infra"
    """
    target = domain.lower() if domain else ""
    url_lower = url.lower() if url else ""

    if _API_HOST_PATTERNS.search(target) or _API_PATTERNS.search(url_lower):
        return "api"

    # Infra heuristics: IP-only, internal ranges, port-based services
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        return "infra"
    if re.search(r'(?:mail|smtp|ftp|ssh|rdp|vpn|proxy|lb|loadbalancer|cdn)\.', target):
        return "infra"

    return "web"


def tag_auth_gated(headers: dict | None = None, status_code: int | None = None) -> bool:
    """
    Return True if the asset appears to be authentication-gated.
    Checks response headers and status codes.
    """
    if headers:
        lower_headers = {k.lower(): v for k, v in headers.items()}
        if any(h in lower_headers for h in _AUTH_HEADERS):
            return True
    if status_code in (401, 403):
        return True
    return False


def auto_tag_asset(asset: dict) -> dict:
    """
    Apply all auto-tags to an Asset dict.
    Returns the asset dict with updated criticality, type, and tags fields.
    """
    domain = asset.get("domain", "")
    url = asset.get("url", "")
    headers = asset.get("headers", {})
    status_code = asset.get("status_code")
    existing_tags = list(asset.get("tags", []))

    criticality = tag_criticality(domain, url)
    asset_type = tag_type(domain, url, headers)
    auth_gated = tag_auth_gated(headers, status_code)

    # Add computed tags
    if auth_gated and "auth-gated" not in existing_tags:
        existing_tags.append("auth-gated")
    elif not auth_gated and "public" not in existing_tags:
        existing_tags.append("public")

    if f"env:{criticality}" not in existing_tags:
        existing_tags.append(f"env:{criticality}")

    return {**asset, "criticality": criticality, "type": asset_type, "tags": existing_tags}


def batch_tag(assets: list[dict]) -> list[dict]:
    """Apply auto-tagging to a list of asset dicts."""
    return [auto_tag_asset(a) for a in assets]
