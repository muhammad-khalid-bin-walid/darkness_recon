"""
lib/notifications.py — Slack, Discord, and webhook notification support.
Sends findings to external channels with rate limiting and rich formatting.
"""
from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from .report_utils import filter_by_severity

# Rate-limit state: deque of timestamps for sent messages
_rate_window: deque[float] = deque()
_MAX_MESSAGES_PER_MINUTE = 30


@dataclass
class NotificationResult:
    """Result of a notification attempt."""
    success: bool
    platform: str
    channel: str
    error: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _check_rate_limit() -> bool:
    """Return True if within rate limit, False if throttled."""
    now = time.monotonic()
    while _rate_window and _rate_window[0] < now - 60:
        _rate_window.popleft()
    if len(_rate_window) >= _MAX_MESSAGES_PER_MINUTE:
        return False
    _rate_window.append(now)
    return True


def _http_post(url: str, data: dict, headers: dict[str, str] | None = None) -> tuple[int, str]:
    """POST JSON to url. Returns (status_code, response_body)."""
    headers = headers or {}
    headers.setdefault("Content-Type", "application/json")
    body = json.dumps(data).encode("utf-8")
    req = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except URLError as exc:
        return 0, str(exc)
    except Exception as exc:
        return 0, str(exc)


def format_slack_message(finding: dict) -> dict:
    """Format a finding as a Slack Block Kit message payload."""
    severity = (finding.get("severity") or "info").upper()
    title = finding.get("title", "Untitled Finding")
    asset = finding.get("asset_id", "N/A")
    phase = finding.get("phase", "N/A")
    tool = finding.get("tool", "")
    description = finding.get("description", "")
    confidence = finding.get("confidence", 0.0)

    sev_colors = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#28a745",
        "info": "#17a2b8",
    }
    color = sev_colors.get(severity.lower(), "#6c757d")

    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🚨 {title}", "emoji": True},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n:{severity.lower()}: {severity}"},
                    {"type": "mrkdwn", "text": f"*Asset:*\n`{asset}`"},
                    {"type": "mrkdwn", "text": f"*Phase:*\n`{phase}`"},
                    {"type": "mrkdwn", "text": f"*Confidence:*\n{confidence:.0%}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Description:*\n{description or '_No description provided._'}"},
            },
            {"type": "divider"},
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Tool: `{tool}` | Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"},
                ],
            },
        ],
        "attachments": [{"color": color, "blocks": []}],
    }


def format_discord_embed(finding: dict) -> dict:
    """Format a finding as a Discord embed payload."""
    severity = (finding.get("severity") or "info").upper()
    title = finding.get("title", "Untitled Finding")
    asset = finding.get("asset_id", "N/A")
    phase = finding.get("phase", "N/A")
    tool = finding.get("tool", "")
    description = finding.get("description", "")
    confidence = finding.get("confidence", 0.0)

    sev_colors = {
        "critical": 0xDC3545,
        "high": 0xFD7E14,
        "medium": 0xFFC107,
        "low": 0x28A745,
        "info": 0x17A2B8,
    }
    color = sev_colors.get(severity.lower(), 0x6C757D)

    return {
        "embeds": [
            {
                "title": f"🚨 {title}",
                "description": description or "_No description provided._",
                "color": color,
                "fields": [
                    {"name": "Severity", "value": severity, "inline": True},
                    {"name": "Asset", "value": f"`{asset}`", "inline": True},
                    {"name": "Phase", "value": f"`{phase}`", "inline": True},
                    {"name": "Confidence", "value": f"{confidence:.0%}", "inline": True},
                    {"name": "Tool", "value": f"`{tool}`", "inline": True},
                ],
                "footer": {"text": "Dark Recon Framework"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]
    }


def send_slack(channel: str, finding: dict, webhook_url: str) -> NotificationResult:
    """Send a finding to a Slack channel via webhook."""
    if not _check_rate_limit():
        return NotificationResult(success=False, platform="slack", channel=channel, error="Rate limit exceeded")
    if not webhook_url:
        return NotificationResult(success=False, platform="slack", channel=channel, error="No webhook URL configured")

    payload = format_slack_message(finding)
    status, body = _http_post(webhook_url, payload)
    if 200 <= status < 300:
        return NotificationResult(success=True, platform="slack", channel=channel)
    return NotificationResult(success=False, platform="slack", channel=channel, error=f"HTTP {status}: {body}")


def send_discord(channel: str, finding: dict, webhook_url: str) -> NotificationResult:
    """Send a finding to a Discord channel via webhook."""
    if not _check_rate_limit():
        return NotificationResult(success=False, platform="discord", channel=channel, error="Rate limit exceeded")
    if not webhook_url:
        return NotificationResult(success=False, platform="discord", channel=channel, error="No webhook URL configured")

    payload = format_discord_embed(finding)
    status, body = _http_post(webhook_url, payload)
    if 200 <= status < 300:
        return NotificationResult(success=True, platform="discord", channel=channel)
    return NotificationResult(success=False, platform="discord", channel=channel, error=f"HTTP {status}: {body}")


def send_webhook(url: str, payload: dict, headers: dict[str, str] | None = None) -> NotificationResult:
    """Send an arbitrary JSON payload to a custom webhook endpoint."""
    if not _check_rate_limit():
        return NotificationResult(success=False, platform="webhook", channel=url, error="Rate limit exceeded")
    if not url:
        return NotificationResult(success=False, platform="webhook", channel=url, error="No webhook URL provided")

    status, body = _http_post(url, payload, headers)
    if 200 <= status < 300:
        return NotificationResult(success=True, platform="webhook", channel=url)
    return NotificationResult(success=False, platform="webhook", channel=url, error=f"HTTP {status}: {body}")


def notify_critical(findings: list[dict], config: dict[str, Any]) -> list[NotificationResult]:
    """Send notifications for critical and high findings across all configured channels."""
    critical_findings = filter_by_severity(findings, "high")
    results: list[NotificationResult] = []

    for finding in critical_findings:
        slack_cfg = config.get("slack", {})
        if slack_cfg.get("webhook"):
            result = send_slack(
                channel=slack_cfg.get("channel", "#security"),
                finding=finding,
                webhook_url=slack_cfg["webhook"],
            )
            results.append(result)

        discord_cfg = config.get("discord", {})
        if discord_cfg.get("webhook"):
            result = send_discord(
                channel=discord_cfg.get("channel", "security"),
                finding=finding,
                webhook_url=discord_cfg["webhook"],
            )
            results.append(result)

        for wh in config.get("webhooks", []):
            if wh.get("url"):
                result = send_webhook(url=wh["url"], payload=finding, headers=wh.get("headers"))
                results.append(result)

    return results


def batch_notify(findings: list[dict], config: dict[str, Any]) -> list[NotificationResult]:
    """Send all findings (grouped by severity, critical first) through configured channels."""
    from .report_utils import _SEVERITY_ORDER
    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get((f.get("severity") or "info").lower(), 0),
        reverse=True,
    )
    return notify_critical(sorted_findings, config)
