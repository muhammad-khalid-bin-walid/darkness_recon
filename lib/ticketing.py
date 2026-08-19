"""
lib/ticketing.py — Jira and Linear ticket management for findings.
Creates, updates, and tracks tickets for security findings.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from .report_utils import _SEVERITY_ORDER


@dataclass
class TicketResult:
    """Result of a ticket creation or update operation."""
    ticket_id: str
    url: str
    status: str
    platform: str
    error: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _http_request(
    url: str,
    method: str = "GET",
    data: dict | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, str]:
    """Make an HTTP request and return (status_code, response_body)."""
    headers = headers or {}
    body = json.dumps(data).encode("utf-8") if data else None
    req = Request(url, data=body, headers=headers, method=method)
    if body and "Content-Type" not in headers:
        req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except URLError as exc:
        return 0, str(exc)
    except Exception as exc:
        return 0, str(exc)


def _map_priority(finding: dict) -> str:
    """Map finding severity to a platform-agnostic priority string."""
    severity = (finding.get("severity") or "info").lower()
    if severity == "critical":
        return "highest"
    elif severity == "high":
        return "high"
    elif severity == "medium":
        return "medium"
    elif severity == "low":
        return "low"
    return "lowest"


def _jira_priority(finding: dict) -> str:
    """Map finding severity to Jira priority name."""
    severity = (finding.get("severity") or "info").lower()
    mapping = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    }
    return mapping.get(severity, "Medium")


def _build_jira_description(finding: dict) -> str:
    """Build a Jira-flavored markdown description from a finding."""
    parts = [
        f"h3. Description\n{finding.get('description', 'No description provided.')}",
        f"\nh3. Details",
        f"* *Asset:* {{code}}{finding.get('asset_id', 'N/A')}{{code}}",
        f"* *Phase:* {{code}}{finding.get('phase', 'N/A')}{{code}}",
        f"* *Tool:* {{code}}{finding.get('tool', 'N/A')}{{code}}",
        f"* *Confidence:* {finding.get('confidence', 0):.0%}",
    ]
    evidence = finding.get("evidence")
    if evidence:
        parts.append(f"\nh3. Evidence\n{{code}}\n{evidence}\n{{code}}")
    return "\n".join(parts)


def _build_linear_description(finding: dict) -> str:
    """Build a markdown description from a finding for Linear."""
    parts = [
        f"## Description\n{finding.get('description', 'No description provided.')}",
        f"\n## Details",
        f"- **Asset:** `{finding.get('asset_id', 'N/A')}`",
        f"- **Phase:** `{finding.get('phase', 'N/A')}`",
        f"- **Tool:** `{finding.get('tool', 'N/A')}`",
        f"- **Confidence:** {finding.get('confidence', 0):.0%}",
    ]
    evidence = finding.get("evidence")
    if evidence:
        parts.append(f"\n## Evidence\n```\n{evidence}\n```")
    return "\n".join(parts)


def create_jira_ticket(finding: dict, config: dict[str, Any]) -> TicketResult:
    """Create a Jira ticket from a finding using the REST API."""
    base_url = config.get("jira", {}).get("base_url", config.get("base_url", ""))
    project_key = config.get("jira", {}).get("project_key", config.get("project_key", ""))
    email = config.get("jira", {}).get("email", "")
    token = config.get("jira", {}).get("token", config.get("api_token", ""))

    if not base_url or not project_key:
        return TicketResult(
            ticket_id="", url="", status="failed",
            platform="jira", error="Missing base_url or project_key in config",
        )

    auth_token = base64.b64encode(f"{email}:{token}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth_token}",
        "Content-Type": "application/json",
    }

    severity = (finding.get("severity") or "info").lower()
    labels = [severity]
    custom_labels = finding.get("labels", [])
    if custom_labels:
        labels.extend(custom_labels)

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": finding.get("title", "Untitled Finding"),
            "description": _build_jira_description(finding),
            "issuetype": {"name": "Bug"},
            "priority": {"name": _jira_priority(finding)},
            "labels": labels,
        }
    }

    url = f"{base_url.rstrip('/')}/rest/api/2/issue"
    status, body = _http_request(url, method="POST", data=payload, headers=headers)

    if 200 <= status < 300:
        resp = json.loads(body)
        ticket_id = resp.get("key", "")
        ticket_url = f"{base_url.rstrip('/')}/browse/{ticket_id}"
        return TicketResult(
            ticket_id=ticket_id, url=ticket_url,
            status="created", platform="jira",
        )

    error_msg = body
    try:
        err = json.loads(body)
        error_msg = err.get("errors", {}).get("summary", err.get("errorMessages", [body])[0])
    except (json.JSONDecodeError, IndexError, KeyError):
        pass
    return TicketResult(
        ticket_id="", url="", status="failed",
        platform="jira", error=f"HTTP {status}: {error_msg}",
    )


def create_linear_ticket(finding: dict, config: dict[str, Any]) -> TicketResult:
    """Create a Linear ticket from a finding using the GraphQL API."""
    linear_cfg = config.get("linear", {})
    api_key = linear_cfg.get("api_key", "")
    team_id = linear_cfg.get("team_id", "")

    if not api_key:
        return TicketResult(
            ticket_id="", url="", status="failed",
            platform="linear", error="Missing Linear API key in config",
        )

    priority = {"highest": 1, "high": 2, "medium": 3, "low": 4, "lowest": 5}
    sev_priority = _map_priority(finding)

    query = """
    mutation IssueCreate($input: IssueCreateInput!) {
        issueCreate(input: $input) {
            success
            issue {
                id
                identifier
                url
            }
        }
    }
    """
    variables = {
        "input": {
            "title": finding.get("title", "Untitled Finding"),
            "description": _build_linear_description(finding),
            "priority": priority.get(sev_priority, 3),
        }
    }
    if team_id:
        variables["input"]["teamId"] = team_id

    headers = {
        "Authorization": api_key,
        "Content-Type": "application/json",
    }
    payload = {"query": query, "variables": variables}

    status, body = _http_request(
        "https://api.linear.app/graphql",
        method="POST", data=payload, headers=headers,
    )

    if 200 <= status < 300:
        resp = json.loads(body)
        data = resp.get("data", {}).get("issueCreate", {})
        if data.get("success"):
            issue = data.get("issue", {})
            return TicketResult(
                ticket_id=issue.get("identifier", ""),
                url=issue.get("url", ""),
                status="created",
                platform="linear",
            )
        errors = resp.get("errors", [])
        error_msg = errors[0].get("message", "Unknown error") if errors else "Issue creation failed"
        return TicketResult(
            ticket_id="", url="", status="failed",
            platform="linear", error=error_msg,
        )

    return TicketResult(
        ticket_id="", url="", status="failed",
        platform="linear", error=f"HTTP {status}: {body}",
    )


def update_ticket_status(ticket_id: str, status: str, config: dict[str, Any]) -> bool:
    """Update a Jira or Linear ticket status. Returns True on success."""
    platform = config.get("_platform", "jira")

    if platform == "jira":
        base_url = config.get("jira", {}).get("base_url", config.get("base_url", ""))
        email = config.get("jira", {}).get("email", "")
        token = config.get("jira", {}).get("token", config.get("api_token", ""))

        auth_token = base64.b64encode(f"{email}:{token}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth_token}",
            "Content-Type": "application/json",
        }
        url = f"{base_url.rstrip('/')}/rest/api/2/issue/{ticket_id}/transitions"
        resp_status, body = _http_request(url, method="GET", headers=headers)
        if resp_status != 200:
            return False

        transitions = json.loads(body).get("transitions", [])
        target_id = None
        for t in transitions:
            if t.get("name", "").lower() == status.lower():
                target_id = t["id"]
                break
        if not target_id:
            return False

        url = f"{base_url.rstrip('/')}/rest/api/2/issue/{ticket_id}/transitions"
        resp_status, _ = _http_request(url, method="POST", data={"transition": {"id": target_id}}, headers=headers)
        return 200 <= resp_status < 300

    elif platform == "linear":
        api_key = config.get("linear", {}).get("api_key", "")
        status_map = {"todo": "Todo", "in_progress": "In Progress", "done": "Done", "cancelled": "Cancelled"}
        linear_status = status_map.get(status.lower().replace(" ", "_"), status)

        query = """
        mutation IssueUpdate($input: IssueUpdateInput!) {
            issueUpdate(input: $input) {
                success
            }
        }
        """
        variables = {"input": {"id": ticket_id, "state": linear_status}}
        headers = {"Authorization": api_key, "Content-Type": "application/json"}
        resp_status, body = _http_request(
            "https://api.linear.app/graphql",
            method="POST",
            data={"query": query, "variables": variables},
            headers=headers,
        )
        if 200 <= resp_status < 300:
            resp = json.loads(body)
            return resp.get("data", {}).get("issueUpdate", {}).get("success", False)
        return False

    return False


def add_comment(ticket_id: str, comment: str, config: dict[str, Any]) -> bool:
    """Add a comment to a Jira or Linear ticket. Returns True on success."""
    platform = config.get("_platform", "jira")

    if platform == "jira":
        base_url = config.get("jira", {}).get("base_url", config.get("base_url", ""))
        email = config.get("jira", {}).get("email", "")
        token = config.get("jira", {}).get("token", config.get("api_token", ""))

        auth_token = base64.b64encode(f"{email}:{token}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth_token}",
            "Content-Type": "application/json",
        }
        url = f"{base_url.rstrip('/')}/rest/api/2/issue/{ticket_id}/comment"
        payload = {"body": comment}
        resp_status, _ = _http_request(url, method="POST", data=payload, headers=headers)
        return 200 <= resp_status < 300

    elif platform == "linear":
        api_key = config.get("linear", {}).get("api_key", "")
        query = """
        mutation CommentCreate($input: CommentCreateInput!) {
            commentCreate(input: $input) {
                success
            }
        }
        """
        variables = {"input": {"issueId": ticket_id, "body": comment}}
        headers = {"Authorization": api_key, "Content-Type": "application/json"}
        resp_status, body = _http_request(
            "https://api.linear.app/graphql",
            method="POST",
            data={"query": query, "variables": variables},
            headers=headers,
        )
        if 200 <= resp_status < 300:
            resp = json.loads(body)
            return resp.get("data", {}).get("commentCreate", {}).get("success", False)
        return False

    return False


def list_tickets(project: str, config: dict[str, Any]) -> list[dict[str, str]]:
    """List tickets for a project. Returns list of {ticket_id, summary, status, url}."""
    platform = config.get("_platform", "jira")
    tickets: list[dict[str, str]] = []

    if platform == "jira":
        base_url = config.get("jira", {}).get("base_url", config.get("base_url", ""))
        email = config.get("jira", {}).get("email", "")
        token = config.get("jira", {}).get("token", config.get("api_token", ""))

        auth_token = base64.b64encode(f"{email}:{token}".encode()).decode()
        headers = {"Authorization": f"Basic {auth_token}"}

        jql = f"project = {project} ORDER BY created DESC"
        url = f"{base_url.rstrip('/')}/rest/api/2/search?jql={jql}&maxResults=50&fields=summary,status"
        resp_status, body = _http_request(url, method="GET", headers=headers)
        if resp_status == 200:
            data = json.loads(body)
            for issue in data.get("issues", []):
                fields = issue.get("fields", {})
                tickets.append({
                    "ticket_id": issue.get("key", ""),
                    "summary": fields.get("summary", ""),
                    "status": fields.get("status", {}).get("name", ""),
                    "url": f"{base_url.rstrip('/')}/browse/{issue.get('key', '')}",
                })

    elif platform == "linear":
        api_key = config.get("linear", {}).get("api_key", "")
        team_id = config.get("linear", {}).get("team_id", "")

        query = """
        query($teamId: String!) {
            issues(filter: { team: { id: { eq: $teamId } } }, first: 50) {
                nodes {
                    identifier
                    title
                    state { name }
                    url
                }
            }
        }
        """
        headers = {"Authorization": api_key, "Content-Type": "application/json"}
        variables = {"teamId": team_id}
        resp_status, body = _http_request(
            "https://api.linear.app/graphql",
            method="POST",
            data={"query": query, "variables": variables},
            headers=headers,
        )
        if 200 <= resp_status < 300:
            nodes = json.loads(body).get("data", {}).get("issues", {}).get("nodes", [])
            for node in nodes:
                tickets.append({
                    "ticket_id": node.get("identifier", ""),
                    "summary": node.get("title", ""),
                    "status": node.get("state", {}).get("name", ""),
                    "url": node.get("url", ""),
                })

    return tickets
