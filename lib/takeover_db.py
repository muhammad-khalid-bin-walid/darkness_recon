"""
lib/takeover_db.py — Subdomain takeover fingerprint database (plan Phase 31)
Per-provider fingerprints for AWS, Azure, Heroku, GitHub Pages, etc.
"""
from __future__ import annotations

import json
from pathlib import Path

FINGERPRINT_DB: list[dict] = [
    {"provider": "aws_s3",        "cname_pattern": "s3.amazonaws.com",            "body_pattern": "NoSuchBucket",            "takeover_possible": True},
    {"provider": "aws_elb",       "cname_pattern": "elasticbeanstalk.com",         "body_pattern": "NoSuchApplication",       "takeover_possible": True},
    {"provider": "azure",         "cname_pattern": "azurewebsites.net",            "body_pattern": "404 Web Site not found",  "takeover_possible": True},
    {"provider": "azure_cdn",     "cname_pattern": "azureedge.net",                "body_pattern": "404",                     "takeover_possible": True},
    {"provider": "heroku",        "cname_pattern": "herokudns.com",                "body_pattern": "No such app",             "takeover_possible": True},
    {"provider": "heroku_ssl",    "cname_pattern": "herokussl.com",                "body_pattern": "No such app",             "takeover_possible": True},
    {"provider": "github_pages",  "cname_pattern": "github.io",                   "body_pattern": "There isn't a GitHub Pages site here", "takeover_possible": True},
    {"provider": "fastly",        "cname_pattern": "fastly.net",                  "body_pattern": "Fastly error: unknown domain", "takeover_possible": True},
    {"provider": "netlify",       "cname_pattern": "netlify.app",                 "body_pattern": "Not Found",               "takeover_possible": True},
    {"provider": "surge_sh",      "cname_pattern": "surge.sh",                    "body_pattern": "project not found",       "takeover_possible": True},
    {"provider": "zendesk",       "cname_pattern": "zendesk.com",                 "body_pattern": "Help Center Closed",      "takeover_possible": True},
    {"provider": "desk_com",      "cname_pattern": "desk.com",                    "body_pattern": "Please try again",        "takeover_possible": True},
    {"provider": "wpengine",      "cname_pattern": "wpengine.com",                "body_pattern": "The site you were looking for", "takeover_possible": True},
    {"provider": "bitbucket",     "cname_pattern": "bitbucket.io",                "body_pattern": "Repository not found",   "takeover_possible": True},
    {"provider": "cloudfront",    "cname_pattern": "cloudfront.net",              "body_pattern": "Bad request",             "takeover_possible": False},
    {"provider": "shopify",       "cname_pattern": "myshopify.com",               "body_pattern": "Sorry, this shop is currently unavailable", "takeover_possible": True},
    {"provider": "cargo",         "cname_pattern": "cargocollective.com",          "body_pattern": "404 Not Found",           "takeover_possible": True},
    {"provider": "teamwork",      "cname_pattern": "teamwork.com",                "body_pattern": "Oops - We didn't find your site", "takeover_possible": True},
    {"provider": "strikingly",    "cname_pattern": "strikingly.com",              "body_pattern": "But if you're looking",   "takeover_possible": True},
    {"provider": "helpjuice",     "cname_pattern": "helpjuice.com",               "body_pattern": "We could not find what you're looking for", "takeover_possible": True},
    {"provider": "intercom",      "cname_pattern": "custom.intercom.help",         "body_pattern": "This page is reserved",  "takeover_possible": True},
    {"provider": "pingdom",       "cname_pattern": "stats.pingdom.com",            "body_pattern": "This public report page has not been activated", "takeover_possible": True},
    {"provider": "readme_io",     "cname_pattern": "readme.io",                   "body_pattern": "Project doesnt exist",   "takeover_possible": True},
    {"provider": "hubspot",       "cname_pattern": "hubspot.net",                 "body_pattern": "Domain not found",       "takeover_possible": True},
    {"provider": "ghost",         "cname_pattern": "ghost.io",                    "body_pattern": "The thing you were looking for is no longer here", "takeover_possible": True},
]


def get_all_fingerprints() -> list[dict]:
    return list(FINGERPRINT_DB)


def get_fingerprints_for_cname(cname: str) -> list[dict]:
    cname_lower = cname.lower().rstrip(".")
    return [fp for fp in FINGERPRINT_DB if cname_lower.endswith(fp["cname_pattern"])]


def check_body_for_takeover(body: str, cname: str) -> dict | None:
    """Check if a response body matches a takeover fingerprint for the given CNAME."""
    matches = get_fingerprints_for_cname(cname)
    for fp in matches:
        if fp["body_pattern"].lower() in body.lower():
            return fp
    return None


def export_to_file(path: str) -> None:
    Path(path).write_text(json.dumps(FINGERPRINT_DB, indent=2), encoding="utf-8")
