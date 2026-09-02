"""Issue definitions endpoint.

Surfaces ``redveil.knowledge.vuln_descriptions.VULN_DB`` as a flat list of
canonical entries so the UI's "Issue defs" tab can show every issue the
framework knows about, plus a short summary.

We dedupe by canonical entry identity because many ``(check_id, kind)``
keys in VULN_DB map to the same VulnEntry dict (e.g. ``missing`` and
``x-frame-options-missing`` both point at MISSING_X_FRAME_OPTIONS).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter

from redveil_api.schemas import IssueDefinitionOut

log = logging.getLogger(__name__)

router = APIRouter()


def _severity_for_check(check_id: str) -> str:
    """Heuristic severity mapping based on the check category.

    The knowledge base does not store a severity per-entry; the severity is
    decided by the check that produced the finding. We approximate based on
    the check_id so the Issue Defs tab has a meaningful color for each row.
    """
    high_checks = {
        "sqli-time-based",
        "command-injection",
        "ssrf",
        "bola-idor",
        "bfla",
        "bfla-behavior",
        "mass-assignment",
    }
    medium_checks = {
        "xss-reflected",
        "open-redirect-indicator",
        "session-cookie",
        "session-invalidation",
        "path-traversal",
        "graphql",
        "cors-policy",
    }
    if check_id in high_checks:
        return "high"
    if check_id in medium_checks:
        return "medium"
    return "info"


def _name_for_entry(entry_key: str, entry: dict) -> str:
    """Derive a human-friendly issue name from the entry key or summary."""
    return entry_key.replace("_", " ").title()


def _cwe_for_check(check_id: str) -> list[str]:
    """Best-effort CWE mapping per check_id (for the UI's reference column)."""
    cwe_map: dict[str, list[str]] = {
        "xss-reflected": ["CWE-79"],
        "sqli-time-based": ["CWE-89"],
        "ssrf": ["CWE-918"],
        "command-injection": ["CWE-78"],
        "path-traversal": ["CWE-22"],
        "bola-idor": ["CWE-639", "CWE-285"],
        "bfla": ["CWE-285"],
        "bfla-behavior": ["CWE-285"],
        "graphql": ["CWE-200"],
        "session-cookie": ["CWE-1004", "CWE-614", "CWE-384"],
        "session-invalidation": ["CWE-613"],
        "mass-assignment": ["CWE-915"],
        "open-redirect-indicator": ["CWE-601"],
        "http-methods": ["CWE-749", "CWE-200"],
        "cors-policy": ["CWE-942", "CWE-346"],
        "security-headers": ["CWE-693"],
        "information-disclosure": ["CWE-200"],
        "source-map-exposure": ["CWE-540"],
    }
    return cwe_map.get(check_id, [])


def _owasp_for_check(check_id: str) -> list[str]:
    """Best-effort OWASP Top-10 mapping per check_id."""
    owasp_map: dict[str, list[str]] = {
        "xss-reflected": ["A03:2021"],
        "sqli-time-based": ["A03:2021"],
        "ssrf": ["A10:2021"],
        "command-injection": ["A03:2021"],
        "path-traversal": ["A01:2021"],
        "bola-idor": ["A01:2021"],
        "bfla": ["A01:2021"],
        "bfla-behavior": ["A01:2021"],
        "graphql": ["A05:2021"],
        "session-cookie": ["A07:2021"],
        "session-invalidation": ["A07:2021"],
        "mass-assignment": ["A08:2021"],
        "open-redirect-indicator": ["A01:2021"],
        "http-methods": ["A05:2021"],
        "cors-policy": ["A05:2021"],
        "security-headers": ["A05:2021"],
        "information-disclosure": ["A05:2021"],
        "source-map-exposure": ["A05:2021"],
    }
    return owasp_map.get(check_id, [])


@router.get("/issue-definitions", response_model=list[IssueDefinitionOut])
async def list_issue_definitions() -> list[IssueDefinitionOut]:
    """Return the deduplicated list of issue definitions from the knowledge base."""
    try:
        from redveil.knowledge.vuln_descriptions import VULN_DB
    except Exception as e:  # noqa: BLE001
        log.warning("vuln_descriptions import failed: %s", e)
        return []

    # Group aliases by canonical entry identity (id() of the dict object).
    canonical: dict[int, tuple[str, dict]] = {}
    for (check_id, _kind), entry in VULN_DB.items():
        if not isinstance(entry, dict):
            continue
        key = id(entry)
        # Prefer the first check_id we encounter for this canonical entry.
        if key not in canonical:
            canonical[key] = (check_id, entry)

    out: list[IssueDefinitionOut] = []
    for check_id, entry in canonical.values():
        # Derive a stable id from the entry's first summary sentence so the
        # UI can key list items without depending on dict identity.
        summary = entry.get("summary") or ""
        entry_id = (check_id or "issue").replace("-", "_").upper()
        out.append(
            IssueDefinitionOut(
                id=entry_id,
                name=_name_for_entry(entry_id, entry),
                check_id=check_id,
                severity=_severity_for_check(check_id),
                summary=summary,
                cwe=_cwe_for_check(check_id),
                owasp=_owasp_for_check(check_id),
            )
        )

    out.sort(key=lambda i: (i.severity != "high", i.severity != "medium", i.id))
    return out