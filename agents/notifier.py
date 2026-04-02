"""
Notifier Node
──────────────
Prints a structured summary to stdout and optionally sends a Slack message.
In a production system this would also tag the PR assignee via GitHub API.
"""
from __future__ import annotations

import logging

import httpx

from config import SLACK_WEBHOOK_URL
from state import AgentState

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


def notifier_node(state: AgentState) -> dict:
    vuln = state["vulnerability"]
    pr_url = state.get("pr_url", "N/A")
    pr_branch = state.get("pr_branch", "N/A")
    usage_sites = state.get("usage_sites", [])
    proposed_fixes = state.get("proposed_fixes", [])
    emoji = _SEVERITY_EMOJI.get(vuln["severity"].lower(), "⚪")

    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║         SNYK AUTO-REMEDIATION  —  PIPELINE COMPLETE          ║
╠══════════════════════════════════════════════════════════════╣
║  {emoji}  Severity : {vuln["severity"].upper():<52}║
║  📦  Package  : {vuln["package_name"]} {vuln["affected_version"]} → {vuln["fixed_version"]:<38}║
║  🔑  CVEs     : {", ".join(vuln["cve_ids"]) or "N/A":<52}║
║  🌿  Branch   : {pr_branch:<52}║
║  🔗  PR       : {pr_url:<52}║
╠══════════════════════════════════════════════════════════════╣
║  📍 Usage sites  : {len(usage_sites):>3}   ({sum(1 for s in usage_sites if s["has_user_input"])} with user-input risk)       ║
║  🛠  Code fixes  : {len(proposed_fixes):>3}   (inline suggestions in PR body)        ║
║                                                              ║
║  ➡  Review the draft PR, apply/modify the code suggestions,  ║
║     then mark ready for review and merge.                    ║
╚══════════════════════════════════════════════════════════════╝"""

    print(banner)
    logger.info("[Notifier] Pipeline complete. PR: %s", pr_url)

    # ── Optional Slack notification ──────────────────────────────────────────
    if SLACK_WEBHOOK_URL:
        payload = {
            "text": f"{emoji} *Snyk Auto-Remediation* — draft PR ready",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"{emoji} *{vuln['title']}*\n"
                            f"Package: `{vuln['package_name']}` "
                            f"`{vuln['affected_version']}` → `{vuln['fixed_version']}`\n"
                            f"Severity: *{vuln['severity'].upper()}* | "
                            f"CVEs: {', '.join(vuln['cve_ids']) or 'N/A'}"
                        ),
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"Found *{len(usage_sites)}* usage sites, "
                            f"*{len(proposed_fixes)}* code suggestions.\n"
                            f"<{pr_url}|View Draft PR →>"
                        ),
                    },
                },
            ],
        }
        try:
            httpx.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
            logger.info("[Notifier] Slack notification sent")
        except Exception as exc:
            logger.warning("[Notifier] Slack notification failed: %s", exc)

    log_msgs = list(state.get("messages", []))
    log_msgs.append(f"[Notifier] Done. PR: {pr_url}")

    return {
        "current_step": "completed",
        "messages": log_msgs,
    }
