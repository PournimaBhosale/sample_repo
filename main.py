#!/usr/bin/env python3
"""
Snyk Auto-Remediation Bot — Entry Point
────────────────────────────────────────
Usage:
  python main.py serve           # Start the FastAPI webhook server (port 8080)
  python main.py mock            # Run against the bundled mock Snyk alert
  python main.py mock --alert fixtures/snyk_alert.json --repo /path/to/repo
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-25s │ %(levelname)-8s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("main")


# ── Commands ──────────────────────────────────────────────────────────────────


def cmd_serve() -> None:
    import uvicorn
    from webhook_server import server

    logger.info("Starting webhook server on http://0.0.0.0:8080")
    uvicorn.run(server, host="0.0.0.0", port=8080, log_level="info")


def cmd_mock(alert_path: str, repo_path: str) -> None:
    from graph import app as langgraph_app
    from state import AgentState, SnykVulnerability
    from webhook_server import _parse_snyk_payload

    logger.info("Loading mock alert from %s", alert_path)
    try:
        with open(alert_path) as fh:
            payload = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.error("Cannot read alert file: %s", exc)
        sys.exit(1)

    vulns = _parse_snyk_payload(payload)
    if not vulns:
        logger.error("No vulnerabilities found in %s", alert_path)
        sys.exit(1)

    repo_abs = os.path.abspath(repo_path)
    logger.info("Repository path: %s", repo_abs)

    for vuln in vulns:
        print(f"\n{'═'*65}")
        print(
            f"  Processing: {vuln['package_name']} "
            f"({vuln['severity'].upper()}) — {vuln['id']}"
        )
        print(f"{'═'*65}\n")

        initial_state: AgentState = {
            "vulnerability": vuln,
            "repo_path": repo_abs,
            "breaking_changes": False,
            "breaking_change_analysis": "",
            "advisory_track": False,
            "semver_analysis": "",
            "affected_functions": list(vuln["affected_functions"]),
            "usage_sites": [],
            "proposed_fixes": [],
            "manifest_changes": {},
            "review_approved": False,
            "review_feedback": "",
            "review_iterations": 0,
            "risk_assessment": "",
            "pr_url": "",
            "pr_number": 0,
            "pr_branch": "",
            "error": None,
            "current_step": "started",
            "messages": [],
        }

        final_state = langgraph_app.invoke(initial_state)

        print("\n── Audit trail ──────────────────────────────────────────────")
        for msg in final_state.get("messages", []):
            print(f"  {msg}")
        print("─────────────────────────────────────────────────────────────\n")


# ── CLI ───────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Snyk Auto-Remediation Bot (LangGraph + Ollama/Mistral)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # serve
    sub.add_parser("serve", help="Start the FastAPI webhook server (port 8080)")

    # mock
    mock_p = sub.add_parser("mock", help="Run with a local mock Snyk alert JSON")
    mock_p.add_argument(
        "--alert",
        default="fixtures/snyk_alert.json",
        help="Path to mock Snyk alert JSON (default: fixtures/snyk_alert.json)",
    )
    mock_p.add_argument(
        "--repo",
        default=os.getenv("REPO_LOCAL_PATH", "fixtures/sample_repo"),
        help="Path to the repository to scan and patch",
    )

    args = parser.parse_args()

    if args.command == "serve":
        cmd_serve()
    elif args.command == "mock":
        cmd_mock(args.alert, args.repo)


if __name__ == "__main__":
    main()
