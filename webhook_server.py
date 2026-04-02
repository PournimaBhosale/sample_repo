"""
FastAPI Webhook Server
──────────────────────
Listens for incoming Snyk webhook POST requests, parses the payload, and
dispatches each new vulnerability through the LangGraph remediation pipeline
in a background thread (non-blocking).

Endpoints:
  POST /webhook  — Snyk alert receiver (HMAC-SHA256 verified)
  GET  /health   — Liveness probe
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from config import REPO_LOCAL_PATH, WEBHOOK_SECRET
from graph import app as langgraph_app
from state import AgentState, SnykVulnerability

logger = logging.getLogger(__name__)
_executor = ThreadPoolExecutor(max_workers=4)


# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def _lifespan(app: FastAPI):
    logger.info("Snyk Auto-Remediation webhook server started — waiting for alerts")
    yield
    _executor.shutdown(wait=False)
    logger.info("Server shutting down")


# ── FastAPI app ────────────────────────────────────────────────────────────────

server = FastAPI(
    title="Snyk Auto-Remediation Webhook",
    description=(
        "Receives Snyk vulnerability alerts and orchestrates AI-driven "
        "fix PRs using LangGraph + Ollama (Mistral)."
    ),
    version="1.0.0",
    lifespan=_lifespan,
)


# ── Security helpers ──────────────────────────────────────────────────────────


def _verify_signature(body: bytes, header_value: str | None) -> bool:
    """Verify Snyk HMAC-SHA256 webhook signature."""
    if not WEBHOOK_SECRET or WEBHOOK_SECRET == "dev-secret":
        return True   # Signature check disabled in dev mode
    if not header_value:
        return False
    mac = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256)
    expected = mac.hexdigest()
    received = header_value.replace("sha256=", "")
    return hmac.compare_digest(expected, received)


# ── Payload parsing ───────────────────────────────────────────────────────────


def _parse_snyk_payload(payload: dict) -> list[SnykVulnerability]:
    vulns: list[SnykVulnerability] = []
    for issue in payload.get("newIssues", []):
        issue_data = issue.get("issueData", {})
        fixed_in: list[str] = issue.get("fixedIn") or []
        versions: list[str] = issue.get("pkgVersions") or []
        vuln = SnykVulnerability(
            id=issue.get("id") or issue_data.get("id", "unknown"),
            title=issue_data.get("title", "Unknown Vulnerability"),
            severity=issue_data.get("severity", "medium"),
            package_name=issue.get("pkgName", "unknown"),
            affected_version=versions[0] if versions else "unknown",
            fixed_version=fixed_in[0] if fixed_in else "unknown",
            description=issue_data.get("description", ""),
            cve_ids=issue_data.get("identifiers", {}).get("CVE", []),
            affected_functions=issue_data.get("functions", []),
        )
        vulns.append(vuln)
    return vulns


# ── Pipeline runner ───────────────────────────────────────────────────────────


def _run_pipeline(vuln: SnykVulnerability, repo_path: str) -> None:
    """Synchronous pipeline entry — executed in thread pool."""
    initial_state: AgentState = {
        "vulnerability": vuln,
        "repo_path": repo_path,
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
    try:
        final = langgraph_app.invoke(initial_state)
        logger.info(
            "[Pipeline] Done: %s → %s", vuln["package_name"], final.get("pr_url", "no PR")
        )
    except Exception:
        logger.error("[Pipeline] Error for %s:\n%s", vuln["id"], traceback.format_exc())


# ── Routes ────────────────────────────────────────────────────────────────────


@server.post("/webhook", status_code=202)
async def snyk_webhook(request: Request) -> JSONResponse:
    body = await request.body()

    # Verify signature (Snyk sends X-Hub-Signature-256 or X-Snyk-Signature)
    sig = request.headers.get("X-Hub-Signature-256") or request.headers.get(
        "X-Snyk-Signature"
    )
    if not _verify_signature(body, sig):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc

    vulns = _parse_snyk_payload(payload)
    if not vulns:
        return JSONResponse({"status": "ok", "message": "No new issues to process"})

    loop = asyncio.get_running_loop()
    for vuln in vulns:
        loop.run_in_executor(_executor, _run_pipeline, vuln, REPO_LOCAL_PATH)
        logger.info("[Webhook] Queued remediation for %s (%s)", vuln["package_name"], vuln["id"])

    return JSONResponse(
        {
            "status": "accepted",
            "queued": len(vulns),
            "ids": [v["id"] for v in vulns],
        },
        status_code=202,
    )


@server.get("/health")
async def health() -> dict:
    return {"status": "healthy", "service": "snyk-auto-remediation"}
