from __future__ import annotations
from typing import TypedDict, List, Optional


class SnykVulnerability(TypedDict):
    id: str
    title: str
    severity: str                   # critical | high | medium | low
    package_name: str
    affected_version: str
    fixed_version: str
    description: str
    cve_ids: List[str]
    affected_functions: List[str]   # e.g. ["_.merge", "_.defaultsDeep"]
    is_transitive: bool             # True if vuln is in a transitive dep
    transitive_chain: List[str]     # e.g. ["mkdirp", "minimist"]
    parent_package: str             # direct dep that brings in the vuln dep


class UsageSite(TypedDict):
    file_path: str
    line_number: int
    snippet: str                    # surrounding lines of code
    function_called: str            # e.g. "_.merge"
    has_user_input: bool            # True if req.body / user data detected nearby


class ProposedFix(TypedDict):
    file_path: str
    line_number: int
    original_code: str
    fixed_code: str
    explanation: str
    risk_level: str                 # low | medium | high


class AgentState(TypedDict):
    # ── Input ─────────────────────────────────────────────────────────────────
    vulnerability: SnykVulnerability
    repo_path: str

    # ── Dependency Analysis node ───────────────────────────────────────────────
    breaking_changes: bool
    breaking_change_analysis: str
    advisory_track: bool            # True  → full AST+SE+DA track
    semver_analysis: str
    affected_functions: List[str]

    # ── AST Context Engine node ───────────────────────────────────────────────
    usage_sites: List[UsageSite]

    # ── Software Engineer node ────────────────────────────────────────────────
    proposed_fixes: List[ProposedFix]
    manifest_changes: dict          # {"file": "package.json", "package": ..., ...}

    # ── Devil's Advocate node ─────────────────────────────────────────────────
    review_approved: bool
    review_feedback: str
    review_iterations: int
    risk_assessment: str            # Markdown section for PR description

    # ── PR Creator node ───────────────────────────────────────────────────────
    pr_url: str
    pr_number: int
    pr_branch: str

    # ── Meta ─────────────────────────────────────────────────────────────────
    error: Optional[str]
    current_step: str
    messages: List[str]             # audit trail across all nodes
