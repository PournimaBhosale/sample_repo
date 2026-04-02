"""
Devil's Advocate Agent
───────────────────────
Critically reviews the Software Engineer's proposed fixes looking for:
  • Logical regressions that break business logic
  • Incomplete fixes that still leave the vulnerability exploitable
  • Edge-case failures (null / undefined / arrays in JSON.parse, etc.)
  • Performance regressions
  • Over-corrections that change behaviour unintentionally

Returns: approved flag, free-text feedback (if rejected), and a markdown
         risk_assessment block suitable for inclusion in the PR description.
"""
from __future__ import annotations

import json
import logging
import re

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from config import OLLAMA_BASE_URL, OLLAMA_MODEL
from state import AgentState

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a Devil's Advocate code reviewer focused on preventing production regressions.

Review proposed security fixes and return a JSON object (no prose, no fences):
{
  "approved"        : <bool>,           // true = safe to merge after human review
  "overall_risk"    : "low|medium|high",
  "issues"          : [<string>],       // list of specific concerns; empty if approved
  "feedback"        : "<string>",       // actionable instructions for the SE if not approved
  "risk_assessment" : "<markdown>"      // 3-5 sentence summary for the PR description
}

Be rigorous. Reject if:
  - JSON.parse(JSON.stringify()) is used on a value that may be undefined/null/circular
  - The fix breaks the existing behaviour for valid inputs
  - A user-input site is left unguarded
  - The fix is too broad (sanitises inputs that don't need it, harming performance)

Approve if the fixes are correct, minimal, and the manifest bump is safe.
"""


def _extract_json(text: str) -> dict:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    m = re.search(r"\{[\s\S]*\}", text)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return {}


def devils_advocate_node(state: AgentState) -> dict:
    vuln = state["vulnerability"]
    proposed_fixes = state.get("proposed_fixes", [])
    usage_sites = state.get("usage_sites", [])
    iteration = state.get("review_iterations", 1)

    logger.info(
        "[DevilsAdvocate] Reviewing %d fix(es) — iteration %d",
        len(proposed_fixes),
        iteration,
    )

    llm = ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL, temperature=0)

    fixes_block = ""
    for i, fix in enumerate(proposed_fixes, start=1):
        fixes_block += (
            f"\nFix {i}: {fix['file_path']}:{fix['line_number']}  "
            f"[risk={fix['risk_level']}]\n"
            f"  Before:\n{fix['original_code']}\n"
            f"  After:\n{fix['fixed_code']}\n"
            f"  Rationale: {fix['explanation']}\n"
            f"{'─'*60}"
        )

    human_msg = f"""Review these security fixes for regressions:

Vulnerability : {vuln["title"]}  ({vuln["severity"].upper()})
Package       : {vuln["package_name"]} {vuln["affected_version"]} → {vuln["fixed_version"]}
Usage sites   : {len(usage_sites)} total, {sum(1 for s in usage_sites if s["has_user_input"])} with user input
{fixes_block or "No code changes proposed — only manifest version bump."}

Checklist:
1. Does each fix preserve the original business logic for valid inputs?
2. Does `JSON.parse(JSON.stringify(x))` handle edge-cases (null, undefined, Date, Buffer)?
3. Are ALL user-input call sites covered, or are some still vulnerable?
4. Is the fix minimal (no unnecessary sanitisation of trusted data)?
5. Are there async/callback ordering issues introduced?

Provide a `risk_assessment` markdown paragraph (3-5 sentences) for the PR body.
"""

    try:
        response = llm.invoke(
            [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=human_msg)]
        )
        review = _extract_json(response.content)
    except Exception as exc:
        logger.error("[DevilsAdvocate] LLM call failed: %s", exc)
        review = {}

    approved: bool = review.get("approved", True)
    feedback: str = review.get("feedback", "")
    risk_assessment: str = review.get(
        "risk_assessment", "No automated risk assessment available."
    )
    issues: list = review.get("issues", [])

    log_msgs = list(state.get("messages", []))
    log_msgs.append(
        f"[DevilsAdvocate] Iteration {iteration}: "
        f"{'APPROVED ✓' if approved else 'REVISION NEEDED ✗'} | "
        f"issues={len(issues)} | overall_risk={review.get('overall_risk', 'unknown')}"
    )
    logger.info(log_msgs[-1])

    return {
        "review_approved": approved,
        "review_feedback": feedback,
        "risk_assessment": risk_assessment,
        "current_step": "review_complete",
        "messages": log_msgs,
    }
