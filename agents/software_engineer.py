"""
Software Engineer Agent
────────────────────────
Given the vulnerability details and usage sites produced by the AST Context
Engine, asks Mistral (via Ollama) to draft specific code fixes for each
call site where user-controlled input reaches a vulnerable function.

If a previous round was rejected by the Devil's Advocate, the feedback is
included in the prompt so the agent can incorporate the critique.
"""
from __future__ import annotations

import json
import logging
import re
from typing import List

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from config import OLLAMA_BASE_URL, OLLAMA_MODEL
from state import AgentState, ProposedFix

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a senior security engineer drafting minimal, safe code fixes.

For each provided call site:
1. Determine whether user-controlled data reaches the vulnerable function.
2. If YES  → produce a targeted fix (e.g. sanitise input before the call).
3. If NO   → explicitly state that a manifest-only bump is sufficient for this site.

Return ONLY a JSON array, no prose, no markdown fences. Each element:
{
  "file_path"     : "<relative path>",
  "line_number"   : <int>,
  "original_code" : "<exact line(s) as-is>",
  "fixed_code"    : "<replacement line(s)>",
  "explanation"   : "<1-2 sentence rationale>",
  "risk_level"    : "low|medium|high"
}

Preferred fix patterns for prototype-pollution (lodash):
  • JSON round-trip: `JSON.parse(JSON.stringify(userInput))` before merge
  • Object.create(null) base  + shallow spread  instead of deep merge
  • Input validation / allowlist before merge
Keep fixes minimal — preserve the surrounding business logic exactly.
"""


def _extract_fixes(text: str) -> list:
    text = text.strip()
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        pass
    m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if m:
        try:
            parsed = json.loads(m.group(1))
            return parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            pass
    m = re.search(r"\[[\s\S]*\]", text)
    if m:
        try:
            parsed = json.loads(m.group(0))
            return parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            pass
    return []


def software_engineer_node(state: AgentState) -> dict:
    vuln = state["vulnerability"]
    usage_sites = state.get("usage_sites", [])
    review_feedback = state.get("review_feedback", "")
    iteration = state.get("review_iterations", 0)

    logger.info("[SoftwareEngineer] Drafting fixes — iteration %d", iteration + 1)

    llm = ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.1)

    # Build usage-site block (cap at 10 to stay within context window)
    sites_block = ""
    for i, site in enumerate(usage_sites[:10], start=1):
        sites_block += (
            f"\nSite {i}: {site['file_path']}:{site['line_number']}\n"
            f"  Function : {site['function_called']}\n"
            f"  User input nearby: {'YES ⚠' if site['has_user_input'] else 'no'}\n"
            f"  Code:\n{site['snippet']}\n"
            f"{'─'*60}"
        )

    feedback_block = (
        f"\n\nPrevious review feedback — address every point:\n{review_feedback}"
        if review_feedback
        else ""
    )

    human_msg = f"""Fix this vulnerability:

Package       : {vuln["package_name"]} {vuln["affected_version"]} → {vuln["fixed_version"]}
Title         : {vuln["title"]}
CVEs          : {", ".join(vuln["cve_ids"]) or "N/A"}
Description   : {vuln["description"]}
Affected fns  : {", ".join(state.get("affected_functions") or vuln["affected_functions"])}

─── Usage Sites ─────────────────────────────────────────────
{sites_block or "No specific call sites found. Provide general guidance only."}
{feedback_block}

Only generate a fix object for sites where user-controlled input is present.
For safe sites (no user input) set fixed_code = original_code and note that
manifest upgrade alone is sufficient.
"""

    try:
        response = llm.invoke(
            [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=human_msg)]
        )
        raw_fixes = _extract_fixes(response.content)
    except Exception as exc:
        logger.error("[SoftwareEngineer] LLM call failed: %s", exc)
        raw_fixes = []

    proposed_fixes: List[ProposedFix] = []
    for fix in raw_fixes:
        if isinstance(fix, dict) and "file_path" in fix:
            proposed_fixes.append(
                ProposedFix(
                    file_path=fix.get("file_path", ""),
                    line_number=int(fix.get("line_number", 0)),
                    original_code=fix.get("original_code", ""),
                    fixed_code=fix.get("fixed_code", ""),
                    explanation=fix.get("explanation", ""),
                    risk_level=fix.get("risk_level", "medium"),
                )
            )

    manifest_changes = {
        "file": "package.json",
        "package": vuln["package_name"],
        "from_version": vuln["affected_version"],
        "to_version": vuln["fixed_version"],
    }

    log_msgs = list(state.get("messages", []))
    log_msgs.append(
        f"[SoftwareEngineer] Iteration {iteration + 1}: "
        f"{len(proposed_fixes)} fix(es) drafted"
    )
    logger.info(log_msgs[-1])

    return {
        "proposed_fixes": proposed_fixes,
        "manifest_changes": manifest_changes,
        "review_iterations": iteration + 1,
        "current_step": "fixes_drafted",
        "messages": log_msgs,
    }
