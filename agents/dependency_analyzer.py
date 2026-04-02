"""
Dependency Analysis Agent
─────────────────────────
Uses Mistral (via Ollama) to decide:
  1. Whether the version upgrade involves breaking API changes.
  2. Which functions are affected.
  3. Whether a full advisory track (AST scan + SE + DA) is needed.
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

_SYSTEM_PROMPT = """You are a supply-chain security expert specialising in npm dependency vulnerabilities.

Given a Snyk vulnerability report, return a JSON object (no prose, no markdown fences) with:

{
  "breaking_changes": <bool>,        // does upgrading introduce breaking API changes?
  "advisory_track": <bool>,          // true = needs code audit; false = manifest bump is enough
  "semver_safe": <bool>,             // true = patch/minor upgrade (semver-compatible)
  "affected_functions": [<string>],  // function names that are vulnerable, e.g. "_.merge"
  "reasoning": <string>,             // one paragraph explanation
  "risk_level": "critical|high|medium|low",
  "upgrade_confidence": "high|medium|low"
}

Rules:
- advisory_track = true  when severity is high/critical OR when the vuln involves functions that
  accept user-controlled data (merge, defaultsDeep, zipObjectDeep, etc.)
- advisory_track = false when it is a pure patch and no affected call sites need changing.
"""


def _extract_json(text: str) -> dict:
    text = text.strip()
    # Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Strip markdown fences
    m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # Extract first {...} block
    m = re.search(r"\{[\s\S]*\}", text)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return {}


def dependency_analysis_node(state: AgentState) -> dict:
    vuln = state["vulnerability"]
    logger.info("[DependencyAnalyzer] Analysing %s (%s)", vuln["package_name"], vuln["id"])

    llm = ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL, temperature=0)

    human_msg = f"""Analyse this Snyk vulnerability:

Package       : {vuln["package_name"]}
Affected ver  : {vuln["affected_version"]}
Fixed ver     : {vuln["fixed_version"]}
Severity      : {vuln["severity"]}
CVEs          : {", ".join(vuln["cve_ids"]) or "N/A"}
Title         : {vuln["title"]}
Description   : {vuln["description"]}
Known affected functions (Snyk): {", ".join(vuln["affected_functions"]) or "none listed"}

Questions to answer:
1. Is upgrading from {vuln["affected_version"]} to {vuln["fixed_version"]} semver-compatible?
2. Are there known breaking API changes in the fixed version?
3. Is a full codebase audit required (advisory_track)?
4. Which specific functions/methods are vulnerable?
"""

    try:
        response = llm.invoke(
            [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=human_msg)]
        )
        analysis = _extract_json(response.content)
    except Exception as exc:
        logger.error("[DependencyAnalyzer] LLM call failed: %s", exc)
        analysis = {}

    breaking_changes: bool = analysis.get("breaking_changes", False)
    advisory_track: bool = analysis.get(
        "advisory_track", vuln["severity"] in ("high", "critical")
    )
    affected_functions: list[str] = analysis.get(
        "affected_functions", vuln["affected_functions"]
    )

    log_msgs = list(state.get("messages", []))
    log_msgs.append(
        f"[DependencyAnalyzer] breaking={breaking_changes} | advisory={advisory_track} "
        f"| risk={analysis.get('risk_level', 'unknown')} "
        f"| confidence={analysis.get('upgrade_confidence', 'unknown')}"
    )

    logger.info(log_msgs[-1])

    return {
        "breaking_changes": breaking_changes,
        "advisory_track": advisory_track,
        "breaking_change_analysis": analysis.get("reasoning", ""),
        "semver_analysis": str(analysis.get("semver_safe", True)),
        "affected_functions": affected_functions,
        "current_step": "dependency_analysed",
        "messages": log_msgs,
    }
