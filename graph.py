"""
LangGraph Orchestration
────────────────────────
Wires all agent nodes into the remediation pipeline.

Flow:
  START
    └─► dependency_analyzer
          ├─[advisory_track=True]──► ast_context ──► software_engineer ──► devils_advocate
          │                                                                     ├─[approved]──►
          │                                                    ◄──[revise]──────┘
          └─[advisory_track=False]──────────────────────────────────────────────────────────►
                                                                                           pr_creator
                                                                                               └──► notifier ──► END
"""
from __future__ import annotations

import logging

from langgraph.graph import END, START, StateGraph

from agents.ast_context import ast_context_node
from agents.dependency_analyzer import dependency_analysis_node
from agents.devils_advocate import devils_advocate_node
from agents.notifier import notifier_node
from agents.pr_creator import pr_creator_node
from agents.software_engineer import software_engineer_node
from config import MAX_REVIEW_ITERATIONS
from state import AgentState

logger = logging.getLogger(__name__)


# ── Routing functions ────────────────────────────────────────────────────────


def _route_after_analysis(state: AgentState) -> str:
    """Choose between the full advisory track or a direct manifest-only fix."""
    if state.get("advisory_track", False):
        logger.info("[Graph] → Advisory track (AST + SE + DA)")
        return "advisory"
    logger.info("[Graph] → Direct fix (manifest bump only)")
    return "direct"


def _route_after_review(state: AgentState) -> str:
    """After Devil's Advocate review: proceed to PR or loop back to SE."""
    iteration = state.get("review_iterations", 1)
    approved = state.get("review_approved", True)

    if approved:
        logger.info("[Graph] Review approved at iteration %d → PR", iteration)
        return "approved"

    if iteration >= MAX_REVIEW_ITERATIONS:
        logger.info(
            "[Graph] Max iterations (%d) reached → forcing PR creation", MAX_REVIEW_ITERATIONS
        )
        return "approved"

    logger.info("[Graph] Revision needed at iteration %d → back to SE", iteration)
    return "revise"


# ── Graph factory ────────────────────────────────────────────────────────────


def create_graph() -> StateGraph:
    workflow = StateGraph(AgentState)

    # Register nodes
    workflow.add_node("dependency_analyzer", dependency_analysis_node)
    workflow.add_node("ast_context", ast_context_node)
    workflow.add_node("software_engineer", software_engineer_node)
    workflow.add_node("devils_advocate", devils_advocate_node)
    workflow.add_node("pr_creator", pr_creator_node)
    workflow.add_node("notifier", notifier_node)

    # Entry point
    workflow.add_edge(START, "dependency_analyzer")

    # After dependency analysis → branch
    workflow.add_conditional_edges(
        "dependency_analyzer",
        _route_after_analysis,
        {
            "advisory": "ast_context",   # full track
            "direct": "pr_creator",      # manifest-only
        },
    )

    # Advisory track: AST scan → SE → DA (with possible loop)
    workflow.add_edge("ast_context", "software_engineer")
    workflow.add_edge("software_engineer", "devils_advocate")
    workflow.add_conditional_edges(
        "devils_advocate",
        _route_after_review,
        {
            "approved": "pr_creator",
            "revise": "software_engineer",
        },
    )

    # Final steps
    workflow.add_edge("pr_creator", "notifier")
    workflow.add_edge("notifier", END)

    return workflow.compile()


# Compiled singleton — imported by webhook_server and main
app = create_graph()
