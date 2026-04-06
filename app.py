"""
Snyk Auto-Remediation — Streamlit Dashboard
────────────────────────────────────────────
Real-time UI for the LangGraph pipeline.

Run with:
    streamlit run app.py
"""
from __future__ import annotations

import json
import os
import queue
import threading
from datetime import datetime
from typing import Any

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Snyk Auto-Remediation",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
.step-card {
    background: #1e1e2e;
    border-left: 4px solid #6c63ff;
    border-radius: 8px;
    padding: 1rem 1.2rem;
    margin-bottom: 1rem;
}
.step-card.done  { border-left-color: #50fa7b; }
.step-card.error { border-left-color: #ff5555; }
.step-card.warn  { border-left-color: #f1fa8c; }
.badge-critical { background:#ff5555; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.75rem; }
.badge-high     { background:#ff8c00; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.75rem; }
.badge-medium   { background:#f1fa8c; color:#111; padding:2px 8px; border-radius:4px; font-size:0.75rem; }
.badge-low      { background:#50fa7b; color:#111; padding:2px 8px; border-radius:4px; font-size:0.75rem; }
</style>
""", unsafe_allow_html=True)


# ── Session state defaults ─────────────────────────────────────────────────────
def _init_state() -> None:
    defaults = {
        "running": False,
        "pipeline_done": False,
        "log_queue": queue.Queue(),
        "node_results": {},   # node_name → output dict
        "error": None,
        "started_at": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()


# ── Sidebar — inputs ───────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://snyk.io/wp-content/uploads/snyk-logo.svg", width=120)
    st.title("🔒 Auto-Remediation")
    st.divider()

    input_mode = st.radio(
        "Input mode",
        ["Upload Snyk JSON", "Manual entry"],
        horizontal=True,
    )

    vuln_data: dict | None = None

    if input_mode == "Upload Snyk JSON":
        uploaded = st.file_uploader(
            "Snyk alert JSON", type=["json"],
            help="Drop the full Snyk webhook payload here",
        )
        if uploaded:
            try:
                payload = json.loads(uploaded.read())
                st.success(f"Loaded {len(payload.get('newIssues', []))} issue(s)")
            except json.JSONDecodeError:
                st.error("Invalid JSON")
                payload = None
        else:
            payload = None

        use_fixture = st.checkbox("Or use built-in fixture (lodash CVE-2020-8203)", value=True)
        if use_fixture:
            fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "snyk_alert.json")
            try:
                with open(fixture_path) as fh:
                    payload = json.load(fh)
                st.info("Using fixture: lodash prototype pollution")
            except FileNotFoundError:
                st.warning("Fixture not found")
    else:
        package_name = st.text_input("Package name", value="lodash")
        affected_ver  = st.text_input("Affected version", value="4.17.15")
        fixed_ver     = st.text_input("Fixed version", value="4.17.21")
        severity      = st.selectbox("Severity", ["critical", "high", "medium", "low"], index=1)
        cves          = st.text_input("CVEs (comma-separated)", value="CVE-2020-8203")
        description   = st.text_area("Description", value="Prototype Pollution via _.merge")
        functions     = st.text_input("Affected functions", value="_.merge,_.defaultsDeep")

        payload = {
            "newIssues": [{
                "id": f"MANUAL-{package_name.upper()}-001",
                "issueData": {
                    "id": f"MANUAL-{package_name.upper()}-001",
                    "title": f"Vulnerability in {package_name}",
                    "severity": severity,
                    "description": description,
                    "identifiers": {"CVE": [c.strip() for c in cves.split(",") if c.strip()]},
                    "functions": [f.strip() for f in functions.split(",") if f.strip()],
                },
                "pkgName": package_name,
                "pkgVersions": [affected_ver],
                "fixedIn": [fixed_ver],
            }]
        }

    st.divider()
    repo_path = st.text_input(
        "Repository path",
        value=os.getenv("REPO_LOCAL_PATH", "./fixtures/sample_repo"),
        help="Absolute or relative path to the local repo to scan",
    )

    # ── Vulnerability selector (when payload has multiple issues) ──────────
    vuln_index = 0
    if payload and len(payload.get("newIssues", [])) > 1:
        st.divider()
        st.markdown("**Select vulnerability to process:**")
        vuln_options = []
        for i, issue in enumerate(payload.get("newIssues", [])):
            idata = issue.get("issueData", {})
            sev = idata.get("severity", "?").upper()
            trans = " 🔗" if issue.get("isTransitive") else ""
            vuln_options.append(
                f"{sev}{trans} — {issue.get('pkgName', '?')} — {idata.get('title', '?')}"
            )
        vuln_index = st.selectbox(
            "Vulnerability",
            range(len(vuln_options)),
            format_func=lambda i: vuln_options[i],
        )

    st.divider()
    st.caption(f"Model: `{os.getenv('OLLAMA_MODEL','mistral')}` via Ollama")
    st.caption(f"GitHub repo: `{os.getenv('GITHUB_REPO','(not set)')}`")

    run_btn = st.button(
        "🚀 Run Pipeline",
        disabled=st.session_state["running"] or payload is None,
        type="primary",
        width='stretch',
    )


# ── Pipeline runner (background thread) ───────────────────────────────────────
def _run_pipeline(payload: dict, repo_path: str, q: queue.Queue, vuln_idx: int = 0) -> None:
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from graph import create_graph
    from webhook_server import _parse_snyk_payload
    from state import AgentState

    vulns = _parse_snyk_payload(payload)
    if not vulns:
        q.put(("error", "No vulnerabilities found in payload"))
        return

    # Process all vulns or just the selected one
    vuln = vulns[min(vuln_idx, len(vulns) - 1)]
    initial_state: AgentState = {
        "vulnerability": vuln,
        "repo_path": os.path.abspath(repo_path),
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

    graph = create_graph()
    try:
        for chunk in graph.stream(initial_state, stream_mode="updates"):
            for node_name, node_output in chunk.items():
                q.put(("node_done", node_name, node_output))
        q.put(("done",))
    except Exception as exc:
        q.put(("error", str(exc)))


# ── Trigger pipeline ───────────────────────────────────────────────────────────
if run_btn and payload:
    st.session_state["running"] = True
    st.session_state["pipeline_done"] = False
    st.session_state["node_results"] = {}
    st.session_state["error"] = None
    st.session_state["started_at"] = datetime.now()
    st.session_state["log_queue"] = queue.Queue()

    t = threading.Thread(
        target=_run_pipeline,
        args=(payload, repo_path, st.session_state["log_queue"], vuln_index),
        daemon=True,
    )
    t.start()
    st.rerun()


# ── Main content area ──────────────────────────────────────────────────────────
st.title("🔒 Snyk Auto-Remediation Pipeline")

if not st.session_state["running"] and not st.session_state["pipeline_done"]:
    st.info("Configure inputs in the sidebar and click **Run Pipeline** to start.")
    with st.expander("ℹ️ How it works", expanded=True):
        st.markdown("""
| Step | Agent | What it does |
|------|-------|-------------|
| 1 | **Dependency Analyzer** | LLM decides if upgrade is safe & whether a code audit is needed |
| 2 | **AST Context Engine** | Scans every file for vulnerable function calls (parallel, multi-language) |
| 3 | **Software Engineer** | LLM drafts targeted fixes for each risky call site |
| 4 | **Devil's Advocate** | LLM reviews fixes for regressions — loops back if issues found |
| 5 | **PR Creator** | Creates git branch, patches `package.json`, opens a GitHub Draft PR |
| 6 | **Notifier** | Summarises the result |
        """)
    st.stop()


# ── Drain the queue and update state ──────────────────────────────────────────
q: queue.Queue = st.session_state["log_queue"]
drained = 0
while not q.empty() and drained < 50:
    msg: tuple[Any, ...] = q.get_nowait()
    drained += 1
    if msg[0] == "node_done":
        _, node_name, node_output = msg
        st.session_state["node_results"][node_name] = node_output
    elif msg[0] == "done":
        st.session_state["running"] = False
        st.session_state["pipeline_done"] = True
    elif msg[0] == "error":
        st.session_state["running"] = False
        st.session_state["error"] = msg[1]


results: dict = st.session_state["node_results"]

# Auto-refresh while running
if st.session_state["running"]:
    st.toast("Pipeline running…", icon="⏳")


# ── Progress bar ───────────────────────────────────────────────────────────────
STEPS = ["dependency_analyzer", "ast_context", "software_engineer", "devils_advocate", "pr_creator", "notifier"]
done_steps = [s for s in STEPS if s in results]
progress = len(done_steps) / len(STEPS)

col_prog, col_time = st.columns([4, 1])
with col_prog:
    st.progress(progress, text=f"Step {len(done_steps)}/{len(STEPS)}")
with col_time:
    if st.session_state["started_at"]:
        elapsed = (datetime.now() - st.session_state["started_at"]).seconds
        st.metric("Elapsed", f"{elapsed}s")

if st.session_state["error"]:
    st.error(f"Pipeline error: {st.session_state['error']}")

st.divider()


# ── Helper to show step header ─────────────────────────────────────────────────
def _step_header(icon: str, title: str, node: str) -> bool:
    done = node in results
    spinner = "✅" if done else ("⏳" if st.session_state["running"] else "⬜")
    st.subheader(f"{spinner} {icon} {title}")
    return done


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Dependency Analysis
# ══════════════════════════════════════════════════════════════════════════════
with st.expander("Step 1 — Dependency Analysis", expanded="dependency_analyzer" in results):
    if "dependency_analyzer" in results:
        r = results["dependency_analyzer"]

        cols = st.columns(4)
        cols[0].metric("Breaking changes", "Yes ⚠️" if r.get("breaking_changes") else "No ✅")
        cols[1].metric("Advisory track", "Yes 🔍" if r.get("advisory_track") else "No — direct fix")
        cols[2].metric("Semver safe", r.get("semver_analysis", "—"))
        cols[3].metric("Track", "Advisory" if r.get("advisory_track") else "Direct")

        # Show breaking change warning prominently
        if r.get("breaking_changes"):
            st.error(
                "⚠️ **Breaking changes detected!** This is a major version upgrade. "
                "Code modifications will likely be required beyond a simple manifest bump."
            )

        if r.get("breaking_change_analysis"):
            st.markdown("**LLM Analysis:**")
            st.info(r["breaking_change_analysis"])

        if r.get("affected_functions"):
            st.markdown("**Affected functions:**")
            st.code(", ".join(r["affected_functions"]), language="text")
    else:
        st.caption("Waiting for dependency analysis…")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — AST Context Engine
# ══════════════════════════════════════════════════════════════════════════════
with st.expander("Step 2 — AST Code Scan", expanded="ast_context" in results):
    if "ast_context" in results:
        r = results["ast_context"]
        sites = r.get("usage_sites", [])
        risky = [s for s in sites if s.get("has_user_input")]

        cols = st.columns(3)
        cols[0].metric("Usage sites found", len(sites))
        cols[1].metric("With user-input risk ⚠️", len(risky))
        cols[2].metric("Files scanned", r.get("ast_total_files_scanned", "—"))

        if sites:
            import pandas as pd
            df = pd.DataFrame([{
                "File": s["file_path"].replace(os.getcwd(), "."),
                "Line": s["line_number"],
                "Function": s["function_called"],
                "User Input Risk": "⚠️ YES" if s["has_user_input"] else "✅ NO",
            } for s in sites])
            st.dataframe(df, width='stretch', hide_index=True)

            st.markdown("**Code snippets:**")
            for i, site in enumerate(sites, 1):
                label = f"{'⚠️ RISKY' if site['has_user_input'] else '✅ Safe'} — {site['file_path']}:{site['line_number']}"
                with st.expander(label, expanded=site["has_user_input"]):
                    st.code(site["snippet"], language="javascript")
        else:
            st.success("No usage sites found — manifest upgrade is sufficient.")
    else:
        st.caption("Waiting for AST scan…")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Software Engineer Agent
# ══════════════════════════════════════════════════════════════════════════════
with st.expander("Step 3 — Software Engineer Fixes", expanded="software_engineer" in results):
    if "software_engineer" in results:
        r = results["software_engineer"]
        fixes = r.get("proposed_fixes", [])
        manifest = r.get("manifest_changes", {})

        st.metric("Fixes drafted", len(fixes))

        if manifest:
            st.markdown("**Manifest change:**")
            st.code(
                f'{manifest.get("file","package.json")}: '
                f'"{manifest.get("package")}" : '
                f'"{manifest.get("from_version")}" → "{manifest.get("to_version")}"',
                language="text"
            )

        for i, fix in enumerate(fixes, 1):
            risk_color = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(fix.get("risk_level","medium"), "⚪")
            with st.expander(
                f"{risk_color} Fix {i} — `{fix['file_path']}` line {fix['line_number']} ({fix.get('risk_level','?')} risk)",
                expanded=True
            ):
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("**Before:**")
                    st.code(fix.get("original_code", ""), language="javascript")
                with col_b:
                    st.markdown("**After:**")
                    st.code(fix.get("fixed_code", ""), language="javascript")
                st.caption(f"💬 {fix.get('explanation','')}")
    else:
        st.caption("Waiting for SE agent…")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Devil's Advocate Review
# ══════════════════════════════════════════════════════════════════════════════
with st.expander("Step 4 — Devil's Advocate Review", expanded="devils_advocate" in results):
    if "devils_advocate" in results:
        r = results["devils_advocate"]
        approved = r.get("review_approved", False)
        iteration = r.get("review_iterations", 1)

        col1, col2, col3 = st.columns(3)
        col1.metric("Verdict", "✅ Approved" if approved else "🔄 Revision needed")
        col2.metric("Review iteration", iteration)
        col3.metric("Overall risk", r.get("risk_assessment", "—")[:20] + "…" if r.get("risk_assessment") else "—")

        if r.get("review_feedback"):
            st.warning(f"**Feedback:** {r['review_feedback']}")

        if r.get("risk_assessment"):
            st.markdown("**Risk Assessment (goes into PR description):**")
            st.markdown(r["risk_assessment"])
    else:
        st.caption("Waiting for DA review…")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — PR Creator
# ══════════════════════════════════════════════════════════════════════════════
with st.expander("Step 5 — GitHub Draft PR", expanded="pr_creator" in results):
    if "pr_creator" in results:
        r = results["pr_creator"]
        pr_url = r.get("pr_url", "")
        branch = r.get("pr_branch", "")
        is_error = pr_url.startswith("[ERROR]")
        is_dry = pr_url.startswith("[DRY-RUN]")

        st.metric("Branch", branch or "—")

        if is_error:
            st.error(pr_url)
        elif is_dry:
            st.warning(f"Dry-run mode (set GITHUB_REPO in .env for live PRs)\n`{pr_url}`")
        elif pr_url:
            st.success("Draft PR created!")
            st.markdown(f"### 🔗 [Open PR on GitHub]({pr_url})")
        else:
            st.warning("PR URL not available")
    else:
        st.caption("Waiting for PR creation…")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 — Notifier + Audit trail
# ══════════════════════════════════════════════════════════════════════════════
if st.session_state["pipeline_done"] or "notifier" in results:
    st.divider()
    st.success("🎉 Pipeline complete!")

    # Collect all messages across all nodes
    all_msgs: list[str] = []
    for node in STEPS:
        if node in results:
            all_msgs.extend(results[node].get("messages", []))

    if all_msgs:
        with st.expander("📋 Full Audit Trail", expanded=False):
            for msg in all_msgs:
                st.text(msg)

# ── Auto-refresh while running ─────────────────────────────────────────────────
if st.session_state["running"]:
    import time
    time.sleep(1)
    st.rerun()
