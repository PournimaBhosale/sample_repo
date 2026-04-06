"""
PR Creator Node
───────────────
1. Creates a git branch in the target repository.
2. Updates package.json to the fixed version and commits it.
3. Creates a draft GitHub PR via the `gh` CLI containing:
     • Committed manifest change
     • Inline code-fix suggestions (as PR body diff blocks)
     • Risk assessment from the Devil's Advocate

When GITHUB_REPO is not configured the node runs in **dry-run** mode:
it prints the full PR body to stdout without touching GitHub.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from datetime import datetime

from config import GITHUB_REPO, GITHUB_TOKEN
from state import AgentState

logger = logging.getLogger(__name__)


# ── Git / gh helpers ──────────────────────────────────────────────────────────


def _run(cmd: list[str], cwd: str, env: dict | None = None) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=60,
            env=env or os.environ.copy(),
        )
        output = (result.stdout + result.stderr).strip()
        return result.returncode == 0, output
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return False, str(exc)


def _git(args: list[str], cwd: str) -> tuple[bool, str]:
    return _run(["git"] + args, cwd)


def _gh(args: list[str], cwd: str) -> tuple[bool, str]:
    env = os.environ.copy()
    # Only override GH_TOKEN if explicitly set in .env — otherwise let gh CLI
    # use the token stored via `gh auth login`
    if GITHUB_TOKEN and GITHUB_TOKEN not in ("", "your_github_token_here"):
        env["GH_TOKEN"] = GITHUB_TOKEN
    else:
        # Remove any existing GH_TOKEN / GITHUB_TOKEN that might shadow gh auth
        env.pop("GH_TOKEN", None)
        env.pop("GITHUB_TOKEN", None)
    return _run(["gh"] + args, cwd, env=env)


# ── Manifest patching ────────────────────────────────────────────────────────


def _patch_package_json(repo_path: str, package_name: str, new_version: str,
                        is_transitive: bool = False,
                        parent_package: str = "") -> bool:
    pkg_path = os.path.join(repo_path, "package.json")
    if not os.path.isfile(pkg_path):
        logger.warning("[PRCreator] package.json not found at %s", pkg_path)
        return False
    try:
        with open(pkg_path) as fh:
            pkg = json.load(fh)
        patched = False

        if is_transitive:
            # Add npm "overrides" to pin the transitive dependency version
            if "overrides" not in pkg:
                pkg["overrides"] = {}
            pkg["overrides"][package_name] = new_version
            patched = True
            logger.info(
                "[PRCreator] Added override: %s@%s (transitive via %s)",
                package_name, new_version, parent_package,
            )
        else:
            for dep_key in ("dependencies", "devDependencies", "peerDependencies"):
                if dep_key in pkg and package_name in pkg[dep_key]:
                    pkg[dep_key][package_name] = new_version
                    patched = True

        if patched:
            with open(pkg_path, "w") as fh:
                json.dump(pkg, fh, indent=2)
                fh.write("\n")
        return patched
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("[PRCreator] Failed to patch package.json: %s", exc)
        return False


# ── PR body builder ───────────────────────────────────────────────────────────


def _build_pr_body(state: AgentState) -> str:
    vuln = state["vulnerability"]
    usage_sites = state.get("usage_sites", [])
    proposed_fixes = state.get("proposed_fixes", [])
    risk_assessment = state.get("risk_assessment", "")
    analysis = state.get("breaking_change_analysis", "")

    is_transitive = vuln.get("is_transitive", False)
    transitive_chain = vuln.get("transitive_chain", [])
    breaking = state.get("breaking_changes", False)

    transitive_badge = ""
    if is_transitive:
        chain_str = " → ".join(transitive_chain)
        transitive_badge = f"\n**Transitive dependency:** Yes — `{chain_str}`  \n**Parent package:** `{vuln.get('parent_package', 'N/A')}`  "

    breaking_badge = ""
    if breaking:
        breaking_badge = "\n**⚠️ BREAKING CHANGES DETECTED** — code modifications required  "

    body = f"""## 🔒 Security Fix: {vuln["title"]}

**Package:** `{vuln["package_name"]}` `{vuln["affected_version"]}` → `{vuln["fixed_version"]}`  
**Severity:** `{vuln["severity"].upper()}`  
**CVEs:** {", ".join(vuln["cve_ids"]) or "N/A"}  
**Snyk ID:** `{vuln["id"]}`  {transitive_badge}{breaking_badge}

### Summary
{vuln["description"]}

### Breaking-Change Analysis
{analysis or "_No breaking changes detected — this is a semver-compatible upgrade._"}

### Usage Sites ({len(usage_sites)} found)

| File | Line | Function | User-Input Nearby |
|------|------|----------|-------------------|
"""
    for site in usage_sites:
        risk_badge = "⚠️ YES" if site["has_user_input"] else "✅ NO"
        body += (
            f"| `{site['file_path']}` | {site['line_number']} "
            f"| `{site['function_called']}` | {risk_badge} |\n"
        )

    if proposed_fixes:
        body += "\n### Suggested Code Changes\n"
        body += (
            "> **These are suggestions only — review each diff, "
            "apply manually, then commit before merging.**\n\n"
        )
        for i, fix in enumerate(proposed_fixes, start=1):
            orig = fix["original_code"].replace("\n", "\n- ")
            fixed = fix["fixed_code"].replace("\n", "\n+ ")
            body += f"""#### Suggestion {i} — `{fix["file_path"]}` line {fix["line_number"]}

> {fix["explanation"]}

```diff
- {orig}
+ {fixed}
```

"""

    if risk_assessment:
        body += f"\n### Risk Assessment\n\n{risk_assessment}\n"

    body += (
        f"\n---\n"
        f"*Auto-generated by **snyk-auto-remediation** on "
        f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} "
        f"— review carefully before merging.*"
    )
    return body


# ── LangGraph node ─────────────────────────────────────────────────────────────


def pr_creator_node(state: AgentState) -> dict:
    vuln = state["vulnerability"]
    repo_path = os.path.abspath(state["repo_path"])
    dry_run = not GITHUB_REPO

    logger.info(
        "[PRCreator] Creating PR for %s (%s mode)",
        vuln["package_name"],
        "dry-run" if dry_run else "live",
    )

    # Sanitise branch name (no slashes from vuln id)
    branch_name = (
        f"fix/snyk-{vuln['package_name']}-{vuln['id'][:20]}"
        .lower()
        .replace("/", "-")
        .replace("_", "-")
    )

    # ── Ensure git repo exists ───────────────────────────────────────────────
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        _git(["init"], repo_path)
        _git(["config", "user.email", "snyk-bot@example.com"], repo_path)
        _git(["config", "user.name", "Snyk Auto-Remediation Bot"], repo_path)
        _git(["add", "."], repo_path)
        _git(["commit", "-m", "chore: initial commit (snyk-bot setup)"], repo_path)

    # ── Always start from main/default branch ─────────────────────────────
    _git(["checkout", "main"], repo_path)
    # Pull latest to avoid divergence (ignore errors if no remote)
    _git(["pull", "--rebase", "origin", "main"], repo_path)

    # ── Create fix branch ────────────────────────────────────────────────────
    ok, _ = _git(["checkout", "-b", branch_name], repo_path)
    if not ok:
        # Branch already exists — delete and recreate from main
        _git(["checkout", "main"], repo_path)
        _git(["branch", "-D", branch_name], repo_path)
        _git(["checkout", "-b", branch_name], repo_path)

    # ── Patch manifest ───────────────────────────────────────────────────────
    patched = _patch_package_json(
        repo_path,
        vuln["package_name"],
        vuln["fixed_version"],
        is_transitive=vuln.get("is_transitive", False),
        parent_package=vuln.get("parent_package", ""),
    )
    if patched:
        commit_msg = (
            f"fix: upgrade {vuln['package_name']} "
            f"{vuln['affected_version']} → {vuln['fixed_version']}\n\n"
            f"Resolves: {', '.join(vuln['cve_ids']) or vuln['id']}\n"
            f"Severity: {vuln['severity'].upper()}\n"
            f"Snyk ID: {vuln['id']}"
        )
        _git(["add", "package.json"], repo_path)
        ok, out = _git(["commit", "-m", commit_msg], repo_path)
        logger.info("[PRCreator] Committed manifest: %s", out.splitlines()[0] if out else "ok")
    else:
        logger.warning("[PRCreator] package.json not patched — committing nothing")

    pr_body = _build_pr_body(state)
    pr_url = ""
    pr_number = 0

    if not dry_run:
        # ── Ensure remote 'origin' points to GITHUB_REPO ────────────────────
        _, existing_remote = _git(["remote", "get-url", "origin"], repo_path)
        expected_remote = f"https://github.com/{GITHUB_REPO}.git"
        if GITHUB_REPO not in existing_remote:
            _git(["remote", "remove", "origin"], repo_path)
            _git(["remote", "add", "origin", expected_remote], repo_path)
            logger.info("[PRCreator] Remote set to %s", expected_remote)

        # ── Delete stale remote branch if it exists, then push fresh ──────────
        _git(["push", "origin", "--delete", branch_name], repo_path)  # ignore errors
        push_ok, push_out = _git(
            ["push", "-u", "origin", branch_name],
            repo_path,
        )
        if not push_ok:
            logger.error("[PRCreator] Push failed: %s", push_out)
            pr_url = f"[ERROR] push failed: {push_out[:120]}"
        else:
            logger.info("[PRCreator] Pushed branch %s", branch_name)

            pr_title = (
                f"fix: Upgrade {vuln['package_name']} to {vuln['fixed_version']} "
                f"({vuln['severity'].upper()} — {', '.join(vuln['cve_ids']) or vuln['id']})"
            )
            body_file = f"/tmp/snyk_pr_body_{vuln['id'][:8]}.md"
            with open(body_file, "w") as fh:
                fh.write(pr_body)

            ok, out = _gh(
                [
                    "pr", "create",
                    "--draft",
                    "--title", pr_title,
                    "--body-file", body_file,
                    "--repo", GITHUB_REPO,
                    "--head", branch_name,
                    "--base", "main",
                ],
                cwd=repo_path,
            )
            if ok:
                pr_url = out.strip().splitlines()[-1]
                logger.info("[PRCreator] Draft PR created: %s", pr_url)
            else:
                logger.error("[PRCreator] PR creation failed: %s", out)
                pr_url = f"[ERROR] {out[:120]}"
    else:
        pr_url = f"[DRY-RUN] branch={branch_name}"
        separator = "=" * 70
        print(f"\n{separator}\n[DRY-RUN] PR Body Preview\n{separator}\n{pr_body}\n{separator}\n")

    log_msgs = list(state.get("messages", []))
    log_msgs.append(f"[PRCreator] {pr_url}")

    return {
        "pr_url": pr_url,
        "pr_number": pr_number,
        "pr_branch": branch_name,
        "current_step": "pr_created",
        "messages": log_msgs,
    }
