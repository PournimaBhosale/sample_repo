"""
AST Context Engine
──────────────────
Scans the repository for all call sites of the vulnerable package functions.
Primary scanner : tree-sitter (JavaScript / TypeScript)
Fallback scanner: regex (used when tree-sitter bindings are unavailable)

Returns a list of UsageSite objects with file, line, surrounding code, and a
flag indicating whether user-controlled input appears nearby.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import List

from state import AgentState, UsageSite

logger = logging.getLogger(__name__)

# ── Heuristics ────────────────────────────────────────────────────────────────

# Signals that user-controlled data is present near a call site
_USER_INPUT_SIGNALS: list[str] = [
    r"req\.body",
    r"req\.query",
    r"req\.params",
    r"request\.body",
    r"process\.argv",
    r"JSON\.parse",
    r"userInput",
    r"userData",
    r"\binput\b",
    r"formData",
    r"payload",
]

# require() / import patterns that reference the vulnerable package
_IMPORT_PATTERNS: list[str] = [
    r"""(?:const|let|var)\s+\w+\s*=\s*require\s*\(\s*['"](?P<pkg>[^'"]+)['"]\s*\)""",
    r"""import\s+(?:\*\s+as\s+)?\w+\s+from\s+['"](?P<pkg>[^'"]+)['"]""",
    r"""(?:const|let|var)\s*\{[^}]+\}\s*=\s*require\s*\(\s*['"](?P<pkg>[^'"]+)['"]\s*\)""",
]

# JS/TS file extensions to scan
_JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

# Directories that should never be scanned
_IGNORE_DIRS = {"node_modules", ".git", "dist", "build", ".next", "coverage", ".cache"}


# ── Helpers ────────────────────────────────────────────────────────────────────


def _get_source_files(repo_path: str) -> List[str]:
    files: List[str] = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _IGNORE_DIRS]
        for fname in filenames:
            if Path(fname).suffix in _JS_EXTENSIONS:
                files.append(os.path.join(root, fname))
    return sorted(files)


def _imports_package(file_path: str, package_name: str) -> bool:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return False
    for pat in _IMPORT_PATTERNS:
        for m in re.finditer(pat, content):
            pkg = m.group("pkg")
            if pkg == package_name or pkg.startswith(package_name + "/"):
                return True
    return False


def _has_user_input(snippet: str) -> bool:
    return any(re.search(sig, snippet) for sig in _USER_INPUT_SIGNALS)


def _snippet_around(lines: list[str], line_num: int, context: int = 3) -> str:
    start = max(0, line_num - 1 - context)
    end = min(len(lines), line_num + context)
    return "\n".join(lines[start:end])


# ── Tree-sitter scanner ────────────────────────────────────────────────────────


def _scan_with_tree_sitter(
    file_path: str, affected_methods: list[str]
) -> List[UsageSite]:
    """Walk the JS AST looking for member-expression calls to affected methods."""
    try:
        import tree_sitter_javascript as tsjs  # type: ignore
        from tree_sitter import Language, Parser
    except ImportError:
        return []

    try:
        lang = Language(tsjs.language())
        try:
            parser = Parser(lang)           # tree-sitter >= 0.22
        except TypeError:
            parser = Parser()               # tree-sitter 0.21.x fallback
            parser.set_language(lang)       # type: ignore[attr-defined]
    except Exception as exc:
        logger.debug("tree-sitter init failed: %s", exc)
        return []

    try:
        with open(file_path, "rb") as fh:
            source_bytes = fh.read()
    except OSError:
        return []

    source_text = source_bytes.decode("utf-8", errors="ignore")
    source_lines = source_text.splitlines()
    tree = parser.parse(source_bytes)

    def _walk(node):  # type: ignore[no-untyped-def]
        yield node
        for child in node.children:
            yield from _walk(child)

    sites: List[UsageSite] = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn_node = node.children[0] if node.children else None
        if fn_node is None or fn_node.type != "member_expression":
            continue
        fn_text = source_bytes[fn_node.start_byte : fn_node.end_byte].decode(
            "utf-8", errors="ignore"
        )
        method = fn_text.split(".")[-1]
        if method not in affected_methods:
            continue

        line_num = node.start_point[0] + 1  # 1-based
        snippet = _snippet_around(source_lines, line_num)
        sites.append(
            UsageSite(
                file_path=file_path,
                line_number=line_num,
                snippet=snippet,
                function_called=fn_text,
                has_user_input=_has_user_input(snippet),
            )
        )

    return sites


# ── Regex fallback scanner ─────────────────────────────────────────────────────


def _scan_with_regex(
    file_path: str, package_name: str, affected_functions: list[str]
) -> List[UsageSite]:
    """Simple regex scanner — used as fallback when tree-sitter is unavailable."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return []

    # Build patterns from affected function names
    patterns: dict[str, str] = {}
    for fn in affected_functions:
        basename = fn.split(".")[-1]
        # matches _.merge( or merge( (destructured import)
        patterns[fn] = rf"(?:_\.)?{re.escape(basename)}\s*\("

    sites: List[UsageSite] = []
    for func_name, pattern in patterns.items():
        for idx, line in enumerate(lines, start=1):
            if re.search(pattern, line):
                snippet = _snippet_around([l.rstrip() for l in lines], idx)
                sites.append(
                    UsageSite(
                        file_path=file_path,
                        line_number=idx,
                        snippet=snippet,
                        function_called=func_name,
                        has_user_input=_has_user_input(snippet),
                    )
                )

    return sites


# ── LangGraph node ─────────────────────────────────────────────────────────────


def ast_context_node(state: AgentState) -> dict:
    vuln = state["vulnerability"]
    repo_path = state["repo_path"]
    affected_functions: list[str] = state.get("affected_functions") or vuln["affected_functions"]

    # Bare method names (without the `_.` prefix) for tree-sitter matching
    affected_methods = [fn.split(".")[-1] for fn in affected_functions]

    logger.info(
        "[ASTContext] Scanning %s for `%s` usage (functions: %s)",
        repo_path,
        vuln["package_name"],
        ", ".join(affected_functions),
    )

    source_files = _get_source_files(repo_path)
    logger.info("[ASTContext] %d JS/TS files to examine", len(source_files))

    all_sites: List[UsageSite] = []

    for fpath in source_files:
        if not _imports_package(fpath, vuln["package_name"]):
            continue

        # Prefer tree-sitter; fall back to regex
        sites = _scan_with_tree_sitter(fpath, affected_methods)
        if not sites:
            sites = _scan_with_regex(fpath, vuln["package_name"], affected_functions)

        if sites:
            logger.info("[ASTContext] %d usage(s) in %s", len(sites), fpath)
            all_sites.extend(sites)

    risky = sum(1 for s in all_sites if s["has_user_input"])
    log_msgs = list(state.get("messages", []))
    log_msgs.append(
        f"[ASTContext] {len(source_files)} files scanned → "
        f"{len(all_sites)} usage sites ({risky} with potential user input)"
    )
    logger.info(log_msgs[-1])

    return {
        "usage_sites": all_sites,
        "current_step": "ast_context_complete",
        "messages": log_msgs,
    }
