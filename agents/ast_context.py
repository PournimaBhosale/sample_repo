"""
AST Context Engine  (v2 — multi-language, parallel, big-repo aware)
────────────────────────────────────────────────────────────────────
Scans the repository for all call sites of the vulnerable package.

Language support:
  • JavaScript / TypeScript  — tree-sitter AST (fallback: regex)
  • Python                   — regex (import + call detection)
  • Java                     — regex (import + method call)
  • Go                       — regex (import + call)
  • Ruby                     — regex (require + call)

Big-repo features:
  • Parallel file scanning via ThreadPoolExecutor
  • Files capped at MAX_FILES_TO_SCAN (configurable)
  • Risky sites (user-input detected) sorted to the top
  • LLM receives only top MAX_SITES_TO_LLM sites to stay in context window
  • Snippet length capped at SNIPPET_MAX_LINES
"""
from __future__ import annotations

import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List

from state import AgentState, UsageSite

logger = logging.getLogger(__name__)

# ── Tuning knobs ───────────────────────────────────────────────────────────────
MAX_FILES_TO_SCAN = int(os.getenv("AST_MAX_FILES", "500"))
MAX_SITES_TO_LLM = int(os.getenv("AST_MAX_SITES_TO_LLM", "15"))
SNIPPET_MAX_LINES = int(os.getenv("AST_SNIPPET_LINES", "6"))
PARALLEL_WORKERS = int(os.getenv("AST_WORKERS", "8"))

# ── User-input heuristics ──────────────────────────────────────────────────────
_USER_INPUT_SIGNALS: list[str] = [
    r"req\.body", r"req\.query", r"req\.params", r"request\.body",
    r"request\.args", r"request\.form", r"request\.json",   # Flask/FastAPI
    r"process\.argv", r"JSON\.parse", r"userInput", r"userData",
    r"\binput\b", r"formData", r"payload", r"stdin",
    r"os\.environ", r"sys\.argv",                            # Python
    r"getParameter", r"getHeader", r"getBody",              # Java servlet
    r"r\.FormValue", r"r\.PostForm",                         # Go net/http
    r"params\[", r"request\.params",                         # Ruby/Rails
]

# ── Language definitions ───────────────────────────────────────────────────────
_LANG_EXTENSIONS: dict[str, set[str]] = {
    "javascript": {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"},
    "python":     {".py"},
    "java":       {".java"},
    "go":         {".go"},
    "ruby":       {".rb"},
}
_ALL_EXTENSIONS: set[str] = {ext for exts in _LANG_EXTENSIONS.values() for ext in exts}

# ── Directories to always skip ─────────────────────────────────────────────────
_IGNORE_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", "coverage",
    ".cache", "__pycache__", ".tox", ".venv", "venv", "vendor",
    "target", "bin", "obj", ".gradle", ".mvn",
}

# ── Import / require detection patterns per language ──────────────────────────
_IMPORT_PATTERNS: dict[str, list[str]] = {
    "javascript": [
        r"""require\s*\(\s*['"](?P<pkg>[^'"]+)['"]\s*\)""",
        r"""from\s+['"](?P<pkg>[^'"]+)['"]""",
    ],
    "python": [
        r"""import\s+(?P<pkg>[\w.]+)""",
        r"""from\s+(?P<pkg>[\w.]+)\s+import""",
    ],
    "java": [
        r"""import\s+(?P<pkg>[\w.]+)""",
    ],
    "go": [
        r'''"(?P<pkg>[^"]+(?:{pkg})[^"]*)"''',   # filled per package
        r'''`(?P<pkg>[^`]+(?:{pkg})[^`]*)`''',
    ],
    "ruby": [
        r"""require\s+['"](?P<pkg>[^'"]+)['"]""",
        r"""require_relative\s+['"](?P<pkg>[^'"]+)['"]""",
    ],
}


def _lang_for(file_path: str) -> str | None:
    ext = Path(file_path).suffix.lower()
    for lang, exts in _LANG_EXTENSIONS.items():
        if ext in exts:
            return lang
    return None


# ── Core helpers ───────────────────────────────────────────────────────────────

def _get_source_files(repo_path: str) -> List[str]:
    files: List[str] = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _IGNORE_DIRS]
        for fname in filenames:
            if Path(fname).suffix.lower() in _ALL_EXTENSIONS:
                files.append(os.path.join(root, fname))
    return sorted(files)


def _file_imports_package(file_path: str, package_name: str) -> bool:
    lang = _lang_for(file_path)
    if not lang:
        return False
    patterns = _IMPORT_PATTERNS.get(lang, [])
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read(8192)  # read first 8 KB only for speed
    except OSError:
        return False

    pkg_base = package_name.split("/")[0].split(".")[0]
    for pat in patterns:
        pat = pat.replace("{pkg}", re.escape(pkg_base))
        for m in re.finditer(pat, content):
            found = m.group("pkg")
            if pkg_base in found:
                return True
    return False


def _has_user_input(snippet: str) -> bool:
    return any(re.search(sig, snippet) for sig in _USER_INPUT_SIGNALS)


def _snippet_around(lines: list[str], line_num: int, context: int = SNIPPET_MAX_LINES) -> str:
    start = max(0, line_num - 1 - context)
    end = min(len(lines), line_num + context)
    return "\n".join(lines[start:end])


# ── Tree-sitter JS/TS scanner ─────────────────────────────────────────────────

def _scan_js_tree_sitter(file_path: str, affected_methods: list[str]) -> List[UsageSite]:
    try:
        import tree_sitter_javascript as tsjs  # type: ignore
        from tree_sitter import Language, Parser
    except ImportError:
        return []
    try:
        lang = Language(tsjs.language())
        try:
            parser = Parser(lang)
        except TypeError:
            parser = Parser()
            parser.set_language(lang)  # type: ignore[attr-defined]
    except Exception:
        return []

    try:
        with open(file_path, "rb") as fh:
            source_bytes = fh.read()
    except OSError:
        return []

    source_lines = source_bytes.decode("utf-8", errors="ignore").splitlines()
    tree = parser.parse(source_bytes)

    def _walk(node):
        yield node
        for child in node.children:
            yield from _walk(child)

    sites: List[UsageSite] = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn_node = node.children[0] if node.children else None
        if not fn_node or fn_node.type != "member_expression":
            continue
        fn_text = source_bytes[fn_node.start_byte:fn_node.end_byte].decode("utf-8", errors="ignore")
        if fn_text.split(".")[-1] not in affected_methods:
            continue
        line_num = node.start_point[0] + 1
        snippet = _snippet_around(source_lines, line_num)
        sites.append(UsageSite(
            file_path=file_path, line_number=line_num, snippet=snippet,
            function_called=fn_text, has_user_input=_has_user_input(snippet),
        ))
    return sites


# ── Generic regex scanner (all languages) ─────────────────────────────────────

def _scan_with_regex(
    file_path: str, package_name: str, affected_functions: list[str]
) -> List[UsageSite]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return []

    stripped = [l.rstrip() for l in lines]
    sites: List[UsageSite] = []

    for fn in affected_functions:
        basename = fn.split(".")[-1]
        # Matches: _.merge(  /  lodash.merge(  /  merge(  /  _merge(
        pattern = rf"(?:[\w_]+\.)?{re.escape(basename)}\s*\("
        for idx, line in enumerate(lines, start=1):
            if re.search(pattern, line):
                snippet = _snippet_around(stripped, idx)
                sites.append(UsageSite(
                    file_path=file_path, line_number=idx, snippet=snippet,
                    function_called=fn, has_user_input=_has_user_input(snippet),
                ))
    return sites


# ── Per-file scan dispatcher ───────────────────────────────────────────────────

def _scan_file(
    file_path: str,
    package_name: str,
    affected_functions: list[str],
    affected_methods: list[str],
) -> List[UsageSite]:
    if not _file_imports_package(file_path, package_name):
        return []
    lang = _lang_for(file_path)
    if lang == "javascript":
        sites = _scan_js_tree_sitter(file_path, affected_methods)
        if not sites:
            sites = _scan_with_regex(file_path, package_name, affected_functions)
    else:
        sites = _scan_with_regex(file_path, package_name, affected_functions)
    return sites


# ── LangGraph node ─────────────────────────────────────────────────────────────

def ast_context_node(state: AgentState) -> dict:
    vuln = state["vulnerability"]
    repo_path = state["repo_path"]
    affected_functions: list[str] = state.get("affected_functions") or vuln["affected_functions"]
    affected_methods = [fn.split(".")[-1] for fn in affected_functions]

    logger.info(
        "[ASTContext] Scanning %s | package=%s | functions=%s",
        repo_path, vuln["package_name"], ", ".join(affected_functions),
    )

    all_files = _get_source_files(repo_path)
    if len(all_files) > MAX_FILES_TO_SCAN:
        logger.warning(
            "[ASTContext] Large repo: %d files found, capping at %d",
            len(all_files), MAX_FILES_TO_SCAN,
        )
    files_to_scan = all_files[:MAX_FILES_TO_SCAN]

    # ── Parallel scan ─────────────────────────────────────────────────────────
    all_sites: List[UsageSite] = []
    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as pool:
        futures = {
            pool.submit(_scan_file, fp, vuln["package_name"], affected_functions, affected_methods): fp
            for fp in files_to_scan
        }
        for future in as_completed(futures):
            try:
                sites = future.result()
                if sites:
                    logger.info("[ASTContext] %d hit(s) in %s", len(sites), futures[future])
                    all_sites.extend(sites)
            except Exception as exc:
                logger.debug("[ASTContext] scan error in %s: %s", futures[future], exc)

    # ── Sort: risky (user-input) first, then by file ───────────────────────────
    all_sites.sort(key=lambda s: (not s["has_user_input"], s["file_path"], s["line_number"]))

    # ── Cap sites passed to LLM to stay in context window ─────────────────────
    sites_for_llm = all_sites[:MAX_SITES_TO_LLM]
    if len(all_sites) > MAX_SITES_TO_LLM:
        logger.info(
            "[ASTContext] %d total sites — sending top %d (risky-first) to LLM",
            len(all_sites), MAX_SITES_TO_LLM,
        )

    risky = sum(1 for s in all_sites if s["has_user_input"])
    log_msgs = list(state.get("messages", []))
    log_msgs.append(
        f"[ASTContext] {len(files_to_scan)}/{len(all_files)} files scanned | "
        f"{len(all_sites)} usage sites ({risky} risky) | "
        f"top {len(sites_for_llm)} sent to SE agent"
    )
    logger.info(log_msgs[-1])

    return {
        "usage_sites": sites_for_llm,         # LLM sees top N
        "current_step": "ast_context_complete",
        "messages": log_msgs,
        # Extra stats stored for the UI
        "ast_total_files_scanned": len(files_to_scan),
        "ast_total_sites_found": len(all_sites),
    }

