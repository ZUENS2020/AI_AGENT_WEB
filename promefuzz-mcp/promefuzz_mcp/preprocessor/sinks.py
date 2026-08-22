"""Dangerous-sink scan and short call-path recovery for vuln hunting.

Pure helpers used by MCP tools and (via import) the analysis workflow.
No MCP or LLM dependency.
"""

from __future__ import annotations

import json
import re
from collections import deque
from pathlib import Path
from typing import Any, Iterable, Optional


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc"}
SKIP_DIR_PARTS = {
    ".git",
    ".svn",
    ".hg",
    "__pycache__",
    ".venv",
    "node_modules",
    "CMakeFiles",
    "_deps",
    "fuzz",
    "out",
    "dist",
    "vendor",
    "third_party",
    "thirdparty",
}

# Each rule: compiled pattern, sink name, CWE, workflow signal_id, size-arg hint.
_SINK_RULES: tuple[tuple[re.Pattern[str], str, str, str, str], ...] = (
    (re.compile(r"\bmemcpy\s*\("), "memcpy", "CWE-120", "mem_oob_candidate", "size"),
    (re.compile(r"\bmemmove\s*\("), "memmove", "CWE-120", "mem_oob_candidate", "size"),
    (re.compile(r"\bmemccpy\s*\("), "memccpy", "CWE-120", "mem_oob_candidate", "size"),
    (re.compile(r"\bstrcpy\s*\("), "strcpy", "CWE-120", "mem_oob_candidate", "dest_unbounded"),
    (re.compile(r"\bstrncpy\s*\("), "strncpy", "CWE-120", "mem_oob_candidate", "n"),
    (re.compile(r"\bstrcat\s*\("), "strcat", "CWE-120", "mem_oob_candidate", "dest_unbounded"),
    (re.compile(r"\bstrncat\s*\("), "strncat", "CWE-120", "mem_oob_candidate", "n"),
    (re.compile(r"\bstpcpy\s*\("), "stpcpy", "CWE-120", "mem_oob_candidate", "dest_unbounded"),
    (re.compile(r"\bsprintf\s*\("), "sprintf", "CWE-134", "format_string_candidate", "format"),
    (re.compile(r"\bvsprintf\s*\("), "vsprintf", "CWE-134", "format_string_candidate", "format"),
    (re.compile(r"\bsnprintf\s*\("), "snprintf", "CWE-134", "format_string_candidate", "format"),
    (re.compile(r"\bvsnprintf\s*\("), "vsnprintf", "CWE-134", "format_string_candidate", "format"),
    (re.compile(r"\bfprintf\s*\("), "fprintf", "CWE-134", "format_string_candidate", "format"),
    (re.compile(r"\bprintf\s*\("), "printf", "CWE-134", "format_string_candidate", "format"),
    (re.compile(r"\bmalloc\s*\("), "malloc", "CWE-190", "integer_overflow_candidate", "size"),
    (re.compile(r"\bcalloc\s*\("), "calloc", "CWE-190", "integer_overflow_candidate", "nmemb*size"),
    (re.compile(r"\brealloc\s*\("), "realloc", "CWE-190", "integer_overflow_candidate", "size"),
    (re.compile(r"\breallocarray\s*\("), "reallocarray", "CWE-190", "integer_overflow_candidate", "nmemb*size"),
    (re.compile(r"\bfree\s*\("), "free", "CWE-416", "uaf_candidate", ""),
    (re.compile(r"\boperator\s+delete\b"), "operator_delete", "CWE-416", "uaf_candidate", ""),
    (re.compile(r"\bsystem\s*\("), "system", "CWE-78", "command_injection_candidate", "command"),
    (re.compile(r"\bpopen\s*\("), "popen", "CWE-78", "command_injection_candidate", "command"),
    (re.compile(r"\bexec[lv][ep]?\s*\("), "exec", "CWE-78", "command_injection_candidate", "argv"),
    (re.compile(r"\bfopen\s*\("), "fopen", "CWE-22", "path_traversal_candidate", "path"),
    (re.compile(r"\bopen\s*\("), "open", "CWE-22", "path_traversal_candidate", "path"),
)

_FUNC_DEF_RE = re.compile(
    r"^[A-Za-z_][\w\s\*:&<>:~]*\b([A-Za-z_][\w:]*)\s*\([^;]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{?\s*$"
)
_SKIP_LINE_RE = re.compile(r"^\s*(?://|/\*|\*|#)")


def _is_skipped_dir(path: Path) -> bool:
    for part in path.parts:
        if part in SKIP_DIR_PARTS:
            return True
        if part.startswith(("build-", "build_", "cmake-build-")):
            return True
    return False


def collect_scan_files(
    source_paths: Optional[Iterable[str]] = None,
    meta_path: Optional[str] = None,
    *,
    extra_skip_parts: Optional[set[str]] = None,
    limit: int = 400,
) -> list[Path]:
    """Collect C/C++ files from explicit paths and/or preprocessor meta.json."""
    files: set[Path] = set()
    skip = set(SKIP_DIR_PARTS)
    if extra_skip_parts:
        skip |= {str(x) for x in extra_skip_parts}

    def _allow(path: Path) -> bool:
        if not path.is_file():
            return False
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            return False
        for part in path.parts:
            if part in skip or part.startswith(("build-", "build_", "cmake-build-")):
                return False
        return True

    def _walk(root: Path) -> None:
        if root.is_file():
            if _allow(root):
                files.add(root.resolve())
            return
        if not root.is_dir() or _is_skipped_dir(root):
            return
        try:
            for child in root.rglob("*"):
                if len(files) >= max(1, int(limit)):
                    return
                if child.is_file() and _allow(child):
                    files.add(child.resolve())
        except OSError:
            return

    for raw in list(source_paths or []):
        text = str(raw or "").strip()
        if text:
            _walk(Path(text).expanduser())

    if meta_path:
        meta_file = Path(str(meta_path)).expanduser()
        if meta_file.is_file():
            try:
                doc = json.loads(meta_file.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                doc = {}
            functions = doc.get("functions") if isinstance(doc, dict) else {}
            if isinstance(functions, dict):
                for loc in functions.keys():
                    file_path = str(loc).rsplit(":", 2)[0]
                    p = Path(file_path)
                    if _allow(p):
                        files.add(p.resolve())

    ordered = sorted(files, key=lambda p: str(p))
    return ordered[: max(1, int(limit))]


def _enclosing_function_from_meta(
    meta_index: list[tuple[str, int, str]],
    file_path: str,
    line: int,
) -> str:
    best_name = ""
    best_line = -1
    file_key = str(Path(file_path))
    for loc_file, loc_line, name in meta_index:
        if loc_file != file_key:
            continue
        if loc_line <= line and loc_line >= best_line:
            best_line = loc_line
            best_name = name
    return best_name


def _enclosing_function_from_source(lines: list[str], line: int) -> str:
    idx = max(0, min(int(line), len(lines)) - 1)
    for i in range(idx, -1, -1):
        text = lines[i].rstrip("\n")
        if "{" not in text and not _FUNC_DEF_RE.match(text.strip()):
            continue
        match = _FUNC_DEF_RE.match(text.strip().rstrip("{").strip())
        if match:
            name = match.group(1)
            if name not in {"if", "for", "while", "switch", "catch", "return"}:
                return name
    return ""


def _meta_function_index(meta_path: Optional[str]) -> list[tuple[str, int, str]]:
    if not meta_path:
        return []
    path = Path(str(meta_path)).expanduser()
    if not path.is_file():
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    functions = doc.get("functions") if isinstance(doc, dict) else {}
    out: list[tuple[str, int, str]] = []
    if not isinstance(functions, dict):
        return out
    for loc, obj in functions.items():
        parts = str(loc).rsplit(":", 2)
        file_path = parts[0] if parts else ""
        try:
            line_no = int(parts[1]) if len(parts) >= 2 else 0
        except Exception:
            line_no = 0
        name = ""
        if isinstance(obj, dict):
            name = str(obj.get("name") or "").strip()
        if file_path and name:
            out.append((str(Path(file_path)), line_no, name))
    return out


def scan_dangerous_sinks(
    *,
    source_paths: Optional[list[str]] = None,
    meta_path: Optional[str] = None,
    extra_skip_parts: Optional[set[str]] = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Scan source files for dangerous C/C++ sinks. Returns dict rows."""
    files = collect_scan_files(
        source_paths,
        meta_path,
        extra_skip_parts=extra_skip_parts,
        limit=800,
    )
    meta_index = _meta_function_index(meta_path)
    max_hits = max(1, min(int(limit or 200), 2000))
    hits: list[dict[str, Any]] = []
    for path in files:
        if len(hits) >= max_hits:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, start=1):
            if len(hits) >= max_hits:
                break
            stripped = line.strip()
            if not stripped or _SKIP_LINE_RE.match(stripped):
                continue
            for pattern, sink, cwe, signal_id, size_hint in _SINK_RULES:
                match = pattern.search(line)
                if not match:
                    continue
                enclosing = _enclosing_function_from_meta(meta_index, str(path), i)
                if not enclosing:
                    enclosing = _enclosing_function_from_source(lines, i)
                snippet = line.strip()
                if len(snippet) > 240:
                    snippet = snippet[:237] + "..."
                hits.append(
                    {
                        "file": str(path),
                        "line": i,
                        "column": int(match.start()) + 1,
                        "sink": sink,
                        "cwe": cwe,
                        "signal_id": signal_id,
                        "size_arg_hint": size_hint,
                        "snippet": snippet,
                        "enclosing_function": enclosing,
                    }
                )
                break
    return hits


def _parse_callgraph_edges(doc: Any) -> list[tuple[str, str]]:
    edges: list[tuple[str, str]] = []
    if not isinstance(doc, dict):
        return edges

    raw_edges = doc.get("edges")
    if isinstance(raw_edges, list):
        for item in raw_edges:
            caller = ""
            callee = ""
            if isinstance(item, dict):
                caller = str(item.get("caller") or item.get("callerName") or "").strip()
                callee = str(item.get("callee") or item.get("calleeName") or "").strip()
            elif isinstance(item, (list, tuple)) and len(item) >= 3:
                caller = str(item[0] or "").strip()
                callee = str(item[2] or "").strip()
            if caller and callee:
                edges.append((caller, callee))

    for key in ("callgraph_summary", "nodes"):
        rows = doc.get(key)
        if not isinstance(rows, list):
            continue
        for item in rows:
            if not isinstance(item, dict):
                continue
            caller = str(item.get("caller") or item.get("from") or "").strip()
            callee = str(item.get("callee") or item.get("to") or "").strip()
            if caller and callee:
                edges.append((caller, callee))
    return edges


def load_callgraph_edges(callgraph_path: Optional[str]) -> tuple[list[tuple[str, str]], str]:
    if not callgraph_path:
        return [], "callgraph_missing"
    path = Path(str(callgraph_path)).expanduser()
    if not path.is_file():
        return [], f"callgraph_not_found:{path}"
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        return [], f"callgraph_parse_error:{exc}"
    edges = _parse_callgraph_edges(doc)
    if not edges:
        return [], "callgraph_empty"
    return edges, ""


def find_call_paths(
    target_symbol: str,
    *,
    callgraph_path: Optional[str] = None,
    edges: Optional[list[tuple[str, str]]] = None,
    public_apis: Optional[list[str]] = None,
    max_hops: int = 6,
    max_paths: int = 8,
) -> dict[str, Any]:
    """Reverse-BFS from a sink/symbol to public (or any) callers."""
    symbol = str(target_symbol or "").strip()
    if not symbol:
        return {
            "status": "error",
            "error": "target_symbol is required",
            "degraded": True,
            "degraded_reason": "missing_target_symbol",
            "paths": [],
        }
    reason = ""
    graph_edges = list(edges or [])
    if not graph_edges:
        graph_edges, reason = load_callgraph_edges(callgraph_path)
    if not graph_edges:
        return {
            "status": "success",
            "target_symbol": symbol,
            "degraded": True,
            "degraded_reason": reason or "callgraph_missing",
            "paths": [],
        }

    reverse: dict[str, set[str]] = {}
    for caller, callee in graph_edges:
        reverse.setdefault(callee, set()).add(caller)

    public = {str(x).strip() for x in list(public_apis or []) if str(x).strip()}
    hops = max(1, min(int(max_hops or 6), 16))
    limit_paths = max(1, min(int(max_paths or 8), 32))

    paths: list[list[str]] = []
    seen_paths: set[tuple[str, ...]] = set()
    queue: deque[list[str]] = deque([[symbol]])
    visited_nodes: set[str] = {symbol}
    while queue and len(paths) < limit_paths:
        path = queue.popleft()
        node = path[-1]
        if len(path) > 1:
            at_public = bool(public) and node in public
            at_leaf = node not in reverse or not reverse.get(node)
            if at_public or (not public and at_leaf) or len(path) - 1 >= hops:
                key = tuple(reversed(path))
                if key not in seen_paths:
                    seen_paths.add(key)
                    paths.append(list(key))
                if at_public or len(path) - 1 >= hops:
                    continue
        if len(path) - 1 >= hops:
            continue
        for caller in sorted(reverse.get(node, set())):
            if caller in path:
                continue
            visited_nodes.add(caller)
            queue.append(path + [caller])

    return {
        "status": "success",
        "target_symbol": symbol,
        "degraded": False,
        "degraded_reason": "",
        "edge_count": len(graph_edges),
        "paths": paths[:limit_paths],
        "public_api_count": len(public),
    }


def resolve_meta_path(info_repo_path: str = "", meta_path: str = "") -> Path:
    candidates = [meta_path, info_repo_path]
    for raw in candidates:
        text = str(raw or "").strip()
        if not text:
            continue
        path = Path(text).expanduser()
        if path.is_file():
            return path
        if path.is_dir():
            for rel in ("meta.json", "work/meta/meta.json", "meta/meta.json"):
                nested = path / rel
                if nested.is_file():
                    return nested
            try:
                found = sorted(path.rglob("meta.json"))
            except OSError:
                found = []
            if found:
                return found[0]
    raise FileNotFoundError("meta.json not found from info_repo_path/meta_path")


def lookup_function_info(
    *,
    function_location: str,
    info_repo_path: str = "",
    meta_path: str = "",
    context_lines: int = 40,
) -> dict[str, Any]:
    """Resolve a function by loc key or name using preprocessor meta.json."""
    loc = str(function_location or "").strip()
    if not loc:
        return {"status": "error", "error": "function_location is required", "found": False}
    try:
        meta_file = resolve_meta_path(info_repo_path, meta_path)
        doc = json.loads(meta_file.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        return {"status": "error", "error": str(exc), "found": False, "location": loc}
    if not isinstance(doc, dict):
        return {"status": "error", "error": "invalid meta json", "found": False, "location": loc}

    functions = doc.get("functions") if isinstance(doc.get("functions"), dict) else {}
    match_obj: dict[str, Any] | None = None
    match_loc = ""
    if loc in functions and isinstance(functions.get(loc), dict):
        match_obj = dict(functions[loc])
        match_loc = loc
    else:
        loc_prefix = loc
        name_query = loc
        if ":" in loc:
            name_query = ""
        for key, obj in functions.items():
            if not isinstance(obj, dict):
                continue
            key_txt = str(key)
            name = str(obj.get("name") or "")
            if loc_prefix and (key_txt == loc or key_txt.startswith(loc_prefix + ":") or key_txt.startswith(loc_prefix)):
                if loc in key_txt or key_txt.startswith(str(Path(loc_prefix))):
                    match_obj = dict(obj)
                    match_loc = key_txt
                    break
            if name_query and name == name_query:
                match_obj = dict(obj)
                match_loc = key_txt
                break
        if match_obj is None and ":" in loc:
            file_part, _, rest = loc.partition(":")
            try:
                want_line = int(str(rest).split(":", 1)[0])
            except Exception:
                want_line = 0
            for key, obj in functions.items():
                if not isinstance(obj, dict):
                    continue
                parts = str(key).rsplit(":", 2)
                if len(parts) < 2:
                    continue
                if str(Path(parts[0])) != str(Path(file_part)):
                    continue
                try:
                    line_no = int(parts[1])
                except Exception:
                    continue
                if want_line and line_no == want_line:
                    match_obj = dict(obj)
                    match_loc = str(key)
                    break

    if match_obj is None:
        return {
            "status": "success",
            "found": False,
            "location": loc,
            "meta_path": str(meta_file),
            "name": "",
            "signature": "",
        }

    parts = str(match_loc).rsplit(":", 2)
    file_path = parts[0] if parts else ""
    try:
        line_no = int(parts[1]) if len(parts) >= 2 else 0
    except Exception:
        line_no = 0
    snippet = ""
    start = line_no
    end = line_no
    src = Path(file_path)
    if src.is_file() and line_no > 0:
        try:
            src_lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
            ctx = max(1, int(context_lines or 40))
            start = max(1, line_no - ctx // 2)
            end = min(len(src_lines), start + ctx - 1)
            snippet = "\n".join(src_lines[start - 1 : end])
        except OSError:
            snippet = ""
    name = str(match_obj.get("name") or "")
    params = match_obj.get("params") or match_obj.get("parameters") or []
    return_type = str(match_obj.get("returnType") or match_obj.get("return_type") or "")
    signature = str(match_obj.get("signature") or "").strip()
    if not signature:
        param_txt = ", ".join(str(x) for x in params) if isinstance(params, list) else ""
        signature = f"{return_type} {name}({param_txt})".strip()
    return {
        "status": "success",
        "found": True,
        "location": match_loc or loc,
        "meta_path": str(meta_file),
        "name": name,
        "signature": signature,
        "return_type": return_type,
        "params": params,
        "file": file_path,
        "line": line_no,
        "heldby_namespace": str(match_obj.get("heldbyNamespace") or ""),
        "heldby_class": str(match_obj.get("heldbyClass") or ""),
        "decl_loc": str(match_obj.get("declLoc") or match_loc),
        "start_line": start,
        "end_line": end,
        "snippet": snippet,
    }
