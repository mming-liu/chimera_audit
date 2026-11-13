"""Multi-hop taint slicer for Python and Java source code."""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Node:
    """AST node in taint graph."""
    id: str
    function: str
    file: str
    line: int
    code: str


@dataclass
class Edge:
    """Taint flow edge in graph."""
    source: str  # node id
    target: str  # node id
    label: str   # e.g., "parameter passing"


@dataclass
class Hop:
    """Single hop in multi-hop call chain."""
    hop_n: int
    function: str
    code: str
    file: str
    line_start: int


@dataclass
class SliceResult:
    """Result of source code slicing."""
    entry_function: str
    entry_route: str
    hops: list[Hop] = field(default_factory=list)
    taint_sources: list[str] = field(default_factory=list)
    taint_sinks: list[str] = field(default_factory=list)
    taint_nodes: list[Node] = field(default_factory=list)
    taint_edges: list[Edge] = field(default_factory=list)


def mask_triple_quoted(source: str) -> tuple[str, dict]:
    """
    Mask triple-quoted strings, preserving line numbers.
    
    Args:
        source: Python source code
        
    Returns:
        (masked_source, restoration_map)
    """
    masked = source
    restoration = {}
    
    # Match """...""" or '''...'''
    pattern = r'("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\')'
    
    matches = list(re.finditer(pattern, source))
    
    for match in reversed(matches):  # reverse to preserve indices
        start, end = match.span()
        original = source[start:end]
        # Replace with spaces, preserving newlines
        replacement = ''.join(' ' if c != '\n' else '\n' for c in original)
        masked = masked[:start] + replacement + masked[end:]
        restoration[start] = original
    
    return masked, restoration


def extract_python_routes(source: str) -> list[tuple[str, str, int]]:
    """
    Extract Python routes (@app, @router, @api_view).
    
    Returns:
        List of (route_pattern, function_name, line_number)
    """
    routes = []
    lines = source.split('\n')
    
    # Pattern: @(app|router|blueprint|api_view)
    decorator_pattern = r'@(?:app|router|blueprint)\.(get|post|put|delete|patch|route)\s*\('
    api_view_pattern = r'@api_view\s*\('
    
    for i, line in enumerate(lines):
        if re.search(decorator_pattern, line) or re.search(api_view_pattern, line):
            # Look for function definition in next few lines
            for j in range(i + 1, min(i + 5, len(lines))):
                func_match = re.search(r'def\s+(\w+)\s*\(', lines[j])
                if func_match:
                    routes.append((line.strip(), func_match.group(1), j + 1))
                    break
    
    return routes


def extract_java_routes(source: str) -> list[tuple[str, str, int]]:
    """
    Extract Java Spring routes (@GetMapping, @PostMapping, etc.).
    
    Returns:
        List of (route_pattern, method_name, line_number)
    """
    routes = []
    lines = source.split('\n')
    
    # Pattern: @(Get|Post|Put|Delete|Patch|Request)Mapping
    mapping_pattern = r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*(?:\([^)]*\))?'
    
    for i, line in enumerate(lines):
        if re.search(mapping_pattern, line):
            # Look for method definition in next few lines (accounting for multi-line signatures)
            for j in range(i + 1, min(i + 10, len(lines))):
                # Match method signature
                method_match = re.search(r'(?:public|private|protected)?\s*(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+\s*)?{', lines[j])
                if method_match:
                    routes.append((line.strip(), method_match.group(1), j + 1))
                    break
    
    return routes


def extract_helper_calls(code: str) -> list[str]:
    """Extract function/method calls from code."""
    # Match function calls: identifier(...)
    pattern = r'\b([a-zA-Z_]\w*)\s*\('
    return re.findall(pattern, code)


def extract_taint_sources(code: str, language: str) -> list[str]:
    """Extract potential taint sources (user input)."""
    sources = []
    
    if language == "python":
        patterns = [
            r"request\.(?:args|form|json|data)\[[\'\"](\w+)[\'\"]\]",
            r"request\.(?:args|form|json|data)\.get\(['\"](\w+)",
            r"@(?:app|router)\.\w+\([^)]*\)\s*def\s+\w+\((.*?)\)",  # route params
        ]
    elif language == "java":
        patterns = [
            r"@(?:RequestParam|PathVariable|RequestBody)\s*(?:\([^)]*\))?\s+\w+\s+(\w+)",
            r"@RequestMapping\([^)]*\)\s*(?:public|private)?\s+\w+\s+\w+\((.*?)\)",
        ]
    else:
        return sources
    
    for pattern in patterns:
        matches = re.findall(pattern, code)
        sources.extend(m for m in matches if m)
    
    return list(set(sources))


def extract_taint_sinks(code: str, language: str) -> list[str]:
    """Extract potential taint sinks (dangerous operations)."""
    sinks = []
    
    if language == "python":
        patterns = [
            r"(?:cursor|execute)\.(execute|executescript|executemany)\s*\(",
            r"open\s*\(",
            r"FileWriter\s*\(",
            r"os\.(system|exec|popen)",
            r"subprocess\.(call|run|popen)\s*\(",
        ]
    elif language == "java":
        patterns = [
            r"(?:stmt|ps|query)\.(execute|addBatch)\s*\(",
            r"new\s+FileWriter\s*\(",
            r"new\s+File\s*\(",
            r"Runtime\.getRuntime\(\)\.exec\s*\(",
        ]
    else:
        return sinks
    
    for pattern in patterns:
        if re.search(pattern, code):
            sinks.append(pattern.split('(')[0].strip())
    
    return list(set(sinks))


def slice_code(code: str, language: str, filename: str = "unknown") -> SliceResult:
    """
    Slice multi-hop taint from source code.
    
    Args:
        code: Source code string
        language: "python" or "java"
        filename: Original filename
        
    Returns:
        SliceResult with hops, taint graph, etc.
    """
    # Mask triple-quoted strings
    masked_code, _ = mask_triple_quoted(code) if language == "python" else (code, {})
    
    # Extract routes
    if language == "python":
        routes = extract_python_routes(masked_code)
    elif language == "java":
        routes = extract_java_routes(masked_code)
    else:
        return SliceResult("", "")
    
    if not routes:
        return SliceResult("", "")
    
    # Build result from first route
    route_pattern, entry_func, line_num = routes[0]
    lines = code.split('\n')
    
    # Extract entry function body
    entry_code = ""
    brace_count = 0
    start_idx = line_num - 1
    for i in range(start_idx, len(lines)):
        line = lines[i]
        brace_count += line.count('{') - line.count('}')
        entry_code += line + '\n'
        if brace_count == 0 and i > start_idx:
            break
    
    # Extract helper calls (hops)
    helper_calls = extract_helper_calls(entry_code)
    hops = [
        Hop(
            hop_n=i + 1,
            function=call,
            code=f"// Call to {call}",
            file=filename,
            line_start=line_num + i
        )
        for i, call in enumerate(helper_calls[:5])  # max 5 hops
    ]
    
    # Extract taint sources and sinks
    taint_sources = extract_taint_sources(code, language)
    taint_sinks = extract_taint_sinks(entry_code, language)
    
    # Build taint nodes and edges
    nodes = [
        Node(
            id=entry_func,
            function=entry_func,
            file=filename,
            line=line_num,
            code=entry_code[:100]
        )
    ]
    for hop in hops:
        nodes.append(Node(
            id=hop.function,
            function=hop.function,
            file=filename,
            line=hop.line_start,
            code=hop.code
        ))
    
    edges = []
    for i, hop in enumerate(hops):
        if i == 0:
            edges.append(Edge(source=entry_func, target=hop.function, label="call"))
        else:
            edges.append(Edge(source=hops[i - 1].function, target=hop.function, label="call"))
    
    return SliceResult(
        entry_function=entry_func,
        entry_route=route_pattern,
        hops=hops,
        taint_sources=taint_sources,
        taint_sinks=taint_sinks,
        taint_nodes=nodes,
        taint_edges=edges
    )
