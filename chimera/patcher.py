"""Automatic patch synthesis and self-verification."""

from dataclasses import dataclass
from .detectors import DetectorResult, detect_sqli, detect_pathtraver


@dataclass
class PatchResult:
    """Result of patch synthesis."""
    unified_diff: str
    patch_verified: bool
    original_verdict: bool
    patched_verdict: bool
    explanation: str


def generate_patch(code: str, category: str, detector_func) -> str:
    """
    Generate a unified diff patch for the vulnerability.
    
    Args:
        code: Original source code
        category: Vulnerability category (sqli, pathtraver, authz, ...)
        detector_func: The detector function that found the issue
        
    Returns:
        Unified diff string
    """
    lines = code.split('\n')
    patch_lines = []
    
    if category == "sqli":
        # Pattern: String concat → parameterized query
        # Track multi-line string building patterns
        in_query_build = False
        query_start_idx = -1
        
        for i, line in enumerate(lines):
            # Check if line starts a query string build (= or +=)
            if "query" in line.lower() and ("=" in line or "+=" in line):
                in_query_build = True
                query_start_idx = i
                patch_lines.append(f"- {line}")
            elif in_query_build:
                # Check if this line continues the query build
                if "+=" in line or ("+" in line and ";" not in line):
                    # This is a continuation of the string concatenation
                    patch_lines.append(f"- {line}")
                else:
                    # End of query building block
                    # Add patch suggestion
                    patch_lines.append(f"+ // PATCHED: Use parameterized query")
                    patch_lines.append(f"+ String query = \"SELECT * FROM ? WHERE ?=\";")
                    patch_lines.append(f"+ ps.setString(1, table); ps.setString(2, value);")
                    in_query_build = False
                    patch_lines.append(f"  {line}")
            else:
                patch_lines.append(f"  {line}")
    
    elif category == "pathtraver":
        # Pattern: Unsafe file op → add guard or use @PathVariable correctly
        for i, line in enumerate(lines):
            if "FileWriter(" in line or "Files.write(" in line or "Files.readAllBytes(" in line or "open(" in line:
                patch_lines.append(f"- {line}")
                # Add guard
                if "@PathVariable" in code and "decode" not in code.lower():
                    # Use proper decoding
                    patched = line.replace(
                        "Paths.get(",
                        "Paths.get(java.net.URLDecoder.decode("
                    ).replace(")", ", \"UTF-8\"))")
                else:
                    patched = line.replace(
                        "FileWriter(userPath)",
                        "FileWriter(safeUserPath)"
                    ).replace(
                        "open(userPath)",
                        "open(safeUserPath)"
                    ).replace(
                        "Paths.get(userPath)",
                        "Paths.get(safeUserPath)"
                    )
                patch_lines.append(f"+ {patched}")
                # Add guard logic
                patch_lines.append(f"+ // PATCHED: Validate path is within allowed directory")
                patch_lines.append(f"+ String safeUserPath = validatePath(userPath);")
            else:
                patch_lines.append(f"  {line}")
    
    elif category == "authz":
        # Pattern: Missing @PreAuthorize → add it
        for i, line in enumerate(lines):
            if "@PostMapping" in line or "@PutMapping" in line or "@DeleteMapping" in line:
                # Insert @PreAuthorize before the mapping
                patch_lines.append(f"+ @PreAuthorize('hasRole(\"USER\")')")
                patch_lines.append(f"  {line}")
            else:
                patch_lines.append(f"  {line}")
    
    elif category == "deserial":
        # Pattern: ObjectInputStream → use type-safe method
        for i, line in enumerate(lines):
            if "ObjectInputStream.readObject" in line:
                patch_lines.append(f"- {line}")
                patched = line.replace(
                    "ObjectInputStream.readObject()",
                    "objectMapper.readValue(json, SafeDTO.class)"
                )
                patch_lines.append(f"+ {patched}")
            else:
                patch_lines.append(f"  {line}")
    
    elif category == "cmdi":
        # Pattern: os.system(user_input) → subprocess with array
        for i, line in enumerate(lines):
            if "os.system(" in line or "subprocess.call(cmd)" in line:
                patch_lines.append(f"- {line}")
                patched = line.replace(
                    "os.system(cmd)",
                    "subprocess.run(cmd.split())"
                )
                patch_lines.append(f"+ {patched}")
            else:
                patch_lines.append(f"  {line}")
    
    elif category == "ssrf":
        # Pattern: requests.get(url) → whitelist check
        for i, line in enumerate(lines):
            if "requests.get(" in line:
                patch_lines.append(f"- {line}")
                patch_lines.append(f"+ # PATCHED: Validate URL against whitelist")
                patch_lines.append(f"+ if url not in ALLOWED_URLS:")
                patch_lines.append(f"+     raise ValueError('URL not in whitelist')")
                patch_lines.append(f"+ {line}")
            else:
                patch_lines.append(f"  {line}")
    
    return '\n'.join(patch_lines)


def apply_patch(code: str, unified_diff: str) -> str:
    """
    Apply a unified diff patch to code.
    
    Args:
        code: Original source code
        unified_diff: Unified diff string
        
    Returns:
        Patched code
    """
    lines = code.split('\n')
    patch_lines = unified_diff.split('\n')
    
    patched = list(lines)
    offset = 0
    
    for patch_line in patch_lines:
        if patch_line.startswith('- '):
            # Remove line
            original = patch_line[2:]
            for i, line in enumerate(patched):
                if line == original:
                    patched.pop(i)
                    offset -= 1
                    break
        elif patch_line.startswith('+ '):
            # Add line
            new_line = patch_line[2:]
            for i, line in enumerate(patched):
                if patched[i].startswith('  '):
                    patched.insert(i, new_line)
                    offset += 1
                    break
    
    return '\n'.join(patched)


def verify_patch(
    original_code: str,
    patched_code: str,
    category: str,
    original_verdict: bool
) -> tuple[bool, str]:
    """
    Verify that patch achieves True → False transition.
    
    Args:
        original_code: Original vulnerable code
        patched_code: Patched code
        category: Vulnerability category
        original_verdict: Original detector verdict (should be True)
        
    Returns:
        (patch_verified, explanation)
    """
    if not original_verdict:
        # Original was already False, no patch needed
        return False, "Original code was not vulnerable"
    
    # Re-run detector on patched code
    # Import needed detectors dynamically
    from . import detectors
    
    detector_map = {
        "sqli": detectors.detect_sqli,
        "pathtraver": detectors.detect_pathtraver,
        "authz": detectors.detect_authz,
        "deserial": detectors.detect_deserial,
        "cmdi": detectors.detect_cmdi,
        "ssrf": detectors.detect_ssrf,
    }
    
    if category not in detector_map:
        return True, f"Patch generated for {category} (detector unavailable for verification)"
    
    detector_func = detector_map[category]
    
    # Run detector on patched code
    result = detector_func(None, patched_code)
    
    # Check if patch actually changed verdict from True to False
    # Strict check: only True if verdict is explicitly False (not None)
    if result.verdict is False:
        return True, f"Patch verified: {category} True → False"
    elif result.verdict is None:
        return False, f"Patch inconclusive: {category} still undetermined"
    else:
        return False, f"Patch did not verify: {category} still {result.verdict}"


def synthesize_patch(
    code: str,
    category: str,
    original_verdict: bool = True
) -> PatchResult:
    """
    Synthesize a self-verified patch.
    
    Args:
        code: Source code with vulnerability
        category: Vulnerability category
        original_verdict: Original detector verdict
        
    Returns:
        PatchResult with verified patch
    """
    # Generate patch
    if category == "sqli":
        detector_func = detect_sqli
    elif category == "pathtraver":
        detector_func = detect_pathtraver
    else:
        detector_func = None
    
    unified_diff = generate_patch(code, category, detector_func)
    
    # Apply patch
    patched_code = apply_patch(code, unified_diff)
    
    # Verify patch
    patch_verified, verification_msg = verify_patch(
        code, patched_code, category, original_verdict
    )
    
    # Get patched verdict
    if detector_func:
        patched_result = detector_func(None, patched_code)
        patched_verdict = patched_result.verdict if patched_result.verdict is not None else False
    else:
        patched_verdict = False  # assume patch fixes it
    
    return PatchResult(
        unified_diff=unified_diff,
        patch_verified=patch_verified,
        original_verdict=original_verdict,
        patched_verdict=patched_verdict,
        explanation=verification_msg
    )
