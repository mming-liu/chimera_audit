"""Kleene three-valued (True/False/None) deterministic security detectors."""

import re
from dataclasses import dataclass
from typing import Optional
from .slicer import SliceResult


@dataclass
class DetectorResult:
    """Result of deterministic security check."""
    category: str                 # "sqli" | "pathtraver" | "authz" | "deserial" | "cmdi" | "ssrf"
    verdict: Optional[bool]       # True=vulnerable, False=safe, None=undetermined
    evidence: list[str] = None    # supporting code fragments
    cwe_id: str = ""             # e.g. "CWE-89"
    cvss_base: float = 0.0       # CVSS base score
    cvss_vector: str = ""        # CVSS 3.1 vector string
    explanation: str = ""        # why True/False/None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []


def detect_sqli(slice_result: SliceResult, code: str = "") -> DetectorResult:
    """
    SQL Injection detector.
    
    True: String concatenation into SQL
    False: Parameterized queries
    None: Ambiguous
    """
    evidence = []
    
    # Pattern 1: String concatenation into SQL (check first)
    concat_patterns = [
        r"[\'\"][^\'\"]*[\'\"].*[+].*[\'\"][^\'\"]*[\'\"]",  # concat with +
        r"query\s*[+=].*[+]",                                  # query += ... +
        r"f[\'\"]\{.*\}",                                      # f-string with var
        r"\.format\s*\(",                                      # .format(
        r"LIKE\s+[\'\"]\s*%",                                  # LIKE '%...
        r"execute.*[+]",                                       # execute ... +
    ]
    
    for pattern in concat_patterns:
        if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
            evidence.append(f"Found string concat pattern")
            return DetectorResult(
                category="sqli",
                verdict=True,
                evidence=evidence,
                cwe_id="CWE-89",
                cvss_base=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                explanation="String concatenation detected into SQL query"
            )
    
    # Pattern 2: Parameterized binding (safe) - check before ambiguous
    safe_patterns = [
        r"\?",                          # ? placeholder
        r":\w+",                        # :paramName
        r"addValue\s*\(",              # addValue(
        r"setString\s*\(",             # setString(
        r"setInt\s*\(",                # setInt(
        r"#{.*}",                      # MyBatis #{}
        r"\.eq\s*\(",                  # query builder .eq(
        r"DatabaseMetaData\.getTables",  # metadata API
    ]
    
    for pattern in safe_patterns:
        if re.search(pattern, code):
            evidence.append(f"Found safe pattern: {pattern}")
            return DetectorResult(
                category="sqli",
                verdict=False,
                evidence=evidence,
                cwe_id="CWE-89",
                cvss_base=0.0,
                cvss_vector="",
                explanation="Parameterized query detected"
            )
    
    # Ambiguous case - only return None if we see SQL keywords without clear safe/unsafe pattern
    if any(kw in code.upper() for kw in ["EXECUTE", "QUERY", "SELECT", "INSERT", "UPDATE", "DELETE"]):
        # More evidence needed, but no clear safe pattern found
        return DetectorResult(
            category="sqli",
            verdict=None,
            evidence=evidence,
            cwe_id="CWE-89",
            cvss_base=0.0,
            explanation="Insufficient evidence for SQL injection"
        )
    
    return DetectorResult(
        category="sqli",
        verdict=False,
        evidence=evidence,
        cwe_id="CWE-89",
        cvss_base=0.0,
        explanation="No SQL injection patterns detected"
    )


def detect_pathtraver(slice_result: SliceResult, code: str = "") -> DetectorResult:
    """
    Path Traversal detector.
    
    True: Unsafe file operations with user input
    False: Guarded by normalization or container
    None: Ambiguous
    """
    evidence = []
    
    # Pattern 1: Unsafe file operations
    unsafe_patterns = [
        r"FileWriter\s*\(\s*\w+",          # FileWriter(userPath)
        r"Files\.write\s*\(\s*\w+",        # Files.write(userPath)
        r"open\s*\(\s*\w+",                # open(userPath)
        r"new\s+File\s*\(\s*\w+",         # new File(userPath)
        r"fopen\s*\(\s*\w+",               # fopen(userPath)
    ]
    
    for pattern in unsafe_patterns:
        if re.search(pattern, code):
            evidence.append(f"Found unsafe file operation: {pattern}")
            
            # Check if this is single-segment @PathVariable (Java/Spring guarded by Tomcat)
            if "@PathVariable" in code and "URLDecoder" not in code and "{*" not in code:
                # Tomcat + Spring 6.1 container guard
                return DetectorResult(
                    category="pathtraver",
                    verdict=False,
                    evidence=evidence + ["Single-segment @PathVariable guarded by Tomcat"],
                    cwe_id="CWE-22",
                    cvss_base=0.0,
                    explanation="Container (Tomcat 10.1 + Spring 6.1) normalizes single-segment @PathVariable"
                )
            
            return DetectorResult(
                category="pathtraver",
                verdict=True,
                evidence=evidence,
                cwe_id="CWE-22",
                cvss_base=8.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                explanation="Unsafe file operation with user input detected"
            )
    
    # Pattern 2: Safe guarding
    safe_patterns = [
        r"normalize\s*\(\s*\)\.startsWith",       # normalize().startsWith()
        r"Path\.relative_to\s*\(",                # Path.relative_to()
        r"URLDecoder\.decode\s*\(",               # URLDecoder.decode()
        r"\.getCanonicalPath\s*\(\)\.startsWith", # getCanonicalPath().startsWith()
    ]
    
    for pattern in safe_patterns:
        if re.search(pattern, code):
            evidence.append(f"Found guard pattern: {pattern}")
            return DetectorResult(
                category="pathtraver",
                verdict=False,
                evidence=evidence,
                cwe_id="CWE-22",
                cvss_base=0.0,
                explanation="Path traversal guarded by normalization"
            )
    
    # Ambiguous
    if "path" in code.lower() or "file" in code.lower():
        return DetectorResult(
            category="pathtraver",
            verdict=None,
            evidence=evidence,
            cwe_id="CWE-22",
            explanation="Insufficient evidence for path traversal"
        )
    
    return DetectorResult(
        category="pathtraver",
        verdict=False,
        evidence=evidence,
        cwe_id="CWE-22",
        explanation="No path traversal patterns detected"
    )


def detect_authz(slice_result: SliceResult, code: str = "") -> DetectorResult:
    """
    Authorization detector (AUTHZ_SIBLING_GUARD).
    
    True: Write endpoint missing auth while sibling has it
    False: Proper authorization in place
    None: Insufficient evidence
    """
    evidence = []
    
    # Check for write methods (POST, PUT, DELETE)
    write_patterns = [
        r"@(?:Post|Put|Delete|Patch)Mapping",
        r"@(?:app|router)\.(?:post|put|delete|patch)",
    ]
    
    is_write = any(re.search(p, code) for p in write_patterns)
    
    if not is_write:
        return DetectorResult(
            category="authz",
            verdict=False,
            evidence=evidence,
            cwe_id="CWE-862",
            explanation="Not a write endpoint"
        )
    
    # Check for auth guards
    auth_patterns = [
        r"@PreAuthorize",
        r"@Secured",
        r"Depends\s*\(\s*get_current_user",
        r"@require_auth",
        r"@login_required",
    ]
    
    has_auth = any(re.search(p, code) for p in auth_patterns)
    
    if not has_auth:
        evidence.append("Write endpoint with NO auth guard")
        return DetectorResult(
            category="authz",
            verdict=None,  # AUTHZ_SIBLING_GUARD requires cross-method check
            evidence=evidence,
            cwe_id="CWE-862",
            cvss_base=8.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            explanation="Write endpoint missing authorization guard"
        )
    
    evidence.append("Write endpoint with auth guard")
    return DetectorResult(
        category="authz",
        verdict=False,
        evidence=evidence,
        cwe_id="CWE-862",
        explanation="Authorization guard present"
    )


def detect_deserial(slice_result: SliceResult, code: str = "") -> DetectorResult:
    """
    Deserialization detector.
    
    True: Unsafe deserialization
    False: Safe deserialization
    None: Ambiguous
    """
    evidence = []
    
    # Pattern 1: Unsafe deserialization
    unsafe_patterns = [
        r"ObjectInputStream\.readObject",
        r"yaml\.load\s*\(",  # without SafeLoader
        r"fastjson\.(parse|parseObject)",
        r"pickle\.load",
        r"pickle\.loads",
        r"eval\s*\(",
        r"exec\s*\(",
    ]
    
    for pattern in unsafe_patterns:
        if re.search(pattern, code):
            evidence.append(f"Found unsafe deserialize: {pattern}")
            
            # Check for SafeLoader in yaml
            if "yaml.load" in code and "yaml.SafeLoader" in code:
                return DetectorResult(
                    category="deserial",
                    verdict=False,
                    evidence=evidence + ["Uses yaml.SafeLoader"],
                    cwe_id="CWE-502",
                    cvss_base=0.0,
                    explanation="Safe YAML loader configured"
                )
            
            return DetectorResult(
                category="deserial",
                verdict=True,
                evidence=evidence,
                cwe_id="CWE-502",
                cvss_base=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                explanation="Unsafe deserialization detected"
            )
    
    # Pattern 2: Safe deserialization
    safe_patterns = [
        r"readValue\s*\(\s*.*,\s*\w+\.class",  # concrete type
        r"@JsonTypeInfo\s*\(\s*use\s*=\s*Id\.NONE",
        r"yaml\.safe_load",
    ]
    
    for pattern in safe_patterns:
        if re.search(pattern, code):
            evidence.append(f"Found safe pattern: {pattern}")
            return DetectorResult(
                category="deserial",
                verdict=False,
                evidence=evidence,
                cwe_id="CWE-502",
                explanation="Safe deserialization method"
            )
    
    # Ambiguous
    if "json" in code.lower() or "serialize" in code.lower():
        return DetectorResult(
            category="deserial",
            verdict=None,
            evidence=evidence,
            cwe_id="CWE-502",
            explanation="Insufficient evidence for unsafe deserialization"
        )
    
    return DetectorResult(
        category="deserial",
        verdict=False,
        evidence=evidence,
        cwe_id="CWE-502",
        explanation="No deserialization patterns detected"
    )


def detect_cmdi(slice_result: SliceResult, code: str = "") -> DetectorResult:
    """
    Command Injection detector.
    
    True: User input in shell/exec command
    False: Safe command execution
    None: Ambiguous
    """
    evidence = []
    
    # Pattern 1: Unsafe command execution
    unsafe_patterns = [
        r"os\.system\s*\(\s*\w+",
        r"subprocess\.(call|run|popen|check_call)\s*\(\s*\w+",
        r"Runtime\.getRuntime\(\)\.exec\s*\(\s*\w+",
        r"ProcessBuilder\s*\(\s*\w+",
    ]
    
    for pattern in unsafe_patterns:
        if re.search(pattern, code):
            evidence.append(f"Found unsafe exec: {pattern}")
            return DetectorResult(
                category="cmdi",
                verdict=True,
                evidence=evidence,
                cwe_id="CWE-78",
                cvss_base=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                explanation="Command injection via user input detected"
            )
    
    # Pattern 2: Safe command execution (array-based)
    safe_patterns = [
        r"subprocess\.(call|run)\s*\(\s*\[",  # array
        r"ProcessBuilder\s*\(\s*\[",          # array
        r"shlex\.quote",                      # properly escaped
    ]
    
    for pattern in safe_patterns:
        if re.search(pattern, code):
            evidence.append(f"Found safe pattern: {pattern}")
            return DetectorResult(
                category="cmdi",
                verdict=False,
                evidence=evidence,
                cwe_id="CWE-78",
                explanation="Safe command execution method"
            )
    
    return DetectorResult(
        category="cmdi",
        verdict=False,
        evidence=evidence,
        cwe_id="CWE-78",
        explanation="No command injection patterns detected"
    )


def detect_ssrf(slice_result: SliceResult, code: str = "") -> DetectorResult:
    """
    Server-Side Request Forgery detector.
    
    True: User input in HTTP request URL
    False: URL properly validated/constrained
    None: Ambiguous
    """
    evidence = []
    
    # Pattern 1: Unsafe SSRF
    unsafe_patterns = [
        r"requests\.get\s*\(\s*\w+",
        r"urllib\.urlopen\s*\(\s*\w+",
        r"httpx\.get\s*\(\s*\w+",
        r"fetch\s*\(\s*\w+",
    ]
    
    for pattern in unsafe_patterns:
        if re.search(pattern, code):
            evidence.append(f"Found user-controlled request: {pattern}")
            
            # Check for safe patterns
            safe_guard = re.search(r"whitelist|startswith|in \[", code)
            if safe_guard:
                return DetectorResult(
                    category="ssrf",
                    verdict=False,
                    evidence=evidence + ["URL whitelist guard detected"],
                    cwe_id="CWE-918",
                    explanation="SSRF guarded by URL whitelist"
                )
            
            return DetectorResult(
                category="ssrf",
                verdict=True,
                evidence=evidence,
                cwe_id="CWE-918",
                cvss_base=8.6,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                explanation="Server-side request forgery detected"
            )
    
    return DetectorResult(
        category="ssrf",
        verdict=False,
        evidence=evidence,
        cwe_id="CWE-918",
        explanation="No SSRF patterns detected"
    )
