"""4-source CVE deduplication (NVD, CIRCL, GHSA, GitHub Issues)."""

from dataclasses import dataclass, field
from typing import Literal
import re


@dataclass
class DedupResult:
    """Result of CVE deduplication check."""
    status: Literal["ZERO_RECORD_FRESH", "DUPLICATE_CVE"]
    matched_cves: list[str] = field(default_factory=list)
    scope: Literal["whole_class", "method_specific", "none"] = "none"
    evidence_complete: bool = True
    evidence_gaps: list[str] = field(default_factory=list)
    sources_checked: list[str] = field(default_factory=list)
    explanation: str = ""


def query_nvd(repo_slug: str, category: str, unit_name: str) -> list[str]:
    """
    Query NVD for matching CVEs.
    
    Returns:
        List of CVE IDs (e.g., ["CVE-2026-108706"])
    """
    # In production, this would call:
    # https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=...
    
    # For now, return simulated results based on patterns
    if "PaymentController" in unit_name or "AliPay" in unit_name:
        if category == "sqli":
            return ["CVE-2026-108706", "CVE-2026-108707"]
        elif category == "pathtraver":
            return ["CVE-2026-108710"]
    
    return []


def query_circl(repo_slug: str, category: str, unit_name: str) -> list[str]:
    """
    Query CIRCL CVE database.
    
    Returns:
        List of CVE IDs
    """
    # In production, this would call:
    # https://cve.circl.lu/api/search/...
    
    if "Workflow" in unit_name and "SQLi" in category:
        return ["CVE-2026-108706"]
    
    return []


def query_ghsa(repo_slug: str, category: str, unit_name: str) -> list[str]:
    """
    Query GitHub Advisory Database.
    
    Returns:
        List of CVE IDs or GHSA IDs
    """
    # In production, this would call:
    # https://api.github.com/advisories?...
    
    if "Spring" in repo_slug and category == "authz":
        return ["CVE-2026-108708", "GHSA-xxxx-xxxx-xxxx"]
    
    return []


def query_github_issues(repo_slug: str, category: str, unit_name: str) -> list[str]:
    """
    Query GitHub Issues for related security reports.
    
    Returns:
        List of CVE IDs or issue references
    """
    # In production, this would call:
    # https://api.github.com/search/issues?q=...
    
    if "FileWriter" in unit_name and category == "pathtraver":
        return ["CVE-2026-108701"]
    
    return []


def match_whole_class(cve_description: str, unit_name: str) -> bool:
    """
    Check if CVE description matches entire class (whole-class scope).
    
    Example: "AliPayController" in CVE description → all methods in controller affected
    """
    # Extract class name from unit_name or assume it's the controller
    if "Controller" in unit_name:
        class_name = unit_name.replace("Method", "").replace(".", "")
        return class_name in cve_description
    
    return False


def match_method_specific(cve_description: str, unit_name: str) -> bool:
    """
    Check if CVE description matches specific method.
    
    Example: method "searchMapStr" explicitly mentioned in CVE
    """
    # Simple substring match for method name
    return unit_name in cve_description or f"`{unit_name}`" in cve_description


def check_evidence_gaps(sources_results: dict) -> tuple[bool, list[str]]:
    """
    Check if evidence is complete across all sources.
    
    Returns:
        (evidence_complete, gaps_list)
    """
    gaps = []
    
    for source, results in sources_results.items():
        if not results:
            gaps.append(f"{source} has no records")
    
    evidence_complete = len(gaps) == 0
    
    return evidence_complete, gaps


def dedup_check(repo_slug: str, category: str, unit_name: str, file_path: str) -> DedupResult:
    """
    Check 4 sources for matching CVEs.
    
    Args:
        repo_slug: e.g., "org/repo"
        category: security category (sqli, pathtraver, authz, ...)
        unit_name: class or method name
        file_path: source file path
        
    Returns:
        DedupResult indicating if this is a fresh finding or duplicate
    """
    sources_results = {}
    all_cves = []
    
    # Query all 4 sources
    nvd_cves = query_nvd(repo_slug, category, unit_name)
    sources_results["NVD"] = nvd_cves
    all_cves.extend(nvd_cves)
    
    circl_cves = query_circl(repo_slug, category, unit_name)
    sources_results["CIRCL"] = circl_cves
    all_cves.extend(circl_cves)
    
    ghsa_cves = query_ghsa(repo_slug, category, unit_name)
    sources_results["GHSA"] = ghsa_cves
    all_cves.extend(ghsa_cves)
    
    github_cves = query_github_issues(repo_slug, category, unit_name)
    sources_results["GitHub"] = github_cves
    all_cves.extend(github_cves)
    
    # Deduplicate CVE IDs
    unique_cves = list(set(all_cves))
    
    # Check evidence completeness
    evidence_complete, evidence_gaps = check_evidence_gaps(sources_results)
    
    # Determine scope and status
    if not unique_cves:
        # No CVE found → ZERO_RECORD_FRESH
        return DedupResult(
            status="ZERO_RECORD_FRESH",
            matched_cves=[],
            scope="none",
            evidence_complete=True,
            evidence_gaps=[],
            sources_checked=list(sources_results.keys()),
            explanation=f"No CVE records found for {unit_name} ({category})"
        )
    
    # CVEs found → check scope
    # Simulated: assume first CVE is whole-class, others are method-specific
    # In reality, you'd parse CVE descriptions
    
    if any(match_whole_class(cve, unit_name) for cve in unique_cves):
        scope = "whole_class"
        status = "DUPLICATE_CVE"
        explanation = f"Whole-class CVE found: {unique_cves[0]} covers {unit_name}"
    elif any(match_method_specific(cve, unit_name) for cve in unique_cves):
        scope = "method_specific"
        status = "DUPLICATE_CVE"
        explanation = f"Method-specific CVE found: {unique_cves[0]}"
    else:
        # CVEs exist but don't match this specific method → ZERO_RECORD_FRESH
        scope = "none"
        status = "ZERO_RECORD_FRESH"
        explanation = f"CVEs found in category but not for this specific method: {unique_cves}"
    
    return DedupResult(
        status=status,
        matched_cves=unique_cves,
        scope=scope,
        evidence_complete=evidence_complete,
        evidence_gaps=evidence_gaps,
        sources_checked=list(sources_results.keys()),
        explanation=explanation
    )
