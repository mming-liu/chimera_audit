"""MITRE CVE 5.2 JSON export and validation."""

import json
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class CVE52Record:
    """MITRE CVE 5.2 format record."""
    dataType: str
    dataVersion: str
    cveMetadata: dict
    containers: dict


def build_cve5_record(
    repo_slug: str,
    category: str,
    unit_name: str,
    file_path: str,
    cwe_id: str,
    cvss_score: float,
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    slice_hops: int = 0,
    taint_sources: list = None,
    taint_sinks: list = None,
    patch_verified: bool = False,
    token_savings_pct: float = 0.0
) -> CVE52Record:
    """
    Build a MITRE CNA-LR CVE 5.2 JSON record.
    
    Args:
        repo_slug: Repository identifier (org/repo)
        category: Vulnerability category (sqli, pathtraver, authz, ...)
        unit_name: Class or method name
        file_path: Source file path
        cwe_id: CWE identifier (e.g., "CWE-89")
        cvss_score: CVSS base score (0-10)
        cvss_vector: CVSS 3.1 vector string
        slice_hops: Number of hops in taint slice
        taint_sources: Taint source identifiers
        taint_sinks: Taint sink identifiers
        patch_verified: Whether patch was verified
        token_savings_pct: Token savings percentage from LLM filtering
        
    Returns:
        CVE52Record object
    """
    if taint_sources is None:
        taint_sources = []
    if taint_sinks is None:
        taint_sinks = []
    
    # Generate CVE ID (format: CVE-YYYY-XXXXXX or x_CAN-YYYY-XXXXXX)
    year = datetime.now().year
    # Simple sequential for demo
    cve_id = f"x_CAN-{year}-{str(hash(f'{repo_slug}{unit_name}'))[-6:].zfill(6).lstrip('-')}"
    
    # Map category to description and severity
    category_map = {
        "sqli": {
            "description": "SQL Injection vulnerability",
            "severity": "CRITICAL" if cvss_score >= 9.0 else "HIGH",
        },
        "pathtraver": {
            "description": "Path Traversal vulnerability",
            "severity": "HIGH" if cvss_score >= 8.0 else "MEDIUM",
        },
        "authz": {
            "description": "Authorization bypass vulnerability",
            "severity": "HIGH" if cvss_score >= 8.0 else "MEDIUM",
        },
        "deserial": {
            "description": "Unsafe deserialization vulnerability",
            "severity": "CRITICAL" if cvss_score >= 9.0 else "HIGH",
        },
        "cmdi": {
            "description": "Command Injection vulnerability",
            "severity": "CRITICAL" if cvss_score >= 9.0 else "HIGH",
        },
        "ssrf": {
            "description": "Server-Side Request Forgery vulnerability",
            "severity": "HIGH" if cvss_score >= 8.0 else "MEDIUM",
        }
    }
    
    cat_info = category_map.get(category, {"description": "Security vulnerability", "severity": "MEDIUM"})
    
    # Extract product name from repo_slug
    product = repo_slug.split('/')[-1] if '/' in repo_slug else repo_slug
    
    # Build CVE metadata
    cve_metadata = {
        "cveId": cve_id,
        "assignerOrgId": "chimera-audit-cna",
        "state": "PUBLISHED",
        "datePublished": datetime.now().isoformat() + "Z"
    }
    
    # Build affected section
    affected = [{
        "product": product,
        "vendor": repo_slug.split('/')[0] if '/' in repo_slug else "unknown",
        "versions": [{
            "version": "0.0",
            "status": "affected",
            "lessThan": "unpatched"
        }],
        "platforms": ["All"],
        "programFiles": [file_path]
    }]
    
    # Build descriptions
    descriptions = [{
        "lang": "en",
        "value": f"{cat_info['description']} in {unit_name} ({category}). The vulnerable code is located in {file_path}. Multi-hop taint slice depth: {slice_hops} hops."
    }]
    
    # Build references
    references = [
        {
            "url": f"https://github.com/{repo_slug}",
            "name": "Repository"
        },
        {
            "url": f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={cwe_id}",
            "name": f"{cwe_id} Details"
        }
    ]
    
    # Build metrics (CVSS 3.1)
    metrics = [{
        "cvssV3_1": {
            "version": "3.1",
            "vectorString": cvss_vector,
            "baseScore": cvss_score,
            "baseSeverity": cat_info['severity'],
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "scope": "UNCHANGED"
        }
    }]
    
    # Build problem types
    problem_types = [{
        "descriptions": [{
            "type": "CWE",
            "cweId": cwe_id,
            "description": cat_info['description']
        }]
    }]
    
    # Build x_CAN extension (chimera-audit specific)
    x_can = {
        "category": category,
        "unitName": unit_name,
        "filePath": file_path,
        "sliceHops": slice_hops,
        "taintSources": taint_sources,
        "taintSinks": taint_sinks,
        "patchVerified": patch_verified,
        "tokenSavingsPct": token_savings_pct,
        "generatedBy": "ChimeraAudit v1.0"
    }
    
    # Build CNA container
    cna = {
        "descriptions": descriptions,
        "affected": affected,
        "references": references,
        "metrics": metrics,
        "problemTypes": problem_types,
        "x_CAN": x_can
    }
    
    # Build containers
    containers = {
        "cna": cna
    }
    
    return CVE52Record(
        dataType="CVE_RECORD",
        dataVersion="5.2",
        cveMetadata=cve_metadata,
        containers=containers
    )


def validate_cve5_record(record: CVE52Record) -> tuple[bool, list[str]]:
    """
    Validate CVE 5.2 record against MITRE schema.
    
    Returns:
        (is_valid, error_messages)
    """
    errors = []
    
    # Check required top-level fields
    if record.dataType != "CVE_RECORD":
        errors.append("dataType must be 'CVE_RECORD'")
    
    if record.dataVersion != "5.2":
        errors.append("dataVersion must be '5.2'")
    
    # Check cveMetadata
    required_metadata = ["cveId", "assignerOrgId", "state"]
    for field in required_metadata:
        if field not in record.cveMetadata:
            errors.append(f"cveMetadata missing required field: {field}")
    
    # Check CVE ID format
    cve_id = record.cveMetadata.get("cveId", "")
    if not (cve_id.startswith("CVE-") or cve_id.startswith("x_CAN-")):
        errors.append(f"Invalid CVE ID format: {cve_id}")
    
    # Check containers.cna
    cna = record.containers.get("cna", {})
    
    if "descriptions" not in cna or not cna["descriptions"]:
        errors.append("CNA must have at least one description")
    else:
        if "lang" not in cna["descriptions"][0] or "value" not in cna["descriptions"][0]:
            errors.append("Description missing 'lang' or 'value'")
    
    if "affected" not in cna or not cna["affected"]:
        errors.append("CNA must have at least one affected product")
    else:
        if "product" not in cna["affected"][0]:
            errors.append("Affected product missing 'product' field")
    
    if "references" not in cna or not cna["references"]:
        errors.append("CNA must have at least one reference")
    
    if "metrics" not in cna or not cna["metrics"]:
        errors.append("CNA must have at least one metric")
    else:
        if "cvssV3_1" not in cna["metrics"][0]:
            errors.append("Metric must contain cvssV3_1")
    
    if "problemTypes" not in cna or not cna["problemTypes"]:
        errors.append("CNA must have at least one problem type")
    
    # Check x_CAN extension
    if "x_CAN" not in cna:
        errors.append("ChimeraAudit x_CAN extension missing")
    
    is_valid = len(errors) == 0
    return is_valid, errors


def export_cve5_json(record: CVE52Record, pretty: bool = True) -> str:
    """
    Export CVE 5.2 record as JSON string.
    
    Args:
        record: CVE52Record object
        pretty: If True, pretty-print JSON
        
    Returns:
        JSON string
    """
    data = {
        "dataType": record.dataType,
        "dataVersion": record.dataVersion,
        "cveMetadata": record.cveMetadata,
        "containers": record.containers
    }
    
    if pretty:
        return json.dumps(data, indent=2)
    else:
        return json.dumps(data)


def export_cve5_file(record: CVE52Record, filepath: str) -> bool:
    """
    Export CVE 5.2 record to file.
    
    Returns:
        True if successful
    """
    try:
        json_str = export_cve5_json(record, pretty=True)
        with open(filepath, 'w') as f:
            f.write(json_str)
        return True
    except Exception as e:
        print(f"Error exporting CVE 5.2: {e}")
        return False
