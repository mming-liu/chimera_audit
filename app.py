"""FastAPI backend for ChimeraAudit."""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os
from pathlib import Path

from chimera.slicer import slice_code
from chimera.detectors import (
    detect_sqli, detect_pathtraver, detect_authz, detect_deserial, detect_cmdi, detect_ssrf
)
from chimera.funnel import route_through_funnel
from chimera.dedup import dedup_check
from chimera.patcher import synthesize_patch
from chimera.cve5_exporter import build_cve5_record, export_cve5_json
from chimera.presets import get_all_presets, preset_to_dict


# FastAPI app
app = FastAPI(
    title="ChimeraAudit",
    description="Frankenstein Security Engine",
    version="1.0.0"
)


# ============================================================================
# Request/Response Models
# ============================================================================

class AuditRequest(BaseModel):
    """Request to audit code."""
    code: str
    language: str  # "python" or "java"
    filename: str = "unknown.py"


class DedupRequest(BaseModel):
    """Request to check for duplicate CVEs."""
    repo_slug: str
    category: str
    unit_name: str
    file_path: str


class PatchRequest(BaseModel):
    """Request to synthesize a patch."""
    code: str
    category: str


class CVE5Request(BaseModel):
    """Request to export CVE 5.2 record."""
    repo_slug: str
    category: str
    unit_name: str
    file_path: str
    cwe_id: str
    cvss_score: float


# ============================================================================
# Routes
# ============================================================================

@app.get("/api/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "offline_mode": not bool(os.environ.get("LLM_API_KEY"))
    }


@app.get("/api/presets")
def get_presets():
    """Get all demo presets."""
    return {
        "presets": [preset_to_dict(p) for p in get_all_presets()]
    }


@app.post("/api/audit")
def audit_code(request: AuditRequest):
    """Audit source code for vulnerabilities."""
    try:
        # Slice
        slice_result = slice_code(request.code, request.language, request.filename)
        
        # Run all detectors
        sqli_result = detect_sqli(slice_result, request.code)
        pathtraver_result = detect_pathtraver(slice_result, request.code)
        authz_result = detect_authz(slice_result, request.code)
        deserial_result = detect_deserial(slice_result, request.code)
        cmdi_result = detect_cmdi(slice_result, request.code)
        ssrf_result = detect_ssrf(slice_result, request.code)
        
        # Route through funnels
        sqli_funnel = route_through_funnel(sqli_result, request.code)
        pathtraver_funnel = route_through_funnel(pathtraver_result, request.code)
        authz_funnel = route_through_funnel(authz_result, request.code)
        deserial_funnel = route_through_funnel(deserial_result, request.code)
        cmdi_funnel = route_through_funnel(cmdi_result, request.code)
        ssrf_funnel = route_through_funnel(ssrf_result, request.code)
        
        # Synthesize patch if any vulnerability found
        patch_result = None
        for cat, result in [("sqli", sqli_result), ("pathtraver", pathtraver_result)]:
            if result.verdict is True:
                patch_result = synthesize_patch(request.code, cat, original_verdict=True)
                break
        
        # Build response
        all_funnels = [
            sqli_funnel, pathtraver_funnel, authz_funnel,
            deserial_funnel, cmdi_funnel, ssrf_funnel
        ]
        
        avg_token_savings = sum(f.token_savings_pct for f in all_funnels) / len(all_funnels)
        
        return {
            "entry_function": slice_result.entry_function,
            "entry_route": slice_result.entry_route,
            "hops": [
                {
                    "hop": h.hop_n,
                    "function": h.function,
                    "file": h.file,
                    "line": h.line_start,
                    "code": h.code
                }
                for h in slice_result.hops
            ],
            "taint_graph": {
                "nodes": [
                    {
                        "id": n.id,
                        "function": n.function,
                        "file": n.file,
                        "line": n.line,
                        "code": n.code[:50]
                    }
                    for n in slice_result.taint_nodes
                ],
                "edges": [
                    {"source": e.source, "target": e.target, "label": e.label}
                    for e in slice_result.taint_edges
                ]
            },
            "categories": {
                "sqli": {
                    "verdict": sqli_funnel.final_verdict,
                    "confidence": sqli_funnel.confidence,
                    "explanation": sqli_funnel.explanation,
                    "tier": sqli_funnel.tier,
                    "cwe": "CWE-89"
                },
                "pathtraver": {
                    "verdict": pathtraver_funnel.final_verdict,
                    "confidence": pathtraver_funnel.confidence,
                    "explanation": pathtraver_funnel.explanation,
                    "tier": pathtraver_funnel.tier,
                    "cwe": "CWE-22"
                },
                "authz": {
                    "verdict": authz_funnel.final_verdict,
                    "confidence": authz_funnel.confidence,
                    "explanation": authz_funnel.explanation,
                    "tier": authz_funnel.tier,
                    "cwe": "CWE-862"
                },
                "deserial": {
                    "verdict": deserial_funnel.final_verdict,
                    "confidence": deserial_funnel.confidence,
                    "explanation": deserial_funnel.explanation,
                    "tier": deserial_funnel.tier,
                    "cwe": "CWE-502"
                },
                "cmdi": {
                    "verdict": cmdi_funnel.final_verdict,
                    "confidence": cmdi_funnel.confidence,
                    "explanation": cmdi_funnel.explanation,
                    "tier": cmdi_funnel.tier,
                    "cwe": "CWE-78"
                },
                "ssrf": {
                    "verdict": ssrf_funnel.final_verdict,
                    "confidence": ssrf_funnel.confidence,
                    "explanation": ssrf_funnel.explanation,
                    "tier": ssrf_funnel.tier,
                    "cwe": "CWE-918"
                }
            },
            "token_savings_pct": avg_token_savings,
            "patch": {
                "unified_diff": patch_result.unified_diff if patch_result else "",
                "patch_verified": patch_result.patch_verified if patch_result else False
            }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/dedup")
def check_dedup(request: DedupRequest):
    """Check for duplicate CVEs."""
    try:
        result = dedup_check(
            request.repo_slug,
            request.category,
            request.unit_name,
            request.file_path
        )
        
        return {
            "status": result.status,
            "matched_cves": result.matched_cves,
            "scope": result.scope,
            "evidence_complete": result.evidence_complete,
            "evidence_gaps": result.evidence_gaps,
            "explanation": result.explanation
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/cve5")
def export_cve5(request: CVE5Request):
    """Export CVE 5.2 record."""
    try:
        record = build_cve5_record(
            repo_slug=request.repo_slug,
            category=request.category,
            unit_name=request.unit_name,
            file_path=request.file_path,
            cwe_id=request.cwe_id,
            cvss_score=request.cvss_score
        )
        
        json_str = export_cve5_json(record, pretty=False)
        import json
        return json.loads(json_str)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/")
def serve_frontend():
    """Serve the dark lab frontend."""
    web_dir = Path(__file__).parent / "web"
    index_file = web_dir / "index.html"
    
    if index_file.exists():
        return FileResponse(index_file)
    else:
        return {"error": "Frontend not found"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
