"""Kiro-native MCP Server for ChimeraAudit."""

import json
import sys
from chimera.slicer import slice_code
from chimera.detectors import (
    detect_sqli, detect_pathtraver, detect_authz, detect_deserial, detect_cmdi, detect_ssrf
)
from chimera.funnel import route_through_funnel
from chimera.dedup import dedup_check
from chimera.patcher import synthesize_patch
from chimera.cve5_exporter import build_cve5_record, export_cve5_json
from chimera.presets import get_all_presets, preset_to_dict


# MCP Server implementation (JSON-RPC 2.0 over stdio)

class MCPServer:
    """Simple JSON-RPC 2.0 MCP server."""
    
    def __init__(self):
        self.methods = {
            "chimera_audit_code": self.chimera_audit_code,
            "chimera_check_dedup": self.chimera_check_dedup,
            "chimera_synthesize_patch": self.chimera_synthesize_patch,
            "chimera_export_cve5": self.chimera_export_cve5,
        }
    
    def chimera_audit_code(self, code: str, language: str, filename: str) -> dict:
        """Audit source code for vulnerabilities."""
        # Slice
        slice_result = slice_code(code, language, filename)
        
        # Run all detectors
        sqli_result = detect_sqli(slice_result, code)
        pathtraver_result = detect_pathtraver(slice_result, code)
        authz_result = detect_authz(slice_result, code)
        deserial_result = detect_deserial(slice_result, code)
        cmdi_result = detect_cmdi(slice_result, code)
        ssrf_result = detect_ssrf(slice_result, code)
        
        # Route through funnels
        sqli_funnel = route_through_funnel(sqli_result, code)
        pathtraver_funnel = route_through_funnel(pathtraver_result, code)
        authz_funnel = route_through_funnel(authz_result, code)
        deserial_funnel = route_through_funnel(deserial_result, code)
        cmdi_funnel = route_through_funnel(cmdi_result, code)
        ssrf_funnel = route_through_funnel(ssrf_result, code)
        
        # Merge results
        return {
            "entry_function": slice_result.entry_function,
            "entry_route": slice_result.entry_route,
            "hops": [{"hop": h.hop_n, "function": h.function, "file": h.file} for h in slice_result.hops],
            "taint_graph": {
                "nodes": [{"id": n.id, "function": n.function, "line": n.line} for n in slice_result.taint_nodes],
                "edges": [{"source": e.source, "target": e.target} for e in slice_result.taint_edges]
            },
            "categories": {
                "sqli": {
                    "verdict": sqli_funnel.final_verdict,
                    "confidence": sqli_funnel.confidence,
                    "explanation": sqli_funnel.explanation
                },
                "pathtraver": {
                    "verdict": pathtraver_funnel.final_verdict,
                    "confidence": pathtraver_funnel.confidence,
                    "explanation": pathtraver_funnel.explanation
                },
                "authz": {
                    "verdict": authz_funnel.final_verdict,
                    "confidence": authz_funnel.confidence,
                    "explanation": authz_funnel.explanation
                },
                "deserial": {
                    "verdict": deserial_funnel.final_verdict,
                    "confidence": deserial_funnel.confidence,
                    "explanation": deserial_funnel.explanation
                },
                "cmdi": {
                    "verdict": cmdi_funnel.final_verdict,
                    "confidence": cmdi_funnel.confidence,
                    "explanation": cmdi_funnel.explanation
                },
                "ssrf": {
                    "verdict": ssrf_funnel.final_verdict,
                    "confidence": ssrf_funnel.confidence,
                    "explanation": ssrf_funnel.explanation
                }
            },
            "token_savings_pct": sum([
                sqli_funnel.token_savings_pct,
                pathtraver_funnel.token_savings_pct,
                authz_funnel.token_savings_pct,
                deserial_funnel.token_savings_pct,
                cmdi_funnel.token_savings_pct,
                ssrf_funnel.token_savings_pct
            ]) / 6.0
        }
    
    def chimera_check_dedup(self, repo_slug: str, category: str, unit_name: str, file_path: str) -> dict:
        """Check for duplicate CVEs."""
        result = dedup_check(repo_slug, category, unit_name, file_path)
        
        return {
            "status": result.status,
            "matched_cves": result.matched_cves,
            "scope": result.scope,
            "evidence_complete": result.evidence_complete,
            "evidence_gaps": result.evidence_gaps,
            "explanation": result.explanation
        }
    
    def chimera_synthesize_patch(self, code: str, category: str) -> dict:
        """Synthesize a patch for the vulnerability."""
        result = synthesize_patch(code, category, original_verdict=True)
        
        return {
            "unified_diff": result.unified_diff,
            "patch_verified": result.patch_verified,
            "original_verdict": result.original_verdict,
            "patched_verdict": result.patched_verdict,
            "explanation": result.explanation
        }
    
    def chimera_export_cve5(self, repo_slug: str, category: str, unit_name: str, file_path: str, cwe_id: str, cvss_score: float) -> dict:
        """Export a CVE 5.2 record."""
        record = build_cve5_record(
            repo_slug=repo_slug,
            category=category,
            unit_name=unit_name,
            file_path=file_path,
            cwe_id=cwe_id,
            cvss_score=cvss_score
        )
        
        json_str = export_cve5_json(record, pretty=False)
        
        return json.loads(json_str)
    
    def handle_request(self, request_data: dict) -> dict:
        """Handle JSON-RPC 2.0 request."""
        method_name = request_data.get("method")
        params = request_data.get("params", {})
        request_id = request_data.get("id")
        
        if method_name not in self.methods:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": f"Method not found: {method_name}"},
                "id": request_id
            }
        
        try:
            result = self.methods[method_name](**params)
            return {
                "jsonrpc": "2.0",
                "result": result,
                "id": request_id
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": str(e)},
                "id": request_id
            }


def main():
    """Run MCP server."""
    server = MCPServer()
    
    # Read requests from stdin
    for line in sys.stdin:
        if line.strip():
            try:
                request = json.loads(line)
                response = server.handle_request(request)
                print(json.dumps(response))
                sys.stdout.flush()
            except Exception as e:
                print(json.dumps({
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": "Parse error"},
                    "id": None
                }))
                sys.stdout.flush()


if __name__ == "__main__":
    main()
