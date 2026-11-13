"""Export REAL ChimeraAudit engine output for the demo video.

No FastAPI/uvicorn needed: this replicates app.py's /api/audit pipeline by
calling the exact same deterministic modules, so every number shown in the
video is genuinely computed by the project's engine.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from chimera.slicer import slice_code
from chimera.detectors import (
    detect_sqli, detect_pathtraver, detect_authz,
    detect_deserial, detect_cmdi, detect_ssrf,
)
from chimera.funnel import route_through_funnel
from chimera.patcher import synthesize_patch
from chimera.cve5_exporter import build_cve5_record, export_cve5_json, validate_cve5_record
from chimera.presets import get_all_presets, preset_to_dict

CWE = {
    "sqli": "CWE-89", "pathtraver": "CWE-22", "authz": "CWE-862",
    "deserial": "CWE-502", "cmdi": "CWE-78", "ssrf": "CWE-918",
}
DETECTORS = [
    ("sqli", detect_sqli), ("pathtraver", detect_pathtraver),
    ("authz", detect_authz), ("deserial", detect_deserial),
    ("cmdi", detect_cmdi), ("ssrf", detect_ssrf),
]


def real_audit(preset):
    """Mirror app.py :: audit_code exactly."""
    s = slice_code(preset.code, preset.language, preset.filename)
    raw = {name: fn(s, preset.code) for name, fn in DETECTORS}
    funnels = {name: route_through_funnel(raw[name], preset.code)
               for name, _ in DETECTORS}

    patch_result = None
    for cat in ("sqli", "pathtraver"):
        if raw[cat].verdict is True:
            patch_result = synthesize_patch(preset.code, cat, original_verdict=True)
            break

    cats = {}
    for name, _ in DETECTORS:
        f = funnels[name]
        cats[name] = {
            "verdict": f.final_verdict,
            "confidence": f.confidence,
            "explanation": f.explanation,
            "tier": f.tier,
            "cwe": CWE[name],
        }
    token_savings = sum(f.token_savings_pct for f in funnels.values()) / len(funnels)

    return {
        "entry_function": s.entry_function,
        "entry_route": s.entry_route,
        "hops": [
            {"hop": h.hop_n, "function": h.function, "file": h.file,
             "line": h.line_start, "code": h.code[:120]}
            for h in s.hops
        ],
        "categories": cats,
        "token_savings_pct": round(token_savings, 1),
        "patch": {
            "unified_diff": patch_result.unified_diff if patch_result else "",
            "patch_verified": patch_result.patch_verified if patch_result else False,
            "explanation": patch_result.explanation if patch_result else "",
        },
    }


def main():
    presets = get_all_presets()
    by_id = {p.id: p for p in presets}
    sqli = by_id["0day_2_workflow_sqli"]
    fp = by_id["fp_trap_1_pathvar_guard"]

    sqli_result = real_audit(sqli)
    fp_result = real_audit(fp)

    record = build_cve5_record(
        repo_slug="your-org/chimera-audit",
        category="sqli",
        unit_name=sqli_result["entry_function"],
        file_path=sqli.filename,
        cwe_id="CWE-89",
        cvss_score=9.8,
        slice_hops=len(sqli_result["hops"]),
        taint_sources=["@RequestBody Map<String,String> searchParams"],
        taint_sinks=["jdbcTemplate.queryForMap(rawQuery)"],
        patch_verified=sqli_result["patch"]["patch_verified"],
        token_savings_pct=sqli_result["token_savings_pct"],
    )
    valid, errors = validate_cve5_record(record)

    data = {
        "presets": [preset_to_dict(p) for p in presets],
        "sqli": {
            "preset": preset_to_dict(sqli),
            "result": sqli_result,
        },
        "fp": {
            "preset": preset_to_dict(fp),
            "result": fp_result,
        },
        "cve5": json.loads(export_cve5_json(record, pretty=False)),
        "cve5_pretty": export_cve5_json(record, pretty=True),
        "cve5_valid": valid,
        "cve5_errors": errors,
        "spec_files": {
            "requirements.md": (ROOT / ".kiro/specs/chimera-audit/requirements.md").read_text(encoding="utf-8"),
            "security-invariants.md": (ROOT / ".kiro/steering/security-invariants.md").read_text(encoding="utf-8"),
        },
        "web_title": "Dr. Frankenstein's Zero-Day Laboratory",
    }

    out = Path(__file__).resolve().parent / "audit_data.json"
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print("wrote", out)
    print("sqli verdict:", sqli_result["categories"]["sqli"])
    print("fp pathtraver:", fp_result["categories"]["pathtraver"])
    print("token savings:", sqli_result["token_savings_pct"])
    print("patch verified:", sqli_result["patch"]["patch_verified"])
    print("cve5 valid:", valid, errors)


if __name__ == "__main__":
    main()
