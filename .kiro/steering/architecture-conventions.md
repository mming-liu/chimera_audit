# Architecture Conventions — ChimeraAudit Steering

> This steering file is ALWAYS included. It governs the five-layer Frankenstein architecture
> and enforces code style, module boundaries, and integration contracts.

## 1. The Five-Layer Frankenstein Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 5: Web Workbench  (web/index.html + app.py FastAPI)  │
│  "Dr. Frankenstein's Zero-Day Laboratory" Dark UI           │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Dedup + CVE Export                                │
│  chimera/dedup.py  ·  chimera/cve5_exporter.py              │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Two-Tier AI Skeptic Funnel                        │
│  chimera/funnel.py  (deterministic-first, LLM second)       │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Deterministic Three-Valued Rule Engine            │
│  chimera/detectors.py  (Kleene True/False/None)             │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Multi-Hop Taint Slicer                            │
│  chimera/slicer.py  (cross-language, cross-function)        │
└─────────────────────────────────────────────────────────────┘
```

## 2. Module Responsibility Boundaries

| Module | Sole Responsibility | MUST NOT |
|--------|--------------------|-----------| 
| `chimera/slicer.py` | Route extraction, hop stitching, taint propagation | Perform vulnerability judgments |
| `chimera/detectors.py` | Return `True`/`False`/`None` per category | Call external APIs; run LLM |
| `chimera/funnel.py` | Route `None` to LLM; merge all results; compute token savings | Re-implement detector logic |
| `chimera/dedup.py` | Query NVD/CIRCL/GHSA/GitHub; return dedup status | Modify audit results |
| `chimera/patcher.py` | Synthesize unified diff; self-verify `True→False` | Generate CVE records |
| `chimera/cve5_exporter.py` | Build + validate CVE 5.2 JSON | Perform dedup or patching |
| `chimera/presets.py` | Provide 6 static preset payloads | Contain live API calls |
| `mcp_server.py` | Expose 4 MCP tools over stdio | Contain business logic (call chimera/) |
| `app.py` | FastAPI routing; serve `web/index.html` | Contain business logic (call chimera/) |

## 3. Data Flow Contract

```
Input Code (str, language, filename)
  → slicer.py        → SliceResult (hops[], taint_nodes[], taint_edges[])
  → detectors.py     → DetectorResult (category, verdict: True/False/None, evidence[])
  → funnel.py        → FunnelResult (final_verdict, confidence, token_savings_pct, explanation)
  → dedup.py         → DedupResult (status: ZERO_RECORD_FRESH|DUPLICATE_CVE, evidence_complete, evidence_gaps[])
  → patcher.py       → PatchResult (unified_diff, patch_verified: bool)
  → cve5_exporter.py → CVE52Record (dataType, dataVersion, cveMetadata, containers)
```

## 4. Python Code Style

- Python 3.11+; type hints on all public functions.
- `dataclasses` or `pydantic.BaseModel` for all structured return types.
- No global mutable state; pass config/keys explicitly.
- All external HTTP calls MUST have `timeout=10` and graceful fallback.
- Logging: use `logging.getLogger(__name__)` — no bare `print()` in library code.
- Tests: `pytest`; each test function name describes the invariant being verified.
- Docstrings: Google style on all public classes and functions.

## 5. API Response Schema (enforced by `app.py`)

`POST /api/audit` response:
```json
{
  "hops": [{"hop": 1, "function": "...", "code": "..."}],
  "taint_graph": {"nodes": [...], "edges": [...]},
  "category": "sqli",
  "verdict": "True",
  "confidence": 0.97,
  "explanation": "...",
  "token_savings_pct": 95.2,
  "dedup_status": "ZERO_RECORD_FRESH",
  "evidence_complete": true,
  "evidence_gaps": [],
  "patch": {"unified_diff": "...", "patch_verified": true},
  "cve5": { ... }
}
```

## 6. `.kiro/` Directory Rules

- NEVER add `.kiro/` or any subdirectory to `.gitignore`.
- `.kiro/settings/mcp.json` MUST register `mcp_server.py` as the local MCP server.
- `.kiro/hooks/` MUST contain at least `security-gate-on-save.json`.
- `.kiro/specs/chimera-audit/` MUST contain `requirements.md`, `design.md`, and `tasks.md`.

## 7. Deployment Requirements

- `Dockerfile` MUST produce a single-container image runnable with `docker run -p 8000:8000`.
- `render.yaml` MUST configure a free-tier Web Service pointing to the same `Dockerfile`.
- The app MUST start cleanly with no `LLM_API_KEY` set (offline mode).
- Default port: `8000`. Health endpoint: `GET /api/health` → `{"status": "ok"}`.
