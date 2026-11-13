# ChimeraAudit Implementation Tasks

> Kiro Spec Mode: Structured checklist for building ChimeraAudit backend, MCP server, and web workbench.
> Track completion with checkboxes. Each task should be a complete, testable module.

## Phase 1: Core Engine (Layer 1 & 2)

- [ ] **Task 1.1**: Implement `chimera/slicer.py`
  - Extract Python routes (@app, @router, @api_view) with token boundary matching
  - Extract Java Spring routes (@GetMapping, @PostMapping, @RequestMapping)
  - Triple-quoted string masking ("""...""", '''...''') preserving line numbers
  - Multi-hop stitching (BFS up to 5 hops)
  - Return SliceResult with taint_nodes, taint_edges
  - **Test**: verify preset code snippets produce expected hop counts

- [ ] **Task 1.2**: Implement `chimera/detectors.py`
  - `detect_sqli()` → True/False/None per decision tree
  - `detect_pathtraver()` → True/False/None (Tomcat @PathVariable guard logic)
  - `detect_authz()` → True/False/None (AUTHZ_SIBLING_GUARD)
  - `detect_deserial()` → True/False/None
  - `detect_cmdi()` → True/False/None
  - `detect_ssrf()` → True/False/None
  - **Test**: all 6 presets return expected verdicts

## Phase 2: Funnel & Dedup (Layer 3 & 4)

- [ ] **Task 2.1**: Implement `chimera/funnel.py`
  - Route True/False → FunnelResult directly (100% token savings)
  - Route None → Tier 1 LLM (fast check)
  - Route UNSURE from Tier 1 → Tier 2 LLM (deep skeptic)
  - Offline mode: None → conservative True, offline_mode=True flag
  - Compute token_savings_pct metric
  - **Test**: mock LLM calls; verify offline fallback

- [ ] **Task 2.2**: Implement `chimera/dedup.py`
  - Query NVD, CIRCL, GHSA, GitHub Issues in parallel
  - Whole-class vs. method-specific CVE matching
  - Return DedupResult (ZERO_RECORD_FRESH | DUPLICATE_CVE)
  - Track evidence_complete, evidence_gaps
  - **Test**: mock API responses; verify matching logic

## Phase 3: Patch & CVE (Layer 5a & 5b)

- [ ] **Task 3.1**: Implement `chimera/patcher.py`
  - Generate unified diff patch from detector feedback
  - Re-run detector on patched code
  - Verify True → False transition
  - Return PatchResult (unified_diff, patch_verified: bool)
  - **Test**: verify patch_verified=true for all presets

- [ ] **Task 3.2**: Implement `chimera/cve5_exporter.py`
  - Build CVE 5.2 JSON record (dataType, dataVersion, containers.cna)
  - Populate cveMetadata, affected[], references[], metrics[], x_CAN extension
  - Validate against MITRE schema
  - Return CVE52Record
  - **Test**: JSON schema validation; verify required fields

- [ ] **Task 3.3**: Implement `chimera/presets.py`
  - 4 real 0-day patterns (FileWriter, SQLi, Authz, PathTraversal)
  - 2 false-positive traps (Tomcat guard, SQL builder)
  - Each preset: code, language, filename, expected_category
  - **Test**: load all 6 presets; verify structure

## Phase 4: Testing

- [ ] **Task 4.1**: Implement `tests/test_chimera_suite.py`
  - Test all 6 presets end-to-end
  - Test triple-quoted masking (line number preservation)
  - Test whole-class vs. method-specific dedup
  - Test patch verification (True → False)
  - Test CVE 5.2 JSON validity
  - Run: `pytest -v tests/test_chimera_suite.py`
  - **Pass Criterion**: 100% of tests pass

## Phase 5: Backend API & MCP (app.py, mcp_server.py)

- [ ] **Task 5.1**: Implement `mcp_server.py`
  - JSON-RPC 2.0 stdio transport
  - Expose 4 MCP tools (chimera_audit_code, chimera_check_dedup, chimera_synthesize_patch, chimera_export_cve5)
  - Graceful fallback if mcp SDK not installed
  - **Test**: test calls to each tool via stdin/stdout

- [ ] **Task 5.2**: Create `.kiro/settings/mcp.json`
  - Register mcp_server.py as local MCP server
  - Command: `python mcp_server.py`
  - Enable Kiro IDE integration

- [ ] **Task 5.3**: Implement `app.py` (FastAPI)
  - POST /api/audit → full audit result
  - POST /api/dedup → DedupResult
  - POST /api/cve5 → CVE52Record
  - GET /api/presets → 6 presets array
  - GET /api/health → health status
  - Serve `web/index.html` at root
  - **Test**: use TestClient; verify HTTP 200 for all endpoints

- [ ] **Task 5.4**: Create `.kiro/hooks/security-gate-on-save.json`
  - Trigger: PostFileSave, matcher: `\.(py|java)$`
  - Action: run pytest + import sanity check
  - Block on failure (exit 2)

## Phase 6: Web Workbench (web/index.html)

- [ ] **Task 6.1**: Design "Dr. Frankenstein's Zero-Day Lab" UI
  - Dark mode (obsidian #0B0F17 + neon green #10B981 + crimson #EF4444)
  - Top bar: 6 one-click preset buttons
  - Left pane: code editor + stitched call chain visualizer
  - Right pane: 4 tabs (Diagnosis, Dedup Radar, Patch, CVE 5.2)
  - Live result rendering from POST /api/audit
  - **Test**: open in browser; click presets; verify rendering

## Phase 7: Deployment

- [ ] **Task 7.1**: Create `Dockerfile`
  - Base: Python 3.11 slim
  - Copy requirements.txt, install deps
  - Expose port 8000
  - CMD: `uvicorn app:app --host 0.0.0.0 --port 8000`
  - **Test**: `docker build -t chimera-audit . && docker run -p 8000:8000 ...`

- [ ] **Task 7.2**: Create `render.yaml`
  - Free Web Service configuration
  - Build: `docker build`
  - Start: `docker run ...`

- [ ] **Task 7.3**: Create `requirements.txt`
  - fastapi, uvicorn, httpx, pydantic, pytest, mcp (or zero-dependency fallback)

- [ ] **Task 7.4**: Create `README.md`
  - Architecture diagram
  - Frankenstein five-layer overview
  - Local dev: `pip install -r requirements.txt && uvicorn app:app`
  - Deployment: Render / Railway / Fly.io link
  - Demo instructions (6 presets, no auth needed)

- [ ] **Task 7.5**: Create `LICENSE` (MIT)

## Phase 8: Git & Publishing

- [ ] **Task 8.1**: Initialize git + push to GitHub
  - New public repo: `chimera-audit`
  - Commit `.kiro/`, `chimera/`, `tests/`, `app.py`, `web/`, `Dockerfile`, `requirements.txt`, `README.md`, `LICENSE`
  - DO NOT add to .gitignore: `.kiro/`
  - Push to origin/main

- [ ] **Task 8.2**: Deploy to Render
  - Connect GitHub repo
  - One-click deploy
  - Verify https://chimera-audit.onrender.com live

- [ ] **Task 8.3**: Record 2:30 demo video
  - Show Kiro IDE + `.kiro/` integration
  - Show web presets running live
  - Upload to YouTube (Public)
  - Add to README.md

---

## Success Criteria

✅ All 8 phases complete
✅ 6 presets run end-to-end (Kiro IDE + web + API)
✅ pytest 100% pass rate
✅ No API errors (all 200 HTTP)
✅ `.kiro/` committed to GitHub (not .gitignore'd)
✅ Public GitHub repo + MIT License + README
✅ Live Render deployment
✅ YouTube demo < 3:00
