# ChimeraAudit — Requirements Specification (Kiro EARS Syntax)

> Format: `WHEN <trigger>, THE SYSTEM SHALL <response>`
> Status: v1.0 — Kiroween 2026 Frankenstein Track

## R1 — Multi-Language Route & Multi-Hop Context Slicing

**R1.1** WHEN the user submits Python source code containing Flask or FastAPI route decorators (`@app.get`, `@app.post`, `@router.get`, `@router.post`, `@api_view`), THE SYSTEM SHALL extract all route handler functions matched at token boundaries, suppressing any decorator-like strings inside triple-quoted docstrings (`"""..."""`, `'''...'''`) while preserving original line numbers.

**R1.2** WHEN the user submits Java Spring Boot source code containing `@RequestMapping`, `@GetMapping`, `@PostMapping`, `@PutMapping`, `@DeleteMapping` (including bare annotations without explicit `value` or `path` attributes), THE SYSTEM SHALL extract route handlers and compose the full URL by concatenating the class-level `@RequestMapping` prefix with the method-level mapping value.

**R1.3** WHEN a route handler calls one or more helper functions (cross-function hops), THE SYSTEM SHALL stitch the multi-hop call chain (up to 5 hops: `Entrypoint → Hop 1 → Hop 2 → … → Sink`) and propagate taint from route parameters, `@RequestParam`, `@RequestBody`, `@PathVariable`, and DTO fields across all hops.

**R1.4** WHEN multi-hop slicing produces a taint chain, THE SYSTEM SHALL return a structured taint graph with labeled nodes (function name, file, line) and directed edges (caller → callee) suitable for visual rendering.

## R2 — Deterministic Security Gate + Two-Tier AI Skeptic Funnel

**R2.1** WHEN a taint slice is produced, THE SYSTEM SHALL evaluate it against six deterministic Kleene three-valued detectors: `sqli`, `pathtraver`, `authz`, `deserial`, `cmdi`, `ssrf`, returning `True` (vulnerable), `False` (safe), or `None` (undetermined) per the invariants defined in `.kiro/steering/security-invariants.md`.

**R2.2** WHEN a detector returns `True` or `False`, THE SYSTEM SHALL report the final verdict directly without invoking the LLM, logging the token savings percentage.

**R2.3** WHEN a detector returns `None`, THE SYSTEM SHALL route the slice to Tier 1 (fast LLM check) and, if still uncertain, to Tier 2 (deep LLM skeptic analysis), merging the result back into the final verdict pipeline.

**R2.4** WHEN no `LLM_API_KEY` environment variable is configured, THE SYSTEM SHALL operate in offline deterministic mode: `True`/`False` verdicts are returned as-is; `None` verdicts are conservatively promoted to `True` with an `offline_mode: true` flag.

**R2.5** WHEN the two-tier funnel completes, THE SYSTEM SHALL return a `token_savings_pct` metric indicating what percentage of LLM tokens were avoided through deterministic pre-filtering.

## R3 — 4-Source 0-Day Deduplication, CVE 5.2 Export & Auto-Patch Synthesis

**R3.1** WHEN a `True` verdict is confirmed, THE SYSTEM SHALL query four sources in parallel: NVD (NIST), CIRCL CVE Search, GHSA (GitHub Advisory Database), and GitHub Issues search, applying whole-class vs. method-specific matching logic as defined in `.kiro/steering/security-invariants.md`.

**R3.2** WHEN all four sources return no matching CVE, THE SYSTEM SHALL classify the finding as `ZERO_RECORD_FRESH` with `evidence_complete: true`.

**R3.3** WHEN at least one source returns a matching CVE but the specific method under analysis is not patched in the existing CVE, THE SYSTEM SHALL classify as `ZERO_RECORD_FRESH` (new finding) alongside the related `DUPLICATE_CVE` context, tracking `evidence_complete` and listing `evidence_gaps`.

**R3.4** WHEN a finding is classified as `ZERO_RECORD_FRESH`, THE SYSTEM SHALL generate a valid MITRE CNA-LR CVE 5.2 JSON record (`dataType: "CVE_RECORD"`, `dataVersion: "5.2"`, `x_CAN` extension) with all mandatory fields populated.

**R3.5** WHEN a `True` verdict is confirmed, THE SYSTEM SHALL synthesize a unified diff patch and re-run the detector on the patched code to verify `True → False`, setting `patch_verified: true` on success.

## R4 — Kiro MCP Server & Kiro Hook Integration

**R4.1** WHEN Kiro (or any MCP client) connects to `mcp_server.py` via stdio, THE SYSTEM SHALL expose four MCP tools: `chimera_audit_code`, `chimera_check_dedup`, `chimera_synthesize_patch`, `chimera_export_cve5`, each with JSON Schema parameter validation.

**R4.2** WHEN the MCP server cannot import the `mcp` SDK package, THE SYSTEM SHALL fall back to a zero-dependency JSON-RPC 2.0 over stdio implementation that exposes the same four tools.

**R4.3** WHEN a user saves a `.py` or `.java` file in the Kiro IDE, THE SYSTEM SHALL trigger the `security-gate-on-save` Kiro Hook, which runs the deterministic audit and pytest regression suite, blocking the save with an exit code 2 and an error message if critical vulnerabilities are detected.

**R4.4** WHEN `.kiro/settings/mcp.json` is present, THE SYSTEM SHALL register `mcp_server.py` as the local MCP server so Kiro can call the four security tools without any additional configuration.

## R5 — "Dr. Frankenstein's Zero-Day Lab" Interactive Web Workbench

**R5.1** WHEN a user opens the application URL in a browser, THE SYSTEM SHALL serve `web/index.html` — a dark-mode single-page web workbench styled as "Dr. Frankenstein's Zero-Day Laboratory" — requiring no login, registration, or API key.

**R5.2** WHEN the web workbench loads, THE SYSTEM SHALL display six one-click preset buttons:
1. `[0-Day #1] Multi-Hop FileWriter Escape`
2. `[0-Day #2] Workflow JSON SQLi`
3. `[0-Day #3] Bare @PostMapping Authz Bypass`
4. `[0-Day #4] Chunk Upload Traversal`
5. `[FP Trap #1] Tomcat @PathVariable Guard`
6. `[FP Trap #2] NamedParam SQL Builder`

**R5.3** WHEN a preset is clicked or the user submits custom code, THE SYSTEM SHALL display (within 3 seconds) the stitched call chain, taint graph, Kleene verdict, two-tier funnel telemetry, 4-source dedup radar, auto-verified patch diff, and CVE 5.2 JSON in four interactive tabs.

**R5.4** WHEN displaying the taint graph, THE SYSTEM SHALL render an ASCII or SVG call-chain visualizer showing `Entrypoint → Hop 1 → Hop 2 → Sink` with taint flow annotations.

**R5.5** WHEN displaying the CVE 5.2 tab, THE SYSTEM SHALL provide one-click copy and one-click download (`.json` file) of the generated CVE record.

**R5.6** WHEN any REST endpoint fails, THE SYSTEM SHALL return a structured JSON error response (never a 500 HTML page) and display a human-readable error message in the UI.
