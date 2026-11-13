# ChimeraAudit — Technical Design Document

> Version: 1.0 | Kiroween 2026 Frankenstein Track

## 1. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                     ChimeraAudit — Frankenstein Engine               │
│                                                                      │
│  ┌────────────┐   ┌─────────────┐   ┌──────────────┐                │
│  │ Kiro IDE   │   │  Web Browser │   │ MCP Client   │                │
│  │ (Hook)     │   │  (Dark Lab)  │   │ (Kiro Agent) │                │
│  └─────┬──────┘   └──────┬──────┘   └──────┬───────┘                │
│        │                 │                  │                        │
│        └─────────────────▼──────────────────┘                       │
│                     ┌────┴─────┐                                     │
│                     │  app.py  │  FastAPI + Static File Server       │
│                     │  REST API│  POST /api/audit                    │
│                     └────┬─────┘  POST /api/dedup                   │
│                          │        POST /api/cve5                     │
│          ┌───────────────┼───────────────────┐  GET /api/presets    │
│          │               │                   │                      │
│   ┌──────▼──────┐  ┌─────▼──────┐  ┌────────▼──────┐              │
│   │  slicer.py  │  │detectors.py│  │   funnel.py   │              │
│   │  Hop Slicer │  │Kleene 3-VL │  │ 2-Tier AI     │              │
│   └──────┬──────┘  └─────┬──────┘  └────────┬──────┘              │
│          │               │                   │                      │
│          └───────────────▼───────────────────┘                      │
│                   ┌──────┴───────┐                                   │
│          ┌────────┤   dedup.py   ├────────┐                         │
│          │        │  4-Source    │        │                         │
│          │        └──────┬───────┘        │                         │
│   ┌──────▼─────┐         │         ┌──────▼──────┐                 │
│   │ patcher.py │         │         │cve5_exporter│                 │
│   │ Patch Synth│         │         │CVE 5.2 JSON │                 │
│   └────────────┘         │         └─────────────┘                 │
│                          │                                           │
│                   ┌──────▼───────┐                                   │
│                   │  presets.py  │  6 One-Click Cases                │
│                   └──────────────┘                                   │
└──────────────────────────────────────────────────────────────────────┘
```

## 2. Multi-Hop Taint Slicing Algorithm (`chimera/slicer.py`)

### 2.1 Pre-processing: Triple-Quoted String Masking

```python
def mask_triple_quoted(source: str) -> tuple[str, dict]:
    # Find all """...""" and '''...''' spans
    # Replace content with spaces, preserving \n characters exactly
    # Return masked source + restoration map {span: original_text}
```

Invariant: `masked_source.count('\n') == source.count('\n')` — line numbers never shift.

### 2.2 Route Extraction

**Python routes** (regex with token boundary `\b` or start-of-line):
```
@(?:app|router|blueprint)\.(get|post|put|delete|patch|route)\s*\(
@api_view\s*\(
```
Anti-pattern (MUST NOT match): `@device_targeting_options`, `@app.before_request`

**Java Spring routes**:
```
@(Get|Post|Put|Delete|Patch|Request)Mapping(\s*\([^)]*\)|\s+)
```
Bare `@PostMapping` (no arguments) → inherit class `@RequestMapping` prefix → route = `prefix + ""`

### 2.3 Multi-Hop Stitching

```
SliceResult:
  entry_function: str
  entry_route: str
  hops: List[Hop]       # [{hop_n, function_name, code_fragment, file, line_start}]
  taint_sources: List[str]   # ["request.args['id']", "pathVariable", ...]
  taint_sinks: List[str]     # ["cursor.execute(query)", "FileWriter(path)", ...]
  taint_nodes: List[Node]    # for graph rendering
  taint_edges: List[Edge]    # for graph rendering
```

BFS traversal: from entry function, follow direct calls to named helpers (up to 5 hops). Taint tags propagate when a tainted variable is passed as argument.

## 3. Kleene Three-Valued Detector Design (`chimera/detectors.py`)

### 3.1 Detector Interface

```python
@dataclass
class DetectorResult:
    category: str                 # "sqli" | "pathtraver" | "authz" | ...
    verdict: bool | None          # True=vulnerable, False=safe, None=undetermined
    evidence: list[str]           # supporting code fragments
    cwe_id: str                   # e.g. "CWE-89"
    cvss_base: float              # e.g. 9.8
    cvss_vector: str              # CVSS 3.1 vector string

def detect_sqli(slice: SliceResult) -> DetectorResult: ...
def detect_pathtraver(slice: SliceResult) -> DetectorResult: ...
def detect_authz(slice: SliceResult) -> DetectorResult: ...
def detect_deserial(slice: SliceResult) -> DetectorResult: ...
def detect_cmdi(slice: SliceResult) -> DetectorResult: ...
def detect_ssrf(slice: SliceResult) -> DetectorResult: ...
```

### 3.2 SQLi Decision Tree

```
contains string concatenation into SQL?
├── Yes → True (CWE-89, CVSS 9.8)
└── No → has parameterized binding? (?, :name, #{}, .eq(), addValue)
    ├── Yes → False
    └── No → None
```

### 3.3 Path Traversal Decision Tree

```
contains FileWriter(user_input) / Files.write(user_input) / open(user_input)?
├── Yes → is input from single-segment @PathVariable (no URLDecoder, no {*wildcard})?
│   ├── Yes (Java Spring + Tomcat) → False (container blocks %2F)
│   └── No → True (CWE-22, CVSS 8.1)
└── No → has normalize().startsWith() / Path.relative_to()?
    ├── Yes → False
    └── No → None
```

### 3.4 Authorization Decision Tree

```
write endpoint exists (POST/PUT/DELETE)?
├── sibling write endpoint has @PreAuthorize / Depends(auth)?
│   └── target write endpoint missing @PreAuthorize / Depends(auth)?
│       ├── Yes → True (CWE-862, CVSS 8.8) — AUTHZ_SIBLING_GUARD
│       └── No → False
└── No auth guards anywhere → None (insufficient evidence)
```

## 4. Two-Tier AI Skeptic Funnel (`chimera/funnel.py`)

```
Input: SliceResult + DetectorResult(verdict=None)
         │
    ┌────▼─────────────────────────────────────┐
    │  Tier 1: Fast Check (small model / GPT-4o-mini)   │
    │  Prompt: "Is this code vulnerable? Answer YES/NO/UNSURE + 1 sentence" │
    └────┬─────────────────────────────────────┘
         │ YES/NO → FunnelResult(final_verdict, confidence, tier=1)
         │ UNSURE ↓
    ┌────▼─────────────────────────────────────┐
    │  Tier 2: Deep Skeptic (GPT-4o / Claude 3.5)       │
    │  Prompt: "You are a security skeptic. Argue why this is NOT vulnerable. │
    │  Then argue why it IS vulnerable. Give final verdict with confidence." │
    └────┬─────────────────────────────────────┘
         │ → FunnelResult(final_verdict, confidence, tier=2, explanation)
         │
    [OFFLINE MODE: verdict=None → conservative True, offline_mode=True]
```

**Token Savings Formula**:
```
token_savings_pct = (1 - tokens_used / baseline_tokens) * 100
baseline_tokens = estimated cost if LLM processed everything
```
Deterministic `True`/`False` decisions save ~95-99% of LLM tokens.

## 5. 4-Source Deduplication (`chimera/dedup.py`)

### 5.1 Source Query Strategy

| Source | API | Search Key |
|--------|-----|------------|
| NVD | `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=...` | controller class name or method name |
| CIRCL | `https://cve.circl.lu/api/search/...` | CWE category + product |
| GHSA | `https://api.github.com/advisories?...` | repository + package name |
| GitHub Issues | `https://api.github.com/search/issues?q=...` | repo slug + method name |

### 5.2 Matching Algorithm

```python
@dataclass
class DedupResult:
    status: Literal["ZERO_RECORD_FRESH", "DUPLICATE_CVE"]
    matched_cves: list[str]       # e.g. ["CVE-2026-108706"]
    scope: Literal["whole_class", "method_specific", "none"]
    evidence_complete: bool
    evidence_gaps: list[str]      # ["GHSA advisory body unavailable", ...]
    sources_checked: list[str]    # ["NVD", "CIRCL", "GHSA", "GitHub"]
```

Whole-class match: CVE description contains controller class name → all methods tagged.
Method-specific match: CVE description contains exact method name → only that method tagged.
Unpatched sibling: Class matched but current method not in CVE → `ZERO_RECORD_FRESH`.

## 6. CVE 5.2 JSON Structure (`chimera/cve5_exporter.py`)

```json
{
  "dataType": "CVE_RECORD",
  "dataVersion": "5.2",
  "cveMetadata": {
    "cveId": "x_CAN-2026-XXXXXX",
    "assignerOrgId": "chimera-audit-cna",
    "state": "PUBLISHED"
  },
  "containers": {
    "cna": {
      "descriptions": [{"lang": "en", "value": "..."}],
      "affected": [{
        "product": "...",
        "vendor": "...",
        "versions": [{"version": "0.0", "status": "affected", "lessThan": "unpatched"}]
      }],
      "references": [{"url": "...", "name": "..."}],
      "metrics": [{
        "cvssV3_1": {
          "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "baseScore": 9.8,
          "baseSeverity": "CRITICAL"
        }
      }],
      "problemTypes": [{"descriptions": [{"type": "CWE", "cweId": "CWE-89"}]}],
      "x_CAN": {
        "sliceHops": 3,
        "taintSources": ["..."],
        "taintSinks": ["..."],
        "patchVerified": true,
        "tokenSavingsPct": 95.2
      }
    }
  }
}
```

## 7. REST API Contract (`app.py`)

### `POST /api/audit`
Request:
```json
{"code": "...", "language": "python|java", "filename": "example.py"}
```
Response: Full audit result (see architecture-conventions.md §5).

### `POST /api/dedup`
Request:
```json
{"repo_slug": "org/repo", "category": "sqli", "unit_name": "searchMapStr", "file_path": "WorkflowController.java"}
```
Response: `DedupResult` JSON.

### `POST /api/cve5`
Request:
```json
{"repo_slug": "...", "category": "sqli", "unit_name": "...", "file_path": "...", "cwe_id": "CWE-89", "cvss_score": 9.8}
```
Response: CVE 5.2 JSON record.

### `GET /api/presets`
Response: Array of 6 preset objects with `id`, `label`, `category`, `code`, `language`, `filename`.

### `GET /api/health`
Response: `{"status": "ok", "version": "1.0.0", "offline_mode": true|false}`

## 8. MCP Server Protocol (`mcp_server.py`)

Transport: stdio JSON-RPC 2.0

Tools exposed:
1. `chimera_audit_code(code, language, filename)` → Full audit result
2. `chimera_check_dedup(repo_slug, category, unit_name, file_path)` → DedupResult
3. `chimera_synthesize_patch(code, category)` → PatchResult
4. `chimera_export_cve5(repo_slug, category, unit_name, file_path, cwe_id, cvss_score)` → CVE52Record

## 9. Kiro Hook Specification

File: `.kiro/hooks/security-gate-on-save.json`
Trigger: `PostFileSave`
Matcher: `\.(py|java)$`
Action: `command` — runs `python -m pytest tests/ -x -q && python -c "from chimera.detectors import *; print('gate: ok')"`
On failure (exit != 0): surfaces error in Kiro IDE problems panel.
