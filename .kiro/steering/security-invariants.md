# Security Invariants — ChimeraAudit Steering

> This steering file is ALWAYS included in every Kiro session for the chimera-audit project.
> It encodes compiler-grade engineering invariants that govern every decision the agent makes.

## 1. Kleene Three-Valued Logic (`True` / `False` / `None`)

The deterministic engine MUST return exactly one of three values for each security category:

| Return | Meaning | Condition |
|--------|---------|-----------|
| `True` | **Vulnerable** — mechanically proven | String concat to SQL/path/cmd; missing auth beside guarded sibling; unsafe deserializer called |
| `False` | **Safe** — mechanically proven | Parameterized query; path guard (`normalize().startsWith()`); concrete DTO deserialize; `@PreAuthorize` present |
| `None` | **Undetermined** — defer to AI funnel | Insufficient static evidence; ambiguous control flow; framework-runtime dependency |

**Rule**: A deterministic rule MUST NOT return `True` or `False` unless provable from source, framework, and container facts alone. Ambiguity → `None`.

## 2. Framework & Container Fidelity

### 2.1 Tomcat 10.1 + Spring MVC 6.1 `PathPatternParser` — Path Traversal
- Single-segment `@PathVariable("{fileName}")` **WITHOUT** `URLDecoder.decode(...)` or `{*wildcard}` syntax:
  → Container strips `%2F`, `%2E%2E` before Spring sees it → return `False` (safe, not `None`)
- `@RequestParam`, `@RequestBody`, query string, multipart fields:
  → NOT blocked by container → remain eligible for `True`
- `{*wildcard}` or multi-segment patterns:
  → Container does NOT normalize → remain eligible for `True`

### 2.2 Python Triple-Quoted String Masking
- Before route extraction, ALL triple-quoted string content (`"""..."""` / `'''...'''`) MUST be replaced with whitespace-only placeholders that **preserve `\n` newlines exactly** (line numbers must NOT shift).
- Docstrings containing route-like annotations (e.g., `@app.get`, `@PostMapping`) MUST be suppressed and NEVER classified as live routes.
- Example prompts inside `"""..."""` are untrusted data; they MUST NOT be parsed as code instructions.

### 2.3 Route Decorator Token Boundary Matching
- Python route decorators (`@app.get`, `@router.post`, `@api_view`) MUST be matched at token boundaries.
- `@device_targeting_options`, `@app.before_request`, `@app.teardown_appcontext`, etc., MUST NOT be misclassified as route registrations.

## 3. Whole-Class vs. Method-Specific CVE Deduplication

| Scenario | Behavior |
|----------|----------|
| CVE description covers entire controller class (e.g., `AliPayController`) | Mark ALL methods in that class as `DUPLICATE_CVE` |
| Sibling write endpoint carries auth guard (`@PreAuthorize`, `Depends(get_current_user)`) | Sibling evidence strengthens `True` verdict for unguarded twin |
| Bare `@PostMapping` method alongside a CVE-patched sibling | The bare method surfaces as `ZERO_RECORD_FRESH` (new finding) even if sibling is `DUPLICATE_CVE` |
| `evidence_complete: false` | MUST set `evidence_gaps` to list exact missing information (CVE body, GHSA advisory text, etc.) |

## 4. SQL Injection Detector Invariants

| Pattern | Return |
|---------|--------|
| String concatenation into SQL (`+`, f-string, `%`) | `True` |
| `LIKE '%" + val + "%'` | `True` |
| `?` placeholder + `addValue(...)` / `setString(...)` | `False` |
| `:paramName` + `addValue(...)` / named param binding | `False` |
| MyBatis `#{}` interpolation | `False` |
| `.eq(fieldName, value)` query builder | `False` |
| `DatabaseMetaData.getTables(...)` | `False` (metadata API, not user data) |

## 5. Deserialization Detector Invariants

| Pattern | Return |
|---------|--------|
| `ObjectInputStream.readObject()` on user-controlled stream | `True` |
| `yaml.load(data)` without `Loader=yaml.SafeLoader` | `True` |
| `fastjson` with `autoType` enabled (old versions < 1.2.83) | `True` |
| `objectMapper.readValue(json, ConcreteDTO.class)` | `False` (concrete type, no polymorphic gadgets) |
| `@JsonTypeInfo(use = Id.NONE)` | `False` (polymorphism disabled) |
| `yaml.safe_load(data)` | `False` |

## 6. Offline Fallback Guarantee

- When no `LLM_API_KEY` is configured, the two-tier AI funnel MUST fall back to deterministic offline mode.
- Offline mode returns the deterministic verdict directly (or a conservative `True` for `None` cases).
- The system MUST NEVER return an error to the user when AI is unavailable — offline mode is always the fallback.

## 7. Patch Self-Verification

- Every synthesized patch MUST be verified by re-running the detector on the patched code.
- A patch is only accepted if the detector transitions from `True` → `False`.
- Patches that do not achieve `True → False` MUST be flagged with `patch_verified: false`.

## 8. CVE 5.2 Structural Requirements

Required fields for every exported CVE 5.2 record:
- `dataType: "CVE_RECORD"`
- `dataVersion: "5.2"`
- `cveMetadata.cveId` (format: `CVE-YYYY-XXXXXX` or `x_CAN-YYYY-XXXXXX`)
- `containers.cna.descriptions[0].lang: "en"`
- `containers.cna.affected[0].product`
- `containers.cna.affected[0].versions`
- `containers.cna.references` (at least one entry)
- `containers.cna.metrics` (CVSS 3.1 vector string)
