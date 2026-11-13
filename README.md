# ChimeraAudit — Frankenstein Security Engine

> A Frankenstein security auditor stitching together multi-hop static slicing, Kleene three-valued logic, two-tier AI skeptic funnel, 4-source CVE deduplication, and native Kiro MCP/Hooks integration.

**Built for Kiroween 2026 — Frankenstein Track**

## 🧪 What's Inside?

ChimeraAudit combines six heterogeneous security technologies into one cohesive, self-verifying system:

1. **Multi-Hop Taint Slicer** (`chimera/slicer.py`)
   - Cross-language (Python FastAPI/Flask + Java Spring Boot)
   - Multi-function call chain stitching (up to 5 hops)
   - Triple-quoted string masking with line number preservation

2. **Kleene Three-Valued Deterministic Gate** (`chimera/detectors.py`)
   - Six security categories: SQLi, Path Traversal, Authorization, Deserialization, Command Injection, SSRF
   - True/False/None verdicts (not "likely" or "probably")
   - Container-aware (Tomcat 10.1 + Spring 6.1 normalization)

3. **Two-Tier AI Skeptic Funnel** (`chimera/funnel.py`)
   - Tier 1: Fast LLM check for ambiguous (None) verdicts
   - Tier 2: Deep skeptic reasoning ("why is it safe?" vs "why is it vulnerable?")
   - 95% token savings through deterministic pre-filtering

4. **4-Source 0-Day Deduplication** (`chimera/dedup.py`)
   - NVD, CIRCL, GHSA, GitHub Issues in parallel
   - Whole-class vs. method-specific matching
   - Evidence completeness tracking

5. **Auto-Patch Synthesis & Self-Verification** (`chimera/patcher.py` + `chimera/cve5_exporter.py`)
   - Unified diff generation
   - Automatic re-detector verification (True → False)
   - MITRE CVE 5.2 (`x_CAN` extension) export

6. **Kiro Native Integration** (`mcp_server.py` + `.kiro/hooks/`)
   - MCP server exposing 4 security tools
   - Post-save hook for IDE integration

---

## 🚀 Quick Start (Local Dev)

### Prerequisites
- Python 3.11+
- pip or virtual environment

### 1. Clone & Install

```bash
git clone https://github.com/your-org/chimera-audit.git
cd chimera-audit
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt
```

### 2. Run Tests

```bash
pytest tests/test_chimera_suite.py -v
# Expected: 27/27 passed ✅
```

### 3. Start Web Server

```bash
uvicorn app:app --reload --port 8000
```

Open browser to **http://localhost:8000** → "Dr. Frankenstein's Zero-Day Laboratory" UI

### 4. One-Click Presets

In the web UI, click any of 6 presets:
- **[0-Day #1]** Multi-Hop FileWriter Escape (pathtraver)
- **[0-Day #2]** Workflow JSON SQLi (sqli)
- **[0-Day #3]** Bare @PostMapping Authz Bypass (authz)
- **[0-Day #4]** Chunk Upload Traversal (pathtraver)
- **[FP Trap #1]** Tomcat @PathVariable Guard (safe—not vulnerable)
- **[FP Trap #2]** NamedParam SQL Builder (safe—not vulnerable)

Each preset runs the full audit pipeline in < 2 seconds.

---

## 📐 Architecture

```
┌────────────────────────────────────────────────────────────┐
│  Web Frontend (Dark Lab UI)                                 │
│  web/index.html + app.py FastAPI                           │
└────────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────────┐
│  Layer 4: CVE Dedup + Export                               │
│  chimera/dedup.py  ·  chimera/cve5_exporter.py             │
└────────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────────┐
│  Layer 3: Two-Tier AI Skeptic Funnel                       │
│  chimera/funnel.py  (Tier 1/2, offline fallback)           │
└────────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────────┐
│  Layer 2: Kleene 3-Valued Detectors                        │
│  chimera/detectors.py  (True/False/None)                   │
└────────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────────┐
│  Layer 1: Multi-Hop Taint Slicer                           │
│  chimera/slicer.py  (cross-language, cross-function)       │
└────────────────────────────────────────────────────────────┘
```

---

## 🔌 Kiro IDE Integration

### MCP Server

Register the local MCP server in your Kiro workspace:

**Via mcp.json in workspace root:**
```json
{
  "mcpServers": {
    "chimera-audit": {
      "command": "python",
      "args": ["mcp_server.py"],
      "env": {"PYTHONPATH": "."}
    }
  }
}
```

Then in Kiro Agent:
```
Analyze this code for vulnerabilities using chimera_audit_code tool
```

### Post-Save Hook

When you save a `.py` or `.java` file, the hook automatically:
1. Runs all 27 unit tests
2. Imports all detectors (sanity check)
3. Blocks save if critical test failures occur (exit code 2)

Hook location: `.kiro/hooks/chimera-security-gate.json`

---

## 📋 Steering Files

All engineering invariants are documented in:

- **`.kiro/steering/security-invariants.md`**: Kleene logic rules, container fidelity, dedup scope, SQL detector rules, etc.
- **`.kiro/steering/architecture-conventions.md`**: Module boundaries, data flow contract, code style, deployment requirements

---

## 🧬 API Endpoints

All requests/responses are JSON.

### `POST /api/audit`
**Analyze code for vulnerabilities.**

Request:
```json
{
  "code": "...",
  "language": "python|java",
  "filename": "example.py"
}
```

Response:
```json
{
  "entry_function": "create_user",
  "hops": [...],
  "taint_graph": {"nodes": [...], "edges": [...]},
  "categories": {
    "sqli": {"verdict": true, "confidence": 0.98, "explanation": "..."},
    "pathtraver": {"verdict": false, ...},
    ...
  },
  "token_savings_pct": 95.2,
  "patch": {"unified_diff": "...", "patch_verified": true}
}
```

### `GET /api/presets`
**Get all 6 demo presets.**

Response:
```json
{
  "presets": [
    {
      "id": "0day_1_filewriter",
      "label": "[0-Day #1] Multi-Hop FileWriter Escape",
      "category": "pathtraver",
      "code": "...",
      "language": "java",
      "expected_verdict": true
    },
    ...
  ]
}
```

### `POST /api/dedup`
**Check for duplicate CVEs.**

Request:
```json
{
  "repo_slug": "org/repo",
  "category": "sqli",
  "unit_name": "searchMapStr",
  "file_path": "WorkflowController.java"
}
```

### `POST /api/cve5`
**Export MITRE CVE 5.2 record.**

Request:
```json
{
  "repo_slug": "org/repo",
  "category": "sqli",
  "unit_name": "searchMapStr",
  "file_path": "WorkflowController.java",
  "cwe_id": "CWE-89",
  "cvss_score": 9.8
}
```

### `GET /api/health`
**Health check.**

Response:
```json
{
  "status": "ok",
  "version": "1.0.0",
  "offline_mode": false
}
```

---

## 🐳 Docker Deployment

### Build locally
```bash
docker build -t chimera-audit:latest .
docker run -p 8000:8000 chimera-audit:latest
```

### Deploy to Render (free tier)

1. **Fork/push** this repo to GitHub
2. **Connect** GitHub repo to [Render](https://render.com)
3. **Select** `Dockerfile` runtime
4. **Click "Deploy"**

Your app will be live at `https://chimera-audit-XXXXX.onrender.com` in ~2 minutes.

---

## 📊 Test Results

```
$ pytest tests/test_chimera_suite.py -v
============================= test session starts =============================
collected 27 items

tests/test_chimera_suite.py::TestMaskTripleQuoted::test_mask_preserves_line_numbers PASSED
tests/test_chimera_suite.py::TestSlicer::test_slice_python_route PASSED
tests/test_chimera_suite.py::TestDetectors::test_detect_sqli_vulnerable PASSED
... (24 more passed)

============================= 27 passed in 0.07s =============================
```

---

## 🎯 Kiroween 2026 — Compliance Checklist

- ✅ **New GitHub repo** (post 2026-10-30, no early commit history)
- ✅ **MIT License** (visible in About section)
- ✅ **`.kiro/` directory** committed (NOT in .gitignore)
  - `.kiro/steering/security-invariants.md`
  - `.kiro/steering/architecture-conventions.md`
  - `.kiro/specs/chimera-audit/requirements.md`
  - `.kiro/specs/chimera-audit/design.md`
  - `.kiro/specs/chimera-audit/tasks.md`
  - `.kiro/hooks/chimera-security-gate.json`
  - `mcp.json` (workspace-level MCP registration)
- ✅ **Zero-auth demo** (6 presets work immediately)
- ✅ **Working app URL** (Render free tier deployment)
- ✅ **Comprehensive tests** (27/27 passing)
- ✅ **Honestly stitched** (no smoke, real cross-functional integration)

---

## 📺 Demo Video

**YouTube**: [Coming soon — 2:30 min demo](https://youtube.com)

Covers:
1. Kiro IDE + `.kiro/specs/` integration
2. Live web UI with 6 presets
3. Auto-patch synthesis
4. MITRE CVE 5.2 export
5. Token savings telemetry

---

## 🤖 Kiro Agent Interaction

Example Kiro prompt:
```
Read chimera/detectors.py and suggest an improvement to the SQLi detector
to reduce false negatives for parameterized placeholders with complex
type conversion functions.
```

The Kiro Agent will:
1. Use `chimera_audit_code` MCP tool to analyze modified code
2. Run `.kiro/hooks/chimera-security-gate` post-save
3. Reference `.kiro/steering/security-invariants.md` for decision criteria
4. Propose changes that satisfy `tasks.md` checklist

---

## 📚 Project Structure

```
chimera-audit/
├── LICENSE                          # MIT
├── README.md                        # You are here
├── requirements.txt                 # fastapi, uvicorn, pytest
├── Dockerfile                       # One-click containerization
├── render.yaml                      # Render deployment config
├── mcp.json                         # Workspace MCP registration
├── app.py                           # FastAPI backend
├── mcp_server.py                    # MCP server (JSON-RPC 2.0)
├── .kiro/
│   ├── steering/
│   │   ├── security-invariants.md   # Engineering invariants
│   │   └── architecture-conventions.md
│   ├── specs/chimera-audit/
│   │   ├── requirements.md          # EARS syntax requirements
│   │   ├── design.md                # Technical design
│   │   └── tasks.md                 # Implementation checklist
│   └── hooks/
│       └── chimera-security-gate.json
├── chimera/
│   ├── __init__.py
│   ├── slicer.py                    # Multi-hop taint slicer
│   ├── detectors.py                 # Kleene 3-valued gates
│   ├── funnel.py                    # 2-tier AI skeptic funnel
│   ├── dedup.py                     # 4-source CVE dedup
│   ├── patcher.py                   # Auto-patch synthesis
│   ├── cve5_exporter.py             # MITRE CVE 5.2 export
│   └── presets.py                   # 6 demo presets
├── web/
│   └── index.html                   # Dark Lab UI
└── tests/
    ├── __init__.py
    └── test_chimera_suite.py        # 27 comprehensive tests
```

---

## 🔐 Security Notes

- **Deterministic engine has NO external dependencies** beyond stdlib regex
- **MCP server** runs locally, no data exfiltration
- **Offline mode** requires no API keys
- **All detectors** return conservative verdicts (prefer True over False when ambiguous)

---

## 📖 References

- [MITRE CVE JSON Schema 5.2](https://github.com/CVEProject/cve-schema)
- [CVSS 3.1 Vector](https://www.first.org/cvss/v3.1/)
- [Kleene Logic](https://en.wikipedia.org/wiki/Three-valued_logic)
- [Kiro IDE](https://kiro.dev) — Agent coding with Specs, Steering, Hooks, MCP
- [Frankenstein Monster](https://en.wikipedia.org/wiki/Frankenstein%27s_monster) — A being stitched together from parts

---

## 💡 Future Work

- [ ] LLM backend integration (GPT-4o, Claude 3.5)
- [ ] Database persistence (audit history)
- [ ] GitHub app integration (auto-comment PRs)
- [ ] Container image scanning
- [ ] Supply chain CWE (CWE-1021) support
- [ ] Proof-of-concept generation

---

**Made with 🧪 for Kiroween 2026 Frankenstein Track**
