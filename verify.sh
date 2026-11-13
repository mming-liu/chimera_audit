#!/bin/bash

# ChimeraAudit Verification Script
# Run this before pushing to GitHub

set -e

echo "════════════════════════════════════════════════════════════"
echo "ChimeraAudit Pre-Push Verification"
echo "════════════════════════════════════════════════════════════"
echo

# 1. Check .kiro directory
echo "✓ Checking .kiro/ structure..."
if [ ! -d ".kiro/steering" ] || [ ! -d ".kiro/specs" ] || [ ! -d ".kiro/hooks" ]; then
    echo "❌ Missing .kiro/ subdirectories"
    exit 1
fi
echo "  ✓ .kiro/steering/ exists"
echo "  ✓ .kiro/specs/ exists"
echo "  ✓ .kiro/hooks/ exists"
echo

# 2. Check required files
echo "✓ Checking required files..."
required_files=(
    "LICENSE"
    "README.md"
    "requirements.txt"
    "Dockerfile"
    "render.yaml"
    "app.py"
    "mcp_server.py"
    "mcp.json"
    ".kiro/steering/security-invariants.md"
    ".kiro/steering/architecture-conventions.md"
    ".kiro/specs/chimera-audit/requirements.md"
    ".kiro/specs/chimera-audit/design.md"
    ".kiro/specs/chimera-audit/tasks.md"
    ".kiro/hooks/chimera-security-gate.json"
    "chimera/slicer.py"
    "chimera/detectors.py"
    "chimera/funnel.py"
    "chimera/dedup.py"
    "chimera/patcher.py"
    "chimera/cve5_exporter.py"
    "chimera/presets.py"
    "tests/test_chimera_suite.py"
    "web/index.html"
)

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "❌ Missing file: $file"
        exit 1
    fi
done
echo "  ✓ All 23 required files present"
echo

# 3. Check .gitignore
echo "✓ Checking .gitignore..."
if grep -q "\.kiro/" .gitignore 2>/dev/null; then
    echo "❌ .kiro/ is in .gitignore (remove it!)"
    exit 1
fi
echo "  ✓ .kiro/ is NOT in .gitignore"
echo

# 4. Run tests
echo "✓ Running unit tests..."
python -m pytest tests/test_chimera_suite.py -v --tb=line 2>&1 | tail -5
test_result=$?
if [ $test_result -ne 0 ]; then
    echo "❌ Tests failed"
    exit 1
fi
echo

# 5. Check Python imports
echo "✓ Checking Python imports..."
python -c "
from chimera.slicer import slice_code
from chimera.detectors import detect_sqli
from chimera.funnel import route_through_funnel
from chimera.dedup import dedup_check
from chimera.patcher import synthesize_patch
from chimera.cve5_exporter import build_cve5_record
from chimera.presets import get_all_presets
print('  ✓ All core modules import successfully')
print(f'  ✓ Loaded {len(get_all_presets())} demo presets')
"
echo

# 6. Check LICENSE format
echo "✓ Checking LICENSE..."
if head -1 LICENSE | grep -q "MIT License"; then
    echo "  ✓ MIT License detected"
else
    echo "❌ LICENSE format invalid"
    exit 1
fi
echo

# 7. Check Dockerfile
echo "✓ Checking Dockerfile..."
if grep -q "FROM python:3.11" Dockerfile && grep -q "EXPOSE 8000" Dockerfile; then
    echo "  ✓ Dockerfile looks good"
else
    echo "❌ Dockerfile missing key directives"
    exit 1
fi
echo

echo "════════════════════════════════════════════════════════════"
echo "✅ ALL PRE-PUSH CHECKS PASSED"
echo "════════════════════════════════════════════════════════════"
echo
echo "Next steps:"
echo "  1. git add ."
echo "  2. git commit -m 'Initial ChimeraAudit Kiroween 2026 commit'"
echo "  3. git push -u origin main"
echo "  4. Deploy to Render.com"
echo
