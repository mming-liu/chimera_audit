# ChimeraAudit — Deployment Guide

## Pre-Deployment Checklist

Before pushing to GitHub and deploying to Render, verify:

- [ ] All 27 unit tests pass: `pytest tests/test_chimera_suite.py -v`
- [ ] MCP server runs without errors: `python mcp_server.py`
- [ ] Core modules import successfully: `python -c "from chimera import *"`
- [ ] `.kiro/` directory is NOT in `.gitignore`
- [ ] `LICENSE` file exists and is MIT
- [ ] `README.md` is comprehensive
- [ ] `requirements.txt` has all dependencies
- [ ] `Dockerfile` builds successfully: `docker build -t chimera-audit .`
- [ ] Web frontend loads at `http://localhost:8000`

## Step 1: Local Development

### Install dependencies
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run tests
```bash
pytest tests/test_chimera_suite.py -v
# Expected: 27/27 passed
```

### Start web server
```bash
uvicorn app:app --reload --port 8000
```

Visit `http://localhost:8000` and test presets.

## Step 2: GitHub Setup

### Initialize git repo
```bash
git init
git add .
git commit -m "Initial ChimeraAudit Kiroween 2026 commit"
```

### Important: Do NOT gitignore `.kiro/`
Verify `.gitignore` does NOT contain:
```
.kiro/
```

If it does, remove it:
```bash
git rm --cached .kiro/
```

### Create GitHub repo
1. Go to [github.com/new](https://github.com/new)
2. Repository name: `chimera-audit`
3. Make it **PUBLIC**
4. Select **MIT License** template
5. Click "Create repository"

### Push to GitHub
```bash
git remote add origin https://github.com/YOUR-ORG/chimera-audit.git
git branch -M main
git push -u origin main
```

### Verify GitHub repo
- [ ] `.kiro/` directory visible in file tree
- [ ] MIT License badge visible in About section
- [ ] `README.md` renders correctly

## Step 3: Docker Build (Local)

### Build image
```bash
docker build -t chimera-audit:latest .
```

### Test container
```bash
docker run -p 8000:8000 chimera-audit:latest
```

Visit `http://localhost:8000` to verify app works inside container.

## Step 4: Deploy to Render

### Prerequisites
- Render account (free at [render.com](https://render.com))
- GitHub account with public repo

### Deploy steps
1. Log in to [Render Dashboard](https://dashboard.render.com)
2. Click "+ New" → "Web Service"
3. Select "Build and deploy from a Git repository"
4. Connect your GitHub account (authorize)
5. Select `chimera-audit` repository
6. Fill in:
   - **Name**: chimera-audit
   - **Environment**: Docker
   - **Region**: Oregon (or closest)
   - **Plan**: Free (or Pro for better performance)
7. Click "Create Web Service"

### Monitor deployment
Render will:
1. Clone your repo
2. Build Docker image (~2 minutes)
3. Start container (~1 minute)
4. Give you a URL like `https://chimera-audit-XXXXX.onrender.com`

## Step 5: Verify Live Deployment

### Health check
```bash
curl https://chimera-audit-XXXXX.onrender.com/api/health
# Expected: {"status": "ok", "version": "1.0.0", "offline_mode": true}
```

### Test presets
1. Open `https://chimera-audit-XXXXX.onrender.com` in browser
2. Click `[0-Day #2] Workflow JSON SQLi`
3. Should run analysis in < 3 seconds
4. Verdict should be `VULNERABLE`

### Test API
```bash
curl -X POST https://chimera-audit-XXXXX.onrender.com/api/presets
# Expected: list of 6 presets
```

## Step 6: Post-Deploy Checklist

- [ ] Live URL is public and accessible
- [ ] Health check returns `{"status": "ok"}`
- [ ] All 6 presets work without login
- [ ] Analysis completes in < 3 seconds
- [ ] Add live URL to GitHub About section
- [ ] Update README.md with live URL (if desired)

## Troubleshooting

### Build fails: "ModuleNotFoundError"
- Ensure `requirements.txt` has all dependencies
- Check Python version in `Dockerfile` (should be 3.11+)

### Container won't start: Port 8000 already in use
- Render automatically handles port mapping
- Check logs in Render dashboard

### Web UI shows 404 for `/api/presets`
- Ensure `app.py` has all route handlers
- Check MCP server isn't conflicting (it's separate process)

### Tests fail locally but pass in CI
- Ensure Python version matches 3.11+
- Run `pip install -r requirements.txt` again
- Clear `.pytest_cache/`: `rm -rf .pytest_cache/`

## Next Steps (Optional)

1. **Add GitHub Actions CI** to auto-test on push
2. **Record demo video** (2:30 max) and upload to YouTube
3. **Write blog post** on Dev.to/Medium about Kiro Specs
4. **Submit to Kiroween 2026** contest at [kiroween.devpost.com](https://kiroween.devpost.com)

---

For issues, open a GitHub Issue or check [README.md](README.md) for more details.
