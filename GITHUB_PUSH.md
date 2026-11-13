# 🚀 ChimeraAudit — GitHub 推送快速参考

> 清理与规范化完成 ✅ — 现在推送到新 GitHub 仓库

## 一键推送命令（复制粘贴）

### Step 1: 本地 Git 初始化（如未初始化）

```powershell
# Windows PowerShell
cd c:\myFloders\git\chimera_audit
git init
git config user.name "YourName"
git config user.email "your.email@example.com"
```

或 macOS/Linux：
```bash
cd ~/path/to/chimera_audit
git init
git config user.name "YourName"
git config user.email "your.email@example.com"
```

### Step 2: 添加并提交

```bash
git add .
git commit -m "chore: clean pycache and align .kiro settings for Kiroween 2026 submission"
```

### Step 3: 创建 GitHub 仓库

**重要**：在 [github.com/new](https://github.com/new) 创建**新的公开仓库**

1. **Repository name**: `chimera-audit`
2. **Public** ✓
3. **Add a license**: MIT License ✓
4. **Initialize this repository with** ❌ 不勾（我们已有代码）
5. 点击 "Create repository"

### Step 4: 关联远程并推送

替换 `YOUR-USERNAME` 为你的 GitHub 用户名：

```bash
git remote add origin https://github.com/YOUR-USERNAME/chimera-audit.git
git branch -M main
git push -u origin main
```

### Step 5: 验证

访问 `https://github.com/YOUR-USERNAME/chimera-audit`，检查：

- [ ] 仓库主页显示 MIT License 图标
- [ ] `.kiro/steering/` 可见
- [ ] `.kiro/specs/` 可见
- [ ] `.kiro/hooks/` 可见
- [ ] `README.md` 正确渲染
- [ ] 所有 45+ 文件都在列表中

---

## 验证清单

运行以下命令验证一切就绪：

```bash
# 1. 检查 .gitignore
cat .gitignore
# 应输出（无 .kiro/ 字样）：
# __pycache__/
# *.py[cod]
# ...

# 2. 检查 .kiro 目录存在
ls -la .kiro/steering/
ls -la .kiro/specs/
ls -la .kiro/hooks/

# 3. 运行测试
pytest tests/test_chimera_suite.py -q
# 应输出：27 passed
```

---

## 后续：部署到 Render

提交后立即部署（3 分钟）：

1. 登录 [render.com](https://render.com)
2. 点击 `+ New` → `Web Service`
3. 连接 GitHub 账号，选择 `chimera-audit` 仓库
4. 设置：
   - Name: `chimera-audit`
   - Environment: `Docker`
   - Plan: `Free`
5. 点击 `Create Web Service`

等待部署完成（~2-3 分钟），获得 `https://chimera-audit-XXXXX.onrender.com`

---

## 故障排查

### Q: `git remote add` 报错 "repository already exists"
**A**: 执行 `git remote remove origin`，再重新添加

### Q: 推送时报错 "Permission denied"
**A**: 确认已登录 GitHub（`git config --global user.name` 检查）

### Q: GitHub 上看不到 `.kiro/` 文件
**A**: 检查 `.gitignore` 是否包含 `.kiro/`（应该不包含）
```bash
grep ".kiro" .gitignore
```
如果有输出，表示错误。修复：编辑 `.gitignore`，移除相关行。

### Q: MIT License 图标不显示
**A**: 在仓库 About 栏手动选择 `Choose a license` → MIT License

---

## 完成后的奖项冲刺

✅ **Best Frankenstein** — 技术评分（已完整实现）
✅ **Best Demo** — 网页 UI 演示（6 个一键预设）
✅ **Blog Post Prize** — 可选撰写技术博客
✅ **Social Blitz Prize** — 可选发 X/LinkedIn

---

**推送成功后，立即录制 2:30 演示视频并上传 YouTube！** 🎬

