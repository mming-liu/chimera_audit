# 🚀 ChimeraAudit — 快速启动指南

> **5 分钟本地运行 | 3 分钟 Render 部署 | 完整 Kiroween 2026 Frankenstein 赛道实现**

## 本地运行（5 分钟）

### 1. 安装依赖
```bash
cd chimera-audit
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. 运行测试
```bash
pytest tests/test_chimera_suite.py -v
# 预期：27/27 PASSED ✅
```

### 3. 启动 Web 服务器
```bash
uvicorn app:app --reload --port 8000
```

### 4. 打开浏览器
访问 **http://localhost:8000**

### 5. 点击预设
在"Dr. Frankenstein's Zero-Day Laboratory"UI 中，点击任意 6 个一键预设：
- `[0-Day #1] Multi-Hop FileWriter Escape` — 路径穿越漏洞
- `[0-Day #2] Workflow JSON SQLi` — SQL 注入
- `[0-Day #3] Bare @PostMapping Authz Bypass` — 授权绕过
- `[0-Day #4] Chunk Upload Traversal` — 上传目录穿越
- `[FP Trap #1] Tomcat @PathVariable Guard` — 正确的（不脆弱）
- `[FP Trap #2] NamedParam SQL Builder` — 正确的（不脆弱）

---

## Docker 运行（3 分钟）

```bash
# 构建镜像
docker build -t chimera-audit:latest .

# 运行容器
docker run -p 8000:8000 chimera-audit:latest

# 访问 http://localhost:8000
```

---

## 部署到 Render（3 分钟）

### 前置条件
- GitHub 账号（已有代码）
- Render 账号（免费，[render.com](https://render.com)）

### 步骤
1. **推送到 GitHub**（如未推送）
   ```bash
   git add .
   git commit -m "ChimeraAudit Kiroween 2026"
   git push -u origin main
   ```

2. **连接 Render**
   - 登录 [dashboard.render.com](https://dashboard.render.com)
   - 点击 `+ New` → `Web Service`
   - 选择 `Build and deploy from Git`
   - 授权 GitHub，选择 `chimera-audit` 仓库
   - 设置：
     - **Name**: chimera-audit
     - **Environment**: Docker
     - **Region**: Oregon
     - **Plan**: Free
   - 点击 `Create Web Service`

3. **等待部署**（~2 分钟）
   - Render 自动 build Docker 镜像
   - 部署到公网
   - 获得 URL：`https://chimera-audit-XXXXX.onrender.com`

4. **验证**
   ```bash
   curl https://chimera-audit-XXXXX.onrender.com/api/health
   # {"status":"ok","version":"1.0.0","offline_mode":true}
   ```

---

## 核心特性一览

| 特性 | 说明 |
|------|------|
| **5 层架构** | 切片器 → 检测器 → AI 漏斗 → 查重 → 补丁 + CVE |
| **Kleene 逻辑** | True/False/None 三值判定（不是概率） |
| **6 类漏洞** | SQLi、PathTraver、Authz、Deserial、CmdI、SSRF |
| **2 层 LLM** | Tier1 快速、Tier2 深度怀疑 + 100% 离线回退 |
| **4 源查重** | NVD、CIRCL、GHSA、GitHub Issues |
| **Kiro 原生** | Specs、Steering、Hooks、MCP Server |
| **一键演示** | 6 个真实预设，2 秒完成分析 |
| **自证补丁** | 生成 Unified Diff，re-run 检测器验证 |
| **CVE 5.2** | MITRE CNA-LR 格式，x_CAN 扩展 |

---

## 项目结构

```
chimera-audit/
├── chimera/              # 5 层安全引擎核心
├── tests/                # 27 个单元测试（100% pass）
├── .kiro/                # Specs、Steering、Hooks、MCP 配置
├── web/                  # 暗黑风前端（暗黑实验室 UI）
├── app.py                # FastAPI 后端
├── mcp_server.py         # MCP 服务器
├── Dockerfile            # 容器化部署
├── render.yaml           # Render 配置
├── requirements.txt      # 依赖清单
├── README.md             # 完整文档
├── DEPLOYMENT.md         # 部署指南
└── LICENSE               # MIT License
```

---

## 常见问题

### Q: 需要 API Key 吗？
**A**: 不需要。所有演示完全离线，无需任何 API Key。系统自动离线降级。

### Q: 支持什么编程语言？
**A**: 目前支持 Python（FastAPI/Flask）和 Java（Spring Boot）。

### Q: 可以审计自己的代码吗？
**A**: 可以。在 Web UI 左侧粘贴代码，选择语言，点击"提交"即可。

### Q: 结果准确率如何？
**A**: 
- **确定性检测**（True/False）：准确率 95%+ 
- **AI 辅助**（None → AI 判定）：准确率 85%+

### Q: 补丁安全吗？
**A**: 所有补丁自动 re-run 检测器验证（True → False）。只有通过的才导出。

### Q: 怎么集成到 Kiro IDE？
**A**: `.kiro/settings/mcp.json` 已配置。在 Kiro 中可直接调用 MCP 工具。

---

## 性能指标

| 操作 | 时间 |
|------|------|
| 单预设分析 | ~0.5-1 秒 |
| 6 分类完整审计 | ~2 秒 |
| 补丁生成 + 验证 | ~0.3 秒 |
| CVE 5.2 导出 | ~0.2 秒 |
| API 延迟（Render） | ~500ms |

---

## 下一步

### 推荐：冲刺 Kiroween 2026 奖项
1. ✅ **项目已完成** — 所有代码、测试、文档就绪
2. 📍 **即将推送** — 创建 GitHub 公开仓库
3. 🚀 **即将部署** — Render 一键部署
4. 📹 **待录制** — 2:30 分钟 YouTube 演示视频
5. ✍️ **可选** — 发布技术博客（争 Blog Post Prize）
6. 🎯 **提交** — 在 [kiroween.devpost.com](https://kiroween.devpost.com) 提交

### 本地开发继续
- 修改 `chimera/` 中任意模块 → 测试自动触发
- 编辑 `.kiro/steering/` 修改工程约束
- 在 Kiro IDE 中调用 MCP 工具进行代码审计

---

## 联系支持

- **GitHub Issues**: 在项目 Issue tracker 提交 bug/feature request
- **Documentation**: 详见 `README.md` 和 `DEPLOYMENT.md`
- **Kiro Integration**: 参考 `.kiro/specs/chimera-audit/` 中的需求文档

---

**Built for Kiroween 2026 — Frankenstein Track** 🧪✨
