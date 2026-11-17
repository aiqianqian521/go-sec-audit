# 检索索引（rag-index）

**不要全读 references/**。语料 24 文件（2026-11-16 压力测试收口实测合计 ~3068 行，
另有 SKILL.md 215 行；行数随维护自然变动，引用时以复测时点为准，不要写死在别处）。
全读挤爆上下文，全不读等于没有。
用 `scripts/kb_retrieve.py` 两通道取数，一次审计控制在 3-4k token 参考量。

```bash
python scripts/kb_retrieve.py --project <path>            # 指纹唤醒 + 按需检索
python scripts/kb_retrieve.py --q "越权 401 return 装饰"     # 关键词直查
python scripts/kb_retrieve.py --hits E1-SHELL-C,X-PATHTRAV-JOIN
python scripts/kb_retrieve.py --list                       # 全部 chunk
```

## 通道

- **A 指纹唤醒（确定性）**：项目目录 → 检测框架/部署形态/已命中 sink →
  FINGERPRINTS 硬映射必读 chunk，置顶不打分
- **B 关键词检索（BM25）**：heading 命中加权；中文 2-gram，英文按词，
  "路径穿越"和"path traversal"都能召回

输出 `file:start-end`，直接喂 Read 的 offset/limit。

## 语料分层与加载预算

| 层 | 文件 | 何时读 |
|---|---|---|
| 流程 | SKILL.md（本体） | 开场 |
| 骨架 | execution-policy / application-surface / framework-signals / route-map / report-template | Phase 0 / 1 / 6，按阶段 |
| 判决素材 | vuln-features / six-paths / sink-catalog / case-library / reachability / verification-gates | 命中对应类时 |
| 分维度方法论 | authorization / capability-assessment / command-execution / sql-injection / ssrf / template-injection / file-transfers / unsafe-memory | **只在该维度进入判决时**，不预读 |
| 历史线索（可选） | execution-reference-notes / sql-reference-notes / io-template-reference-notes | 独立发现之后 |
| 评估场景 | acceptance-cases | 开发期行为检查 |

## 典型指纹 → 首读

- HTTP 服务（gin/echo/chi/…）→ application-surface + framework-signals + route-map
- 出现 `exec.*` 命中 → six-paths §E1 + sink-catalog E1 节
- SQL/ORM import → vuln-features SQLi 节 + sql-injection.md
- webhook/出站请求 → vuln-features SSRF 节 + ssrf.md
- k8s/client-go → capability-assessment + authorization
- 需要写报告 → report-template（Phase 6 前）
