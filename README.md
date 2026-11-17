# go-sec-audit

**不是又一个 Go 漏洞扫描器——是把"候选"变成"能写进报告的判决"的那一段。**

A Go source-code security audit skill for LLM agents. Scanners produce candidates; this skill
produces verdicts, and only after a named evidence gate. Every finding is graded L0→L3, every
rejection is recorded with its reason, and the rules are guarded by falsifiable assertions
(break a rule, the test must fail).

- 27 条机械 sink 规则（E1-E6 + X，RCE 类）+ 29 条关键词通道（SQLi / SSRF / 越权 / 凭据 / 内存 / 归档）
- 五档裁决：`FINDING` / `HOLD-evidence` / `HOLD-capability` / `KILL` / `未判`
- L0（sink 命中）→ L1（入口可达）→ L2（数据形态存活）→ L3（隔离环境复现）四级证据门
- 报告契约：8 节骨架 + 四态覆盖矩阵 + 计数加总校验 + 交付前 10 项检查
- 纯标准库，Python 3.9+，零第三方依赖

---

## 为什么要单独做一个

现有工具都在"报点"这一层就打住了：

| 工具 | 产出 | 缺什么 |
|---|---|---|
| gosec | AST 规则命中 + CWE 编号 | 不判可达性；一个未被任何路由引用的内部函数也会报 |
| semgrep | 模式匹配命中 | 同上；规则越多噪声越大 |
| gitleaks | 疑似凭据 | 只覆盖凭据一类 |
| **go-sec-audit** | **候选 → 调用链 → 证据门 → 判决** | 需要 LLM agent 驱动，不是一条命令出报告 |

前三个回答"这里像不像有问题"，这个回答"这个问题能不能写进报告、凭什么"。它同时强制记录
**拒绝了什么、为什么拒绝**——因为安全审计里被误报坑掉的时间，通常比漏报更多。

## 安装

skill 是 `SKILL.md` + `references/` 的目录约定，主流 agent 宿主通用。

```bash
# WorkBuddy
git clone <this-repo> ~/.workbuddy/skills/go-sec-audit

# Claude Code
git clone <this-repo> ~/.claude/skills/go-sec-audit
```

Windows 对应 `%USERPROFILE%\.workbuddy\skills\go-sec-audit`。克隆后目录里必须直接是
`SKILL.md`（不要再套一层）。

## 快速开始

```bash
# 1. 机械规则扫一遍，拿到候选清单（只需 Python，不需要 LLM）
python scripts/scan_sinks.py /path/to/go/repo --out scans/report.md --json scans/report.json

# 2. 自测：确认规则本身没坏（含变异测试）
python scripts/test_scan_sinks.py

# 3. 关键词通道的回归（从 vuln-features.md 直接解析正则，防文档与代码漂移）
python assets/stress/stress_kwcheck.py
```

扫描器输出长这样（合成语料，示例）：

```
- 已扫描 .go 文件: 3
- 候选命中: 12（函数内出现输入源 4 / 仅命中 sink 8）
- 分相统计: E1=4 / E2=2 / E4=1 / E5=2 / X=3

| # | 相 | 规则 | 位置 | 函数 | 输入源 | 判断依据 |
|---|----|------|------|------|--------|----------|
| 1 | E1 | E1-SHELL-C | pos_rce.go:40 | renderUserTpl | http form | shell 收到 -c 脚本串，分隔符由 shell 解析 |
```

**扫描器只产出候选。** 后续的可达性追踪、数据形态判定、证据分级由 agent 按 `SKILL.md`
的 Phase 0-6 执行——这是本项目的设计前提，不是缺陷。

## 用它做一次审计

在 agent 里说"对这个 Go 项目做安全审计"，或直接触发关键词（Go 代码审计 / RCE / 命令注入 /
SQL 注入 / SSTI / SSRF / 越权 / CVE 复现校验）。工作流：

| Phase | 做什么 | 关键约束 |
|---|---|---|
| 0 范围与授权 | 记录 commit SHA、Go 版本、入口面、**部署用户** | 没有部署用户就说不清影响 |
| 1 面貌测绘 | APP/L/EP/CMD 编号 + 信任边界表 | 默认端口不等于在监听 |
| 2 候选生成 | 扫描器 + 关键词 + 固定 rg 三连 | 规则只是线索，不是清单 |
| 3 可达性 | **反向**从 sink 追调用方，到 handler 边界停 | Go 通常 2-5 跳，8 跳大概率误报 |
| 4 裁决 | 写 payload 在每个变换点存活的理由 | 任一被过滤即证伪，直说 |
| 5 证据门 | L0→L3，逐级要证据 | 无证据就 `HOLD-evidence`，不是"疑似高危" |
| 6 报告 | 8 节契约 + 覆盖矩阵 + 计数加总 | 交付前 10 项检查 |

执行默认**只读**：不 build / 不 run / 不发请求 / 不改文件。动态验证必须声明授权来源。
详见 [references/execution-policy.md](references/execution-policy.md)。

## 目录

```
SKILL.md                       主文件：不可协商项 / 13 维度 × 工具对照 / Phase 0-6 / 输出契约
references/
  six-paths.md                 六相 RCE 模型（E1-E6 + X）+ 伪 CVE 识别
  sink-catalog.md              27 条规则的匹配/真阳性/噪声/判据
  vuln-features.md             13 类漏洞的关键词特征库（唤醒 / 噪声 / 证伪 / 深读指针）
  verification-gates.md        L0-L3 证据门
  report-template.md           报告契约：8 节骨架 + 五档裁决 + 10 项检查
  case-library.md              历史 RCE 案例（分 L3-repro / L3-lit / 伪样本 / 待核验）
  application-surface.md       面貌测绘
  authorization.md             认证与越权
  sql-injection.md  ssrf.md  template-injection.md  command-execution.md
  unsafe-memory.md  file-transfers.md  capability-assessment.md  framework-signals.md
  reachability.md  route-map.md  rag-index.md  execution-policy.md  acceptance-cases.md
scripts/
  scan_sinks.py                候选扫描器（27 规则，stdlib）
  test_scan_sinks.py           24 条断言，含变异测试
  kb_retrieve.py               references 的两通道检索（BM25 + 指纹）
assets/
  selftest/                    16 个规则样本（7 正 / 9 负）
  stress/                      植入语料：13 个正点 + 7 个反例 + 关键词回归器
prompts/architect-intake.md    agent 角色与 worked examples
```

## 实测数据（可复现）

| 项目 | 结果 | 复现命令 |
|---|---|---|
| 规则断言 | **24/24 通过，0 失败**（7 正 + 9 负 + 7 变异 + 1 空文件） | `python scripts/test_scan_sinks.py` |
| 植入点捕获 | **13/13**（扫描器 8 + 关键词通道 5，互补） | `python scripts/scan_sinks.py assets/stress` |
| 负样本误报 | **0**（7 个反例：argv 分传、常量脚本、embed 模板、time.Parse、os.OpenRoot、值绑定、env 取 key） | 同上，`neg_safe.go` 零命中 |
| 关键词通道 | 29 条正则，5/5 类命中植入正样本 | `python assets/stress/stress_kwcheck.py` |

变异测试的意思是：把规则的锚点抠掉，对应样本必须**不再**命中。否则说明断言是永真的、
测不出东西——这类伪测试在安全规则库里很常见。

## 局限（请先读这段再用）

1. **机械规则只覆盖 RCE 类（E/X 相）。** SQLi / SSRF / 越权 / 凭据 / 内存 / 归档靠关键词通道
   唤醒 + 人工链路追踪，没有规则兜底。关键词未命中**不等于**安全。
2. **召回率只在合成语料上验证过**（13/13）。真实项目的召回率未知，不要用"跑完没报"当结论。
3. **真实项目只抽样过 1 个**（Woodpecker CI：57 条候选 → 0 条确证）。这个样本证明的是
   "干净项目不会被刷成一屏高危"，不构成召回率证据。
4. **需要 agent 驱动。** 脚本只给候选清单；判决由 LLM 按 SKILL.md 的流程做。想要一条命令
   出 SARIF 的，请用 gosec/semgrep。
5. **关键词通道依赖 ripgrep**（`rg`）。不在 PATH 时需自备；回归器用 Python `re`，不受影响。
6. **报告会回显输入的绝对路径**，贴到公开 issue 前自行处理。
7. **不替代人工。** 它压缩的是"从候选到判决"的时间，不是判断力。

## 贡献

最有价值的贡献是**反例**：一个被误报的形态、一条永真的断言、一个规则覆盖不到的真漏洞。
提 PR 前请确认 `test_scan_sinks.py` 与 `stress_kwcheck.py` 都通过——改规则不改测试的 PR
不会被合并，这是本项目唯一硬性要求。

## License

MIT，见 [LICENSE](LICENSE)。

> **权属说明**：本项目的部分方法论文件源自内部审计实践，公开发布前需由作者确认授权范围。
> 若你是权利人或知悉权属争议，请先联系维护者；在权属确认前，请勿用于商业分发。

## 免责

仅用于**已获授权**的代码审计与安全研究。对第三方系统执行任何验证动作前，必须先取得书面授权。

## Related Projects

`go-sec-audit` is a domain skill in the `aiqianqian521` agent-skill family. The sibling
repositories supply the execution discipline, the report structure and the orchestration that
drive it; this one supplies the Go security verdict.

| Repository | What it is | Relation to `go-sec-audit` |
| --- | --- | --- |
| [aiqianqian521/github-project-evaluation](https://github.com/aiqianqian521/github-project-evaluation) | Cross-source project discovery, frozen-repo static first pass, per-project test design | Its first pass can call this skill as the Go security dimension |
| [aiqianqian521/ai-skill-output-template](https://github.com/aiqianqian521/ai-skill-output-template) | Declarative output-template registry | Same contract idea: stable, verifiable, regression-checked report structure |
| [aiqianqian521/ooda_skill](https://github.com/aiqianqian521/ooda_skill) | OODA execution discipline (purpose, evidence, verify, close) | The round loop that drives an audit; verdicts feed its per-round records |
| [aiqianqian521/sloth-loop](https://github.com/aiqianqian521/sloth-loop) | Zero-LLM task orchestration engine | Orchestrates repeated audits; this skill is one domain capability inside a run |

> Sibling skill kept local for now: `go-rce-hunt` (remote code execution hunting in Go source trees).
