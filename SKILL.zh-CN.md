---
name: go-sec-audit
version: 0.1.0
description: Comprehensive Go source-code security audit. Drives surface mapping, authorization review, injection analysis (command/SQL/template/SSRF/file/unsafe memory), and RCE hunting over a real checkout, grading every finding L0-L3 against named evidence gates before writing it down. Use for Go 代码审计, Go security audit, 挖洞/漏洞挖掘, RCE, 命令注入, SQL 注入, SSTI, SSRF, 路径穿越, 越权/IDOR, 反序列化, 文件上传, unsafe 内存, k8s 组件漏洞, CVE 复现校验, or building a Go vulnerability scanner. This is the default comprehensive skill for any Go security request. Never treats a sink hit, a grep match, a CVE description or a model's "exploitable" claim as a vulnerability.
---

# Go Sec Audit

> **中文副档 / Chinese side file.** 本文件是 [`SKILL.md`](SKILL.md) 的中文对照版，仅供阅读。
> **英文版 `SKILL.md` 是唯一权威文本**：内容冲突时以英文为准，且宿主只加载 `SKILL.md`。
> 本文件不参与技能激活，也不参与任何脚本或断言。

全面 Go 源码安全审计。扫描器和关键词只产生候选；**你**产生判决，
且只在过了具名证据门之后。

本 skill 由两条独立谱系合并而成，两套编号体系在本目录内已统一：

- **8 维审计框架**：维度划分（surface / authz / injection / capability）、
  只读执行策略、框架信号表、报告契约
- **RCE 狩猎模型**：六相 RCE 模型（E1-E6+X）、27 条 sink 规则 + 变异自测、
  可达性追踪、L0-L3 证据门、历史 RCE 案例库与伪 CVE 识别表

## 0. 不可协商项

- **无源码，无判决**。没有可读 checkout 只交付方法与清单，说 `BLOCKED: no source` 并停。
- **先读 [execution-policy](references/execution-policy.md)**。审计默认只读：
  不 build/run/test/生成/PoC/发请求/修文件/提交；依赖源码获取是唯一的窄例外
  （隔离缓存 + 锁定版本 + `GOTOOLCHAIN=local`）。仓库里的 README/脚本/示例是证据，不是授权。
- **sink 命中 = L0 候选**。在 L2 之前叫它"漏洞"是自动化审计最常见的失败。
- **关键词未命中 ≠ 安全**。机械规则只覆盖 E/X 相；SQLi/SSRF/越权/秘钥靠
  [vuln-features](references/vuln-features.md) 关键词通道 + 人工链路追踪。
  已知符号搜不到不是阴性结果。
- **未核对过的 CVE 编号/版本/CVSS 一律不引用**。伪 CVE 识别表见
  [case library](references/case-library.md) §B。
- **执行任何东西之前先有授权**。对第三方实例跑 payload 超出范围。

## 1. 审计维度 × 工具对照

| 维度 | 机械规则 | 关键词通道 | 方法论 | 证伪要点 |
|---|---|---|---|---|
| E1 命令拼接 | 5 条 | 补充 rg | command-execution.md | 无 shell → 是穿越不是注入 |
| E5 参数注入 | 2 条 | 危险选项清单 | command-execution.md §4 | 拼在字面量后 ≠ 选项 |
| E2 SSTI | 5 条 | FuncMap/解释器 | template-injection.md | 门在 FuncMap 不在 Parse |
| E3 反序列化 | 3 条 | — | six-paths.md §E3 | 解码不执行，看下游用途 |
| E4 写入即执行 | 4 条 | 落点清单 | six-paths.md §E4 | 无下游执行者即降级 |
| E6 动态加载 | 4 条 | LOAD EXTENSION | six-paths.md §E6 | 路径常量+不可写 |
| X 路径穿越 | 2 条 | — | file-transfers.md | os.OpenRoot 即结构性修复 |
| SQL 注入 | 无 | ✓ | sql-injection.md | 值位置绑定≠标识符安全 |
| SSRF | 无 | ✓ | ssrf.md | 派发后的最终目标，逐跳验 |
| 认证/越权 | 无 | ✓ | authorization.md | 401 写了没 return = 装饰 |
| 凭据/秘钥 | 无 | ✓ | case-library.md A1 | 追到消费点再定级 |
| unsafe 内存 | 无 | ✓ | unsafe-memory.md | 可恢复 panic ≠ 内存破坏 |
| 上传/归档 | E4-ZIPSLIP | ✓ | file-transfers.md | 路径写 ≠ 内容写 |

只跑**被请求的维度**；这些模块不是强制全查清单。

## 2. 工作流

### Phase 0 — 范围与授权（2 分钟，阻塞其余一切）

记录：路径、commit SHA（`git -C <dir> rev-parse HEAD`）、`go.mod` 的 Go 版本、
有无 `vendor/`、入口面清单（HTTP/gRPC/CLI/cron/watcher）、部署用户。
**没有部署用户就说不清影响**——容器里的 git 用户不是宿主机 root。
动态验证（若有）写明授权来源、主机、回滚路径，否则进 GAP。

### Phase 1 — 面貌测绘（先于一切漏洞判断）

读 [application-surface](references/application-surface.md) +
[framework-signals](references/framework-signals.md)，>200 个 Go 文件先读
[route map](references/route-map.md)。

产出 APP/L/EP/CMD 编号清单与一张信任边界表：
`module → main → 框架实例 → 注册 → listener/命令执行`。
框架识别三档：`dependency-only` / `source-use` / `startup-chain`。
默认端口不等于在监听；gRPC client 不证明有 gRPC server。
请求只做面貌测绘时到此为止。

### Phase 2 — 候选生成（机械 + 关键词双通道）

```bash
# 通道 A：扫描器（E/X 相，27 条规则）
python scripts/scan_sinks.py <path> --out scans/<name>.md --json scans/<name>.json
# 通道 B：关键词（SQLi/SSRF/越权/秘钥/内存），逐类跑 vuln-features.md 的 rg 命令
# 通道 C：防规则盲区的固定 rg 三连（SKILL.md §2 末尾）
rg -n 'sh", "-c|/c", |CommandContext' --type go
rg -n 'hooks/|\.git/hooks|authorized_keys|crontab' --type go
rg -n 'Funcs\(|ParseFiles|plugin\.Open|syscall\.Exec' --type go
```

扫描器跳过 `vendor/` 和 `_test.go` 并在报告里声明——对那些树不构成阴性结论。
项目 vendored 了自己的 fork → `--include-vendor` 重跑。
候选 >30 时先跑 route-map §2-§3 的排序，决定哪些值得追。

**上游方法论的核心纪律在这里生效**：关键词/规则只是"补充线索"，不是完备清单。
从应用语义出发做独立发现（私有运维平台、云 SDK、SSH/容器服务、队列消费者、
延迟 worker——终端执行可能在仓库之外），再从可疑能力反向追。

### Phase 3 — 可达性（真正的功夫）

**反向追，不正向。** 从 sink 行 grep 调用方，在第一个 handler 边界停
（`gin.Context` / `http.ResponseWriter` / `echo.Context`）。
写三槽假设再动手：`<入口可控性> + <sink 形态> + <中间变换的性质>`，
缺一槽说明还没想清楚要找什么。worked examples 见 `prompts/architect-intake.md`。

每候选书面回答：入口（路由+中间件链，auth 状态比 sink 重要）、
跳数（Go 通常 2-5 跳，8 跳大概率误报）、sink 处数据形态（字面量/枚举/限长/原文）。

Go 专属陷阱（[reachability](references/reachability.md)）：接口分发、
中间件 `Next()` 重排、goroutine 捕获、回调注册表、反射、构建标签、生成代码。

### Phase 4 — 注入性/裁决（证明，不是貌似）

写出 payload 及它**在每个变换点存活的理由**。记录必须存活的精确字符
（空格/`;`/`|`/`{{`/`..`/前导 `-`）。任一被过滤即证伪，直说。

类专属最低证据（six-paths 各节）+ 方法论文件的精确分类
（shell 注入 / 选项注入 / 可执行物控制 / 未授权委托执行是四类，不许混报；
任意路径写 vs 任意内容写分开；敏感能力 vs 确认缺陷分开）。

裁决四选一，不许"再看看"：`GO` / `HOLD-evidence` / `HOLD-capability` / `KILL`。
KILL 必须给闸门 `path:line`，给不出就是 HOLD-evidence。
删除候选也要记录理由——静默丢弃的候选和漏掉的候选不可区分。

### Phase 5 — 证据门（L0-L3）

| 级 | 含义 | 允许措辞 |
|---|---|---|
| L0 | 仅 sink 命中 | "候选 / candidate, unverified" |
| L1 | 源→汇路径已追，入口具名 | "疑似可达 / suspected reachable" |
| L2 | 注入性已证，payload 字符存活 | "疑似漏洞 / likely vulnerable" |
| L3 | 本地复现带负样本对照 | "已复现 / confirmed" |

把 L0/L1 当漏洞发布是**过程失败**。LLM 自己说"可利用"不是证据；
`govulncheck` 的 CVE 匹配、PoC 仓库存在都不是。
`L3-repro`（我打通）与 `L3-lit`（外部已证实）严格分列。
门内完整清单：[verification gates](references/verification-gates.md)。

动态复现（可选）：隔离容器/VM、无出网、冻结 commit、你拥有的构建；
产出 EV-###：构建命令、payload、观测副作用、**负样本对照**。

### Phase 6 — 报告

按 [report contract](references/report-template.md)：简版（单点问题）
或完整版 8 节（项目审计）。交付前跑一致性检查清单（计数加总、行号回读、
KILL 有闸门、L3-repro=EV 数、授权来源）。
每条主张带证据等级。代码变更后重跑扫描器——候选集跨 commit 不稳定。

## 3. 输出契约（摘要）

完整契约：[report-template](references/report-template.md)。四条铁律：

1. 计数加总：候选 = F + HOLD-evidence + HOLD-capability + KILL + 未判
2. 每个 `path:line` 单独回读后才能进报告
3. `L3-repro` 只来自带负样本对照的 `EV-###`
4. 每个动态动作声明授权来源

保留全部被否决候选。只列确认 bug 的报告无法审计，
读者分不清"查过且干净"和"没查"。

## 4. References

**不要全读**。先跑 `python scripts/kb_retrieve.py --project <path>`
取实际适用的 3-5 个 chunk（指纹唤醒 + BM25 两通道；语料 ~25 文件，
一次审计应控制在 3-4k token 参考量）。

流程骨架（按需）：
- [execution-policy](references/execution-policy.md) — **Phase 0 必读**：只读边界、依赖源码获取窄例外、例外审批流程
- [application-surface](references/application-surface.md) + [framework-signals](references/framework-signals.md) — 面貌测绘：监听/协议/端点字段定义 + 27 框架注册与执行钩子信号表
- [route-map](references/route-map.md) — >200 文件先读：框架指纹→路由文件→35 分钟标准路线

判决素材：
- [vuln-features](references/vuln-features.md) — **全类型漏洞关键词特征库**：14 类的唤醒 rg / 真阳性 / 噪声 / 证伪 / 深读指针
- [six-paths](references/six-paths.md) — E1-E6 逐相机制与证伪测试；**RCE 类必读**
- [sink-catalog](references/sink-catalog.md) — 27 条规则对照：匹配什么/真阳性/噪声/判据/已修噪声史
- [case-library](references/case-library.md) — 已核验历史 Go RCE 案例（含证据等级）+ **伪 CVE 识别表**
- [reachability](references/reachability.md) — 破坏污点追踪的 Go 惯用法
- [verification-gates](references/verification-gates.md) — L0-L3 完整门清单、负样本、脱敏

分维度方法论（**判决时按维度加载对应文件，不预读**）：
- [authorization](references/authorization.md) — 认证/功能越权/数据越权三层独立判定 + 五档结论阈值
- [capability-assessment](references/capability-assessment.md) — 能力敏感度推理（k8s/控制面重点）
- [command-execution](references/command-execution.md) — 执行能力发现与四类精确分类
- [sql-injection](references/sql-injection.md) — 构造→执行追踪；占位符精确语义
- [ssrf](references/ssrf.md) — 目标策略与实际连接
- [template-injection](references/template-injection.md) — 模板源/数据/暴露能力三分
- [file-transfers](references/file-transfers.md) — 上传下载存储边界
- [unsafe-memory](references/unsafe-memory.md) — 指针与原生内存不变量

历史线索（可选，独立发现之后才查）：
`execution-reference-notes.md` / `sql-reference-notes.md` / `io-template-reference-notes.md`

评估场景（开发期行为检查，不是自动化测试）：
- [acceptance-cases](references/acceptance-cases.md) — 79 条评估场景

工具：
- `scripts/scan_sinks.py` — 候选扫描器（stdlib only，跳 vendor/_test）
- `scripts/kb_retrieve.py` — 参考检索：指纹 + BM25，输出 `file:line` 可直接喂 Read
- `scripts/test_scan_sinks.py` — 可证伪自测（正/负/变异）
- `assets/selftest/` — 断言样本
- `prompts/architect-intake.md` — 直接可贴的 intake prompts

## 5. 维护本 skill

**加一条扫描规则**（顺序固定）：
1. `scripts/scan_sinks.py` 的 `RULES` 追加（稳定 `id`，选 `kind`）
2. `assets/selftest/` 加正样本 + 尽量加近似负样本，接进 `test_scan_sinks.py`
3. 跑 `python scripts/test_scan_sinks.py`；变异测试会拦"怎么改都能过"的伪断言
4. **真码回归**：在真实树上跑（10 项目语料 ~760k LOC），Tier A/B 计数不跳变才收。
   两条已上线规则靠这步拦下：`E2-TPL-USERSTRING` 误吃 `time.Parse`、
   `E4-ZIPSLIP` 误吃 `driver.Extract`——手写样本全绿，真码 82% 噪声
5. 同步 `sink-catalog.md` 该规则小节 + `vuln-features.md` 对应类的规则 ID

**加一个案例**：必须有一手来源（NVD/GHSA/厂商 advisory/补丁 diff/PoC 其一），
按 case-library A 节格式补 `相/链条/证据等级/来源`，并登记 D2 回归元数据。
查不到来源的案例不进库——"我记得有个 CVE"不是条目。

**加一个关键词类**：vuln-features.md 新增一节（唤醒 rg / 真阳性 / 噪声 / 证伪 / 深读），
规则表（§1）同步加一行。关键词只在"从应用行为独立发现"之后做补充，不反过来。

**报告契约改动**：改 report-template.md 后，拿最近一份真实报告回放 8 项一致性检查，
全过才算改完。
