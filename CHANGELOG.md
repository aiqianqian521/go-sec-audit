# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [0.1.0] - 2026-11-17

首个公开版本。合并两条独立审计谱系：8 维方法论（面貌测绘 / 认证授权 / 注入面 / 能力评估 /
只读执行策略 / 报告契约）与 RCE 狩猎模型（六相模型 / sink 规则 / 可达性 / 证据门 / 案例库）。

### Added

- **主文件** `SKILL.md`：Phase 0-6 工作流、13 维度 × 工具对照表、不可协商项、输出契约摘要
- **扫描器** `scripts/scan_sinks.py`：27 条 sink 规则，覆盖 E1 命令拼接 / E2 模板注入 /
  E3 反序列化 / E4 写入即执行 / E5 参数注入 / E6 动态加载 / X 路径穿越；
  输出 Markdown + JSON，支持 `--min-severity` / `--include-vendor` / `--include-tests`
- **关键词特征库** `references/vuln-features.md`：13 类漏洞，每类给唤醒正则、真阳性形态、
  噪声形态、证伪判据、深读指针——补齐 SQLi / SSRF / 越权 / 凭据 / 内存 / 归档六类无机械规则的空档
- **报告契约** `references/report-template.md`：8 节骨架 + 四态覆盖矩阵（in-scope assessed /
  not-assessed / out-of-scope / off）+ 五档裁决计数 + 计数加总校验 + 交付前 10 项检查
- **变异自测** `scripts/test_scan_sinks.py`：24 条断言（7 正 + 9 负 + 7 变异 + 1 空文件），
  变异测试要求"抠掉规则锚点后样本必须不再命中"，防止永真断言
- **对抗语料** `assets/stress/`：13 个植入正点 + 7 个近似反例 + `stress_kwcheck.py`
  （从 `vuln-features.md` 直接解析正则做回归，单一事实来源防文档漂移）
- **检索层** `scripts/kb_retrieve.py`：references 的两通道检索（BM25 + 指纹映射），
  200 chunk 全量可查，审计时按需取 3-4k token
- **只读护栏** `references/execution-policy.md`：默认不 build / run / test / 生成 PoC / 发请求；
  依赖获取是唯一窄例外（隔离缓存 + 锁定版本 + `GOTOOLCHAIN=local`）
- **案例库** `references/case-library.md`：证据分 `L3-repro` / `L3-lit` / `L2`，
  附伪 CVE 识别表与"待核验（勿引用）"分区
- **CI**：GitHub Actions 三平台 × 两 Python 版本跑断言、关键词回归、负样本零误报

### Fixed

压力测试两轮共 13 项发现，修复 12 项（1 项记为已知限制）：

- **AUTHZ 关键词叫不醒"401 装饰化"**（写了响应但缺 `return`，函数继续执行）——补
  `http.Error(...40[13])` / `AbortWithStatus` 唤醒词与控制流判据
- **`E2-FUNCMAP-EXEC` 锚不到独立 `var` 定义的 FuncMap**（真实代码常把 FuncMap 定义与
  `.Funcs()` 调用分开）——新增第 27 条规则 `E2-FUNCMAP-DEF`，配正负样本与变异断言
- **SSRF 关键词裸 `import` 命中一切 Go 文件的 import 行**——改为形态词
- **扫描器报告标题残留旧标识**——清理
- `E1-SHELL-C` 的噪声描述与实现不一致（实现已有 `none_of` 常量过滤，文档仍写"会误报"）
- `ZIPSLIP` 参数传入形态漏检（由 `X-PATHTRAV-JOIN` 兜底，已在规则表注明）
- `vuln-features.md` 关键词计数漂移（27 → 29）、类数声明（13 → 14）、规则数声明（26 → 27）
- `scan_sinks.py --help` 描述与新定位不一致

### Verified

- 24/24 断言通过；植入点 13/13 捕获（扫描器 8 + 关键词 5，通道互补）
- 7 个负样本扫描器命中 **0** 次
- 报告契约判别力：回放一份真实审计报告，10 项检查拦住 2 项——拦住的恰好是已知缺陷
- 可移植性：纯 stdlib、无硬编码路径、任意 cwd 可运行、无 BOM / CRLF

### Known limitations

- 机械规则只覆盖 E/X 相；SQLi / SSRF / 越权 / 凭据无规则兜底
- 真实项目抽样仅 1 个（Woodpecker CI：57 候选 → 0 确证），不构成召回率证据
- 报告契约第 2 项（行号回读）只能验证"方法声明"，无法验证引用正确性
- 关键词通道依赖 `rg` 在 PATH 中
