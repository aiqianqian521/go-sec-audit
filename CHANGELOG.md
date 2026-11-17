# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and its version
numbers follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **The whole repository is now English.** Every reference document, root document, prompt, script
  string and test-sample comment was rewritten in English, following the bilingual layout used by
  `ooda_skill`: English is the single authoritative text, with Chinese kept as side files
  (`SKILL.zh-CN.md`, `README.zh-CN.md`) rather than mixed into the same file.
  The 15 Chinese trigger phrases in the `description` frontmatter field are deliberately preserved:
  they are the activation surface for Chinese-speaking users, and narrowing them would silently
  reduce recall on real requests.
- `scripts/kb_retrieve.py`: the fingerprint labels, the BM25 fallback query (`<framework> gate
  falsify`) and every printed string are English. The Chinese 2-gram tokenizer is retained, so a
  Chinese-language query still tokenizes; since the corpus is now English, English queries retrieve best.
- `scripts/scan_sinks.py`: the rule `why` fields and the whole Markdown report (headers, table
  columns, empty-result wording) are English. Rule IDs, regexes and matching semantics are unchanged.

### Verified (after the English migration)

- `scripts/test_scan_sinks.py`: 24/24 assertions still pass, including all 7 mutation assertions.
- `assets/stress` scan: still 12 candidates (4 with a same-function source), per-phase counts
  unchanged at `E1=4 / E2=2 / E4=1 / E5=2 / X=3`.
- `stress_kwcheck.py`: still parses 29 regexes and still reports 16 matching lines.
- `kb_retrieve.py --list`: still 200 chunks / 24,921 tokens; the `--project` fingerprint channel still
  pins 2 chunks (`1. Framework Fingerprint`, `2. Entry Shapes`) — proving the English headings in
  `route-map.md` and the `FINGERPRINTS` table did not drift apart.
- `SKILL.md`: 29 internal links, 0 broken.

## [0.1.0] - 2026-11-17

First public release. Merges two independent audit lineages: the 8-dimension methodology (surface
mapping / authentication and authorization / injection surface / capability assessment / read-only
execution policy / report contract) and the RCE hunting model (six-phase model / sink rules /
reachability / evidence gates / case library).

### Added

- **Main file** `SKILL.md`: Phase 0-6 workflow, 13-dimension × tooling table, non-negotiables, output contract summary
- **Scanner** `scripts/scan_sinks.py`: 27 sink rules covering E1 command concatenation / E2 template
  injection / E3 deserialization / E4 write-then-execute / E5 argument injection / E6 dynamic loading /
  X path traversal; emits Markdown + JSON, supports `--min-severity` / `--include-vendor` / `--include-tests`
- **Keyword feature library** `references/vuln-features.md`: 14 vulnerability classes, each with wake-up
  regexes, true-positive shapes, noise shapes, falsification criteria and deep-read pointers — closing the
  gap for SQLi / SSRF / authorization / credentials / memory / archive, which have no mechanical rules
- **Report contract** `references/report-template.md`: 8-section skeleton + four-state coverage matrix
  (in-scope assessed / not-assessed / out-of-scope / off) + five-verdict counts + count reconciliation +
  10 pre-delivery checks
- **Mutation self-test** `scripts/test_scan_sinks.py`: 24 assertions (7 positive + 9 negative + 7
  mutation + 1 empty file); mutation testing requires that "removing the rule anchor makes the sample
  stop matching", which rules out vacuous assertions
- **Adversarial corpus** `assets/stress/`: 13 planted positive points + 7 near-miss counter-examples +
  `stress_kwcheck.py` (parses regexes straight out of `vuln-features.md` for regression, a single source
  of truth that prevents documentation drift)
- **Retrieval layer** `scripts/kb_retrieve.py`: two-channel reference retrieval (BM25 + fingerprint
  mapping), 200 chunks all queryable, pulling 3-4k tokens on demand during an audit
- **Read-only guardrail** `references/execution-policy.md`: by default no build / run / test / PoC
  generation / request sending; dependency fetching is the single narrow exception (isolated cache +
  pinned versions + `GOTOOLCHAIN=local`)
- **Case library** `references/case-library.md`: evidence split into `L3-repro` / `L3-lit` / `L2`, with a
  fake-CVE identification table and an "unverified (do not cite)" partition
- **CI**: GitHub Actions, three platforms × two Python versions, running the assertions, the keyword
  regression and the zero-false-positive negative samples

### Fixed

Two rounds of stress testing produced 13 findings; 12 were fixed (1 recorded as a known limitation):

- **The AUTHZ keyword could not wake on "decorative 401"** (response written but the `return` is missing,
  so the function continues) — added `http.Error(...40[13])` / `AbortWithStatus` wake-up terms and a
  control-flow criterion
- **`E2-FUNCMAP-EXEC` could not anchor a FuncMap defined as a standalone `var`** (real code often separates
  the FuncMap definition from the `.Funcs()` call) — added the 27th rule `E2-FUNCMAP-DEF`, with positive
  and negative samples and a mutation assertion
- **The SSRF keyword matched the bare `import` line of every Go file** — changed to shape words
- **The scanner report title carried a stale identifier** — cleaned up
- The noise description of `E1-SHELL-C` contradicted the implementation (the code already had a `none_of`
  constant filter while the docs still said "will false-positive")
- The pass-through parameter shape of `ZIPSLIP` was missed (covered by `X-PATHTRAV-JOIN`, now noted in the
  rule table)
- Count drift in `vuln-features.md`: keyword count (27 → 29), class count (13 → 14), rule count (26 → 27)
- The `scan_sinks.py --help` description no longer matched the skill's positioning

### Verified

- 24/24 assertions pass; 13/13 planted points captured (8 by the scanner + 5 by keywords, complementary channels)
- The 7 negative samples produce **0** scanner hits
- Report-contract discriminating power: replaying a real audit report, 10 checks caught 2 issues — and the
  2 caught were exactly the known defects
- Portability: pure stdlib, no hardcoded paths, runs from any cwd, no BOM / CRLF

### Known limitations

- Mechanical rules cover only the E/X phases; SQLi / SSRF / authorization / credentials have no rule backstop
- Only one real project sampled (Woodpecker CI: 57 candidates → 0 confirmed); not evidence of recall
- Report-contract check 2 (line-number re-read) can only verify "the method was declared", not that a
  citation is correct
- The keyword channel depends on `rg` being on PATH
