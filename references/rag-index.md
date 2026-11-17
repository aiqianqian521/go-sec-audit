# Retrieval Index (rag-index)

**Do not read all of references/**. The corpus is 24 files (measured 2026-11-17: 3,058 lines total,
plus SKILL.md at 217 lines; counts drift as the library is maintained — re-measure when citing, never hard-code them elsewhere).
Reading everything blows the context; reading nothing is the same as not having it.
Use `scripts/kb_retrieve.py`'s two channels and keep one audit within 3-4k tokens of reference material.

```bash
python scripts/kb_retrieve.py --project <path>            # fingerprint wake-up + on-demand retrieval
python scripts/kb_retrieve.py --q "auth 401 decorative return"   # direct keyword query
python scripts/kb_retrieve.py --hits E1-SHELL-C,X-PATHTRAV-JOIN
python scripts/kb_retrieve.py --list                       # all chunks
```

## Channels

- **A Fingerprint wake-up (deterministic)**: project directory -> detect framework/deployment shape/hit sinks ->
  FINGERPRINTS maps hard to required chunks, pinned to the top and unscored
- **B Keyword retrieval (BM25)**: heading hits are weighted; English is tokenized by word and CJK by 2-gram,
  so both "path traversal" and the Chinese equivalent can be recalled

Output is `file:start-end`, fed straight into Read's offset/limit.

## Corpus Layers and Loading Budget

| Layer | Files | When to read |
|---|---|---|
| Process | SKILL.md (the main file) | at the start |
| Skeleton | execution-policy / application-surface / framework-signals / route-map / report-template | Phase 0 / 1 / 6, per stage |
| Verdict material | vuln-features / six-paths / sink-catalog / case-library / reachability / verification-gates | when the corresponding class hits |
| Per-dimension methodology | authorization / capability-assessment / command-execution / sql-injection / ssrf / template-injection / file-transfers / unsafe-memory | **only when that dimension reaches a verdict**, never preloaded |
| Historical leads (optional) | execution-reference-notes / sql-reference-notes / io-template-reference-notes | after independent discovery |
| Evaluation scenarios | acceptance-cases | behavioral checks during development |

## Typical Fingerprint -> First Reads

- HTTP service (gin/echo/chi/...) -> application-surface + framework-signals + route-map
- `exec.*` hit -> six-paths §E1 + sink-catalog E1 section
- SQL/ORM import -> vuln-features SQLi section + sql-injection.md
- webhook/outbound request -> vuln-features SSRF section + ssrf.md
- k8s/client-go -> capability-assessment + authorization
- About to write a report -> report-template (before Phase 6)
