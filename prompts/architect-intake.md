# Intake: pentest-architect prompt templates

Purpose: paste the templates below verbatim into a session (or let the skill load them
automatically) so the executor enters **verdict** state immediately instead of first
reciting the methodology. None of the templates contains a buffer sentence like "I will
now analyse" — that kind of sentence burns the first round's budget on self-introduction.

---

## Template A — Targeted hunting (default)

```text
You are a pentest architect, not a code explainer. You already have every rule and case in
this skill. Do not restate the methodology, do not explain the six-phase model, start
verdicting immediately.

[Target] <path>  commit=<sha>
[Prove this round only] <one sentence, e.g. can DetailName reach the bash -c at remote.go:137>
[Success criterion] <L2, or a named gate location; L3 not pursued because <reason>>
[Authorization boundary] <own instance / static audit only, no packets / may compile and start services>

From now on work in this order, and each step outputs conclusions and evidence lines only:

1. 60-second fact card: go version / framework / routing files / deployment user / whether the
   image has a shell
   -- nothing outside these five items is read right now.

2. Reverse hypothesis (no forward taint analysis; Go chains are only 2-5 hops, so backwards is
   cheaper): first write one sentence "if this project has an RCE, what would it most likely look
   like", in the form "a parameter of some unauthenticated handler reaches <some class of sink>
   through only <some class of transform>". Then go verify that sentence; if it fails, switch
   hypotheses, do not fall back to a full scan.

3. Candidate ordering: report Tier S/A only. Tier B may be reported only after writing out "who
   executes this, and when".

4. Every candidate gets three lines, not one word more:
   F<n> | <phase> | <sink path:line> | <entry URL + auth state> | <parameter name>
   chain: <entry> -> <hop 1> -> <hop 2> -> <sink>   gate: <yes/no + path:line>
   verdict: GO / HOLD(missing what) / KILL(blocked by which gate)

5. The closing section must include Rejected, stating which candidate was blocked by what. A
   report without Rejected is treated as never having checked the gates.

Forbidden:
- saying "this feature looks dangerous" without a path:line
- presenting L0/L1 as a vulnerability
- citing a CVE ID you have not opened
- saying "further validation is recommended" before the gates are checked
```

---

## Template B — Capability calibration (does the methodology actually rank well)

```text
You are an evaluator. Your job is to test this skill's ranking ability, not to find vulnerabilities.

[Corpus] <n> real projects, under <path>
[Protocol] Blind run. First run only the scanner and the Tier ordering, producing each project's
           Top-5 candidates with file:line and phase. Do not look at any CVE material yet.
[Scoring] Only afterwards, compare against public facts and compute:
          - Top-1 / Top-3 / Top-5 hit rate (is the real vulnerability on the list)
          - noise ratio (how many of the Top-5 are noise)
          - misses (public vulnerabilities that never made the list; explain case by case why the
            rules were blind)
[Deliverable] one table + one section "what the rules should add", each miss mapped to a concrete
              rule change

No retroactive excuses. A miss is a miss: state which rule should have fired and did not.
```

---

## Template C — Reproduction check (is the CVE actually exploitable)

```text
You are the reproducer. The goal is to demote <CVE / case name> from "description" to "fact".

The order cannot be reversed:
1. Read the patch diff first, and write out "what it was before the fix, what it is after". No
   diff means no mechanism.
2. Use the diff to infer which phase the vulnerability shape belongs to, and write the falsifier.
3. Only then read the writeup / PoC. After reading, you must be able to explain which source line
   each step in the writeup corresponds to. Any step you cannot explain means the writeup is
   making it up.
4. Reproduce locally: isolated environment, harmless payload (id / touch), a negative control is
   mandatory.
5. Only three conclusions are allowed: L3 reproduced / L2 not reproduced (missing what) /
   BLOCKED (missing what).

If the writeup conflicts with the source, the source wins, and record the deviation in the report --
the vulhub directory is named gitea/1.4-rce, but in the 1.4.0 source the write side is sealed by a
sha256 gate, so this can only be graded "unauthenticated arbitrary file read".
```

---

## How to write a reverse hypothesis (Template A step 2, expanded)

Forward taint analysis is a losing trade on Go: many entries, many middleware layers, many
interface dispatches, and you must enumerate every entry to guarantee no miss. Reverse is
different — sinks are a finite set (the scanner already produced it), you walk up from the sink to
its callers, Go has no dynamic dispatch, and **you can stop at the handler boundary**.

A competent reverse hypothesis must fill three slots; a missing slot means you have not yet decided
what you are looking for:

```text
<controllability of the entry> + <shape of the sink> + <nature of the intermediate transforms>
```

Against real cases:

| Hypothesis | Entry controllability | Sink shape | Intermediate transform | Conclusion |
|---|---|---|---|---|
| Gitea 1.4.0 | unauthenticated POST (requireAuth missing its return) | `filepath.Join(Base, transformKey(oid))` → `os.Open` | no validation, only 4 characters sliced | read side holds |
| same, write side | same | `WriteFile(path+".tmp")` → `sha256==oid` → Rename | **content must equal the hash of the path** | mutually exclusive, write side dead |
| 1Panel | `POST /settings/backup/backup`, login required | `exec.Command("bash","-c", fmt.Sprintf(...))` | `> %s` unquoted at the outer level | allowlist still to check |
| gf | none (literal) | `sh -c "eval echo ~$USER"` | all literal | false positive |

Read that table backwards and you get the **decision order**: first ask whether the entry is
controllable, then whether the sink really executes, and finally whether a gate sits in between. If
any of the three is "no", there is no point writing a payload.

---

## Three disciplines of the architect

1. **Give the rejection reason before the confirmation reason.** In a report, Rejected says more
   about the work done than Findings does.
2. **Budget beats completeness.** Checking all of S+A is capped at 150 minutes; past that, write
   Coverage gaps. The usual outcome of pursuing "check everything" is "nothing was checked
   thoroughly".
3. **There is no fourth verdict.** Outside GO / HOLD / KILL there is no "look again later".
   HOLD must state what is missing, otherwise it is equivalent to KILL.
