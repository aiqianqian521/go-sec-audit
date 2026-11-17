# Supplementary Execution Leads and Source Notes

This is an optional reference, not the discovery algorithm or a sink allowlist.
Start with [command-execution.md](command-execution.md) and the actual project.
The model must discover other execution capabilities independently. None of these
names proves a vulnerability, and not all listed operations actually execute code.

## User-provided reading

Read on 2026-10-29:

- [Golang command injection](https://yuque.antfin.com/miantiao.lpc/golangsec/ucz794shcrnya875), doc ID 408553149.
- [K8s command execution](https://yuque.antfin.com/miantiao.lpc/golangsec/gcdm545ddltmg4o9), doc ID 408553144.

These notes informed supplementary coverage, not a direct copy of either document.
The second document labels example code AI-generated and not guaranteed executable.
Image/OCR fragments and historical/private API names require source verification.
Do not copy sample credentials, deployment assumptions or blanket filtering advice.
The cloud/platform prompts below are additions, not claims made by those documents.

## Consult only when relevant to a discovered capability

| Context | Possible leads | What still needs establishing |
| --- | --- | --- |
| Local processes | `os/exec` constructors, `Cmd.Run/Start/Output/CombinedOutput`, direct `Cmd` fields, `os.StartProcess`, platform-specific syscall process APIs | Construction vs start; actual receiver/import; executable, argv, stdin, environment and parser |
| SSH | `golang.org/x/crypto/ssh` sessions, `Run`, `Start`, `Output`, `CombinedOutput`, `Shell`, stdin writes | Remote server's command/shell contract and inputs; interactive shell input after startup |
| Docker/container services | Exec create/start, container create/start, command/entrypoint fields and private host-exec wrappers | SDK/version-specific types; definition vs execution; effective entrypoint plus argv and any shell |
| Kubernetes clients | `PodExecOptions.Command`, REST `pods/exec`, client-go remotecommand executors and stream methods; kubectl execution wrappers | Actual request/stream linkage, target identity/scope and whether argv selects an interpreter |
| K8s server-side adapters | `Executor`, `ExecInContainer`, `ServeExec`, `ExecOptions`, `ContainerExecContext`, `ContainerExecHandlerFunc` when actually present | Package/version and concrete implementation; names from examples are not all client-go APIs |
| CLI helpers / Nirvana-related names in the notes | `NewNamedNirvanaCommand`, `ExecuteWithConfig` | Whether this is CLI dispatch, an application wrapper or actual process/remote execution; no assumed terminal sink |
| Alibaba Cloud SDKs or generic cloud requests | Discovered ECS command operations such as `RunCommand`, `CreateCommand`, `InvokeCommand`; OOS automation execution; script/task/action request fields | Actual product/version/operation contract, content or command-ID linkage, template parameters, target/credential scope and interpreter; create need not execute |
| Unified operations platform / private SDK | Project-specific names combining run/exec/dispatch/submit with jobs, scripts, automation, hosts, nodes or tasks; generic HTTP/RPC calls carrying equivalent fields | Concrete platform contract, actual worker/agent behavior, template expansion and parameter handling; names alone remain candidates |

The table is deliberately non-exhaustive. Build searches from the target repository's
own vocabulary, including aliases and neutral names. Platform execution may use a
generic SDK dispatch method with a serialized action rather than a named function.

## Interpretation cautions

- Go process APIs do not implicitly invoke a shell for ordinary argv execution.
  A caller can explicitly select a shell/interpreter or a wrapper can add one.
- Kubernetes `PodExecOptions.Command` is argv, not implicitly a shell command.
  Follow any explicit interpreter and downstream wrapper before deciding injection.
- Docker command/entrypoint fields need actual container image/runtime semantics;
  string concatenation into an array element alone does not prove shell injection.
- `Run`, `Start`, `Output` and `Shell` are ambiguous names. Resolve receiver types.
  `Wait` generally observes a started process; do not count it as another launch.
- Historical notes include API spellings, incomplete code and restrictive filter
  suggestions. Use actual Go export casing and resolved implementation; do not adopt
  the notes as a compile-tested API catalog or universal remediation recipe.
- Base64/JSON payloads, named commands and task IDs can hide or defer execution.
  Follow both their definitions and consumers; definitions/polling are not launches.
