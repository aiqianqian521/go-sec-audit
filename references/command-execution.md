# Independent Execution Discovery and Injection Analysis

## 1. Discover from the application, not a sink list

Form an initial model of the application's business functions and external
dependencies from entrypoints, imports, configuration, client construction and
service interfaces. Ask where it can cause a program, interpreter, script, task
or user-specified instruction to execute, locally or elsewhere.

Explore both directions:

- Forward from relevant HTTP/RPC/CLI inputs and lower-trust persisted or queued
  data into business services, clients and workers.
- Backward from independently discovered execution-capable calls, request types,
  task handlers and interpreter consumers to their callers and input origins.

Use the project's vocabulary to expand searches. Function/type/interface names,
comments, SDK operation names, serialized action fields and fields containing
commands, scripts, arguments, templates or target hosts are discovery clues. Resolve
receiver types and implementations rather than matching a method name in isolation.
Ordinary names such as `Run` or `Execute` are ambiguous; unfamiliar or innocuous
names can still hide execution. No particular keyword is required for a finding.

Include private operation platforms, cloud APIs, SSH/container services, generic
HTTP/RPC clients, SDKs, queues and controller handoffs when the project uses them.
The terminal execution may exist outside the repository. Lack of a local process
API does not rule out command execution.

Use supplementary references only to challenge possible omissions or understand
a relevant implementation. Do not turn user examples into a complete catalog,
mandatory sequence or default vulnerability verdict. Absence from a supplied list
does not reduce the need to inspect a capability found in the actual project.

## 2. Establish what each discovered call does

Resolve wrappers, function values, interfaces, injected implementations and SDK
requests against the actual local/replaced/vendored version. Where implementation
is remote, use available API contracts, request schemas, agent/worker code and
version-matched authoritative documentation. Do not invent private API behavior.

For each candidate record:

- Qualified symbol/client operation and evidence location.
- Role: builder/definition, submission, dispatch, execution, streaming input,
  result polling or cancellation. A builder/polling call is not itself execution.
- Execution host/container/cluster, identity/credential and resource selection.
- Contract: executable plus argv, shell string, interpreter source, stdin script,
  fixed task with parameters, or a named task whose implementation needs tracing.
- The caller-controlled fields and where they enter that contract.
- Submission-to-execution links for task IDs, command IDs, CRs, persisted templates
  and queue messages, including decoding/rendering done by the eventual consumer.
- Whether execution is statically connected, contract-supported or unresolved.

An API contract can establish remote execution semantics without remote source.
An SDK dependency, suggestive symbol or request field alone cannot. Where only a
candidate is supported, name the missing implementation/contract and retain it in
coverage; do not silently discard it or upgrade it to a confirmed sink.

## 3. Trace source, transformations and parser boundaries

For each execution-capable path connect:

`entry/source -> field -> transforms/guards -> wrapper/request -> dispatch -> consumer/parser -> effect`

Track untrusted values through concatenation, formatting, templates, split/join,
URL/JSON/base64 handling, storage and asynchronous delivery. Encoding is transport,
not sanitization. Persisted input is still lower-trust if another principal controls
it. Record truncation, validation, authorization and fixed-value mappings precisely.

Determine each interpretation layer. Structured argv may become a shell string
inside a wrapper, remote platform or task template; a shell command may invoke
another interpreter. Account for stdin, script files, template expansion, executable
lookup, working directory and environment when caller control affects execution.
Prioritize demonstrated paths rather than hypothetical control of every setting.

Check the data boundary expected by the operation. A requested hostname, filename,
resource name or fixed-task parameter becoming interpreter syntax is different
from an authorized user intentionally submitting a script to a script runner.

## 4. Classify precisely

### Shell or interpreter injection

Establish that lower-trust data reaches shell/interpreter syntax in a context where
it can change the intended program. Identify the actual parser, quoting context,
transformations and control over the relevant fragment. A shell token in an argv
element does not establish shell parsing. A script can also arrive via stdin or a
file rather than a `-c` option.

### Argument/option injection

Without a shell, inspect the target program's real argument grammar. A value may
be interpreted as an option, expression, config, plugin or script instruction.
Prove the target supports the dangerous behavior and the input can select it.
Do not claim that every leading dash is exploitable or that argv prevents every
execution-related problem.

### Executable/script control

If a caller chooses the executable, script content or executable lookup context,
identify the resulting capability and expected boundary. Do not force this into
shell-injection terminology. Establish relevant validation and identity restrictions.

### Unauthorized or excessive delegated execution

A fixed command executed on another user's pod, unauthorized host/cluster or under
an unintended credential can be an authorization defect without command injection.
Use the permission/capability guidance for that boundary. Conversely, legitimate
execution in an authorized sandbox is not a defect just because input is executable.

Classifications can coexist when separate demonstrated boundaries are violated;
do not duplicate one path simply because it appears behind several wrapper calls.

### Path-only control in shell-concatenated commands

When a caller controls a value that is concatenated into a shell string but the
controlled value serves only as a file path (e.g. a redirect target) and the
program output is fixed or determined by constant parameters the caller cannot
change, the finding is arbitrary-path file write, not command execution. Trace
which fields the caller can influence beyond the path: if the caller can also
inject additional options or arguments (via spaces in a path value that bypasses
a character allowlist), classify the option injection separately from the path
write. State the actual shell fragment the caller enters, whether it sets
program identity, arguments, redirect target or stdin source, and which of
those the caller can change. An arbitrary-path write through a fixed shell
program is not RCE unless the caller controls the content written or a
downstream consumer interprets that content as executable.

## 5. Assess controls in the actual execution context

Evaluate strict semantic validation, fixed operation-to-command mappings, argument
separation and context-appropriate quoting for the actual target/parser. Check
whether validation occurs after the final relevant decoding and is preserved by
later transformations. For task templates, examine substitution rules in the
consumer, not merely the SDK parameter type.

Do not endorse a universal metacharacter-deletion list, assumed escaping routine
or regex merely because it looks restrictive. Such controls can corrupt data,
miss nested parser contexts, or leave dangerous options intact. An end-of-options
marker helps only where the actual executable supports it in that argument position.

Prefer removing shell interpretation when unnecessary, fixed approved operations,
typed/validated arguments, correct parameterization and least-privilege target
authorization. If scripts are an intentional feature, address caller/target rights,
isolation, credential scope and allowed capability rather than promising a generic
filter makes arbitrary scripts safe.

## 6. Evidence, impact and delivery

A source-confirmed injection finding needs a lower-trust source, relevant parsing
contract, source-to-execution path, control allowing changed execution semantics,
ineffective applicable guard and a violated code/data boundary. A specific unresolved
consumer/template contract stays a candidate; state what would confirm or refute it.

State required caller access, execution identity, location and affected resources.
Container execution is not automatically host execution; cloud task submission is
not automatically root execution; imported SDK credentials do not prove deployment
grants. Keep demonstrated impact separate from conditional follow-on effects.

Give a bounded static explanation or inert regression input for the specific parser
boundary. Do not run commands, create cloud jobs, connect to pods/SSH, retrieve
secrets, contact callback services or trigger production execution to validate a
claim without authorization. Do not copy active exploit steps from reference notes.

Report both confirmed paths and unresolved execution candidates using the report
contract. A known-symbol search returning no hits is not a negative security result.
