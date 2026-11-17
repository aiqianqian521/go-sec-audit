# Application Surface Mapping

## Establish application boundaries

Inspect `go.work`, each `go.mod`, `go.sum`, `vendor/modules.txt`, local `replace`
targets and source imports. The standard directory is `vendor`; if a repository
uses `vender` or another custom layout, inspect its build configuration rather
than assuming it is an active Go vendor directory.

Record the declared version and actual inspected source separately. Workspace
overrides, vendoring, local replacements and build flags can change resolution.
Do not assert that vendored code is active without evidence of the build mode.
Do not fetch missing modules just to finish an inventory.

Find `package main`, command constructors, startup functions and deployment
configuration relevant to the requested scope. Separate test/example binaries
from production candidates. Note build tags, GOOS/GOARCH and feature switches.

## Framework identification

Use dependencies as discovery leads. Confirm imports and actual API use. Follow
aliases, wrappers, constructors and dependency injection across packages.

Record one of:

- `dependency-only`: no business-source use located.
- `source-use`: source use located; identify client/server/adapter/CLI purpose.
- `startup-chain`: registration and startup connected within an executable.

These are static evidence levels, not runtime or deployment states. A gRPC
client does not prove a gRPC server; a gateway does not prove its backend is local.
Generated registration code is relevant evidence, not business implementation.

## Listeners and protocols

Follow server addresses through constructors, flags, environment variables,
configuration loading and explicit overrides. Inspect actual precedence rather
than assuming a universal order. Keep expressions and conditions when unresolved.

For each listener record:

- Owning executable, subcommand, framework instance and startup location.
- Bind address and port: literal/default/configured value or unresolved expression.
- Value origin and precedence, including environment or command-line dependencies.
- Application protocol: HTTP, gRPC, gateway HTTP, WebSocket, etc., with evidence.
- Transport/security: TCP or Unix socket; HTTP version and TLS only when supported.
- Enablement conditions and whether runtime behavior was independently verified.

`:0` means an OS-assigned port, not a known fixed port. A Unix socket has no TCP
port. A framework default is not evidence of that port being in use. Container
published ports and reverse-proxy paths are distinct from application listeners.
Do not infer HTTPS from a variable name or external exposure from `0.0.0.0`.
Check auxiliary listeners such as metrics, debug/pprof and health servers.

## Endpoints

HTTP: compose mount prefixes, nested groups, resource paths and method-specific
registrations. Preserve framework parameter syntax and host restrictions. Associate
each handler with its actual router/listener. Include static/file/catch-all handlers.
For dynamic route names retain the expression and enumeration limit. Do not turn
`Any` or automatic HEAD/OPTIONS behavior into a guessed method list; check the
resolved implementation or mark the behavior unresolved.

RPC: connect registered service implementations and generated descriptors to full
method names, e.g. `/package.Service/Method`. Inventory unary and streaming methods;
do not present them as ordinary HTTP routes. Record reflection separately.

Gateway: trace actual gateway registration to generated HTTP mappings and backend
methods, including additional bindings. An unregistered proto annotation is only a
candidate route. Record gateway-to-backend metadata/credential forwarding.

CLI: record command/subcommand paths, execution functions, inherited and local
flags, environment/config sources, pre-execution hooks and server-starting branches.
Command parsing itself is not a network protocol or an access-control boundary.

## Coverage

State whether enumeration covers all statically resolved registrations or only a
subset. List unresolved mounts, generated files, plugins, build variants and code
outside scope. Do not label a partial route list as complete.
