# Template Source, Data and Exposed Capabilities

## Discover and separate trust roles

Independently locate template engines, render wrappers, dynamic files, template
storage and final consumers. Include private engines and deferred generators, not
only known parser names. Identify the actual imported version and engine semantics.

Trace separately:

- Template source: text passed to Parse/ParseFiles or equivalent compilation,
  selected files, include names, delimiters and caller-controlled concatenation.
- Render data: the root object and nested values supplied during execution.
- Exposed capabilities: registered functions, reachable methods, loaders, callbacks
  and the output consumer.

Ordinary data containing template delimiters is not automatically parsed again.
A fixed template rendering a caller-controlled string is not source injection
unless a later operation actually treats that string as template source.
Follow storage and repeated parse/render phases when present.

## Establish actual engine behavior and impact

For Go text/template and html/template, parsing and execution are separate stages.
A dynamic Parse call is not evidence that the template is executed. Inspect the
reachable Execute/ExecuteTemplate or wrapper/consumer path and error handling.

Templates do not automatically see every variable in the Go source file. Access
is through supplied data, associated templates and exposed functions/methods under
the engine's real rules. Determine whether sensitive fields or callable methods
are reachable from that object; do not invent arbitrary reflection or file access.

Inspect FuncMap, method sets and data objects for I/O, request, command, secret or
state-changing capabilities. A registered helper may be safe or unreachable for
this template. A function name alone is not proof of its behavior or availability.
Built-in template evaluation does not by itself establish arbitrary OS execution.

html/template contextual escaping protects specific browser-output contexts; it
does not authorize arbitrary template source or sandbox exposed capabilities.
text/template has no automatic HTML escaping, which matters only for an actual
browser-rendered output path. Trusted HTML/JS/URL type conversions require their
own input-to-output analysis; do not conflate them with server-side injection.

For templates generating shell, SQL, configuration, manifests or other templates,
follow the generated artifact into its real parser/controller/executor. Template
expansion alone does not prove downstream execution. Link demonstrated paths to
command/SQL/capability findings and avoid duplicate reports for one root cause.

## Distinguish intended features from defects

User-authored templates may be intentional. Establish the intended data/function
boundary and caller rights, then assess excess exposure, cross-tenant template
selection or dangerous helper delegation. Source control is a capability to assess,
not automatically an injection vulnerability or a reason to suppress risks.

A confirmed finding identifies lower-trust input, the parse-and-consume path, the
violated data/source or capability boundary and a concrete unauthorized effect.
If only source parsing or an unknown helper is visible, retain a candidate and
missing evidence. Distinguish SSTI, sensitive-data exposure, client-side output
injection and downstream command/SQL injection according to the demonstrated path.

Prefer trusted templates with separate render data, narrow data objects/function
sets, authorized template selection and isolated execution where user templates are
required. Escaping braces or enabling HTML escaping is not a universal SSTI repair.
Do not render untrusted target templates or invoke their helpers without authorization.

Optional source context: [io-template-reference-notes.md](io-template-reference-notes.md).
