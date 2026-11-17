# SQL Injection: Controllable Construction to Execution

## Main question

Determine whether lower-trust input becomes SQL syntax instead of remaining data:

`source -> field -> transformations/guards -> query construction -> execution`

Focus on controllable concatenation, formatting, interpolation and raw fragments.
Neither string construction nor missing explicit preparation alone proves injection.
A finding needs actual input control, a syntax-changing insertion point and a
reachable execution path, with applicable guards accounted for.

## Discover independently

Identify database clients, driver/dialect, ORM, repository interfaces and query
builders from the project's actual imports, constructors and uses. Explore forward
from inputs and backward from execution/query-building calls. Follow aliases,
scopes, callbacks, custom expressions, private SDKs and generic data-service RPCs.
Function names guide search but do not establish SQL semantics or trust boundaries.

Use supplied lists only as supplementary leads. Optional source notes are in
[sql-reference-notes.md](sql-reference-notes.md). Do not restrict discovery to
database/sql or GORM, and do not assume an unfamiliar `Fetch` wrapper is safe.
Resolve local/replaced/vendored implementations and relevant dialect behavior;
missing remote query contracts remain explicit candidates, not invented sinks.

## Trace construction and input control

For each relevant path identify:

- The HTTP/RPC/CLI field, stored value or queued configuration an untrusted caller
  controls, and the access required to set it. Storage does not make data trusted.
- Every concatenation, formatting, template, join or raw-expression step leading
  to SQL. Distinguish attacker data from constants and approved fixed mappings.
- The insertion position: literal value, identifier, condition, operator, ordering,
  grouping, projection, join, table/schema or other actual SQL grammar position.
- Validations and conversions, their error handling and later transformations.
  A successfully enforced integer conversion followed by numeric formatting can
  remove syntax control; an ignored conversion error or reuse of raw input may not.
- Final SQL template and argument list separately, plus builder, preparation and
  execution locations. A query builder or prepared statement that is never executed
  is not an established application exploit path.

Follow deferred execution: query fragments stored for reports, workers or scheduled
jobs can be safe at initial insertion yet unsafe when later interpolated. Follow
dynamic SQL inside stored procedures when its implementation or contract is available.
Do not assume either procedure calls or remote data platforms eliminate injection.

## Evaluate parameterization precisely

- Fixed SQL plus correctly bound value arguments can preserve the code/data boundary
  without an explicit `Prepare` call. Inspect actual driver/wrapper semantics.
- Concatenating untrusted text into a query and then calling `Prepare` or enabling
  prepared-statement caching does not turn that text back into a bound value.
- Placeholder arguments protect their own positions, not other concatenated query
  fragments. Track query text and values independently throughout the call chain.
- Value placeholders generally do not parameterize identifiers, keywords or SQL
  fragments. For dynamic columns, tables or ordering, check fixed allowlist mappings
  or the actual dialect-aware identifier/expression construction contract.
- Structured ORM input is not a blanket guarantee: inspect field/key handling,
  expression values, raw flags, custom clause builders and the resolved version.
  Conversely, an ORM raw-query API with fixed SQL and bound values is not inherently
  vulnerable. Builder method names alone cannot establish either verdict.
- ORM debug output may render bound values into a display string. Do not treat that
  display as the SQL actually sent. Inspect template/arguments and the driver path.
  Driver-side interpolation is also not automatically unsafe or safe; evaluate its
  documented encoding, dialect and configuration contract where relevant.

For GORM-like APIs, reason about the actual overload and argument role: condition
text vs value, raw expression vs bound variable, and quoted identifier vs raw SQL.
Extend analysis to any query-contributing method encountered, not only examples in
reference notes. A typed expression can contain unsafe text; a string can be safe
when converted to an approved constant or correctly bound as a value.

## Validate a suspected boundary failure

Explain how permitted input can change SQL grammar or expression semantics beyond
the intended data position, in the actual database/dialect and quoting context.
Account for relevant decoding, validation and driver behavior. A generic quote or
comment token is not proof when the actual context neutralizes it.

Do not require stacked statements, error output, time delays or a successful data
dump to establish source-level injection. Conversely, do not claim file access,
command execution or unrestricted database access without supporting privileges
and backend features. State inspected database identity and scope when known.

Keep adjacent issues distinct: missing tenant predicates are authorization issues,
and wildcard behavior in a bound LIKE pattern is not itself SQL syntax injection.
An intentionally offered SQL console is an execution capability; assess its allowed
users, credentials and resource scope rather than labeling accepted SQL injection.

## Evidence and remediation

For a source-confirmed finding provide source/field, controlled fragment, query
template and argument roles, relevant guards, final execution evidence and the
broken code/data boundary. Preserve unknowns as candidates with the exact missing
consumer, driver contract or path. Do not report a missing `Prepare` alone.

Recommend binding data values instead of string interpolation, fixed mappings for
allowed structural choices and correct builder/dialect contracts. Preparation must
use the trusted template, not an already-contaminated string. Do not propose a
universal keyword/metacharacter blacklist or assume escaping is portable.

Use bounded static explanations and local regression cases for the insertion
context. Do not connect to databases, execute query payloads, retrieve data or run
repository examples without authorization. Findings are source-level conclusions
unless separate runtime testing was explicitly authorized and actually performed.
