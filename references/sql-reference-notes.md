# Supplementary SQL Reference Notes

Optional leads only. Start with [sql-injection.md](sql-injection.md) and discover
the target application's own dataflow. These documents and symbol examples neither
define the audit scope nor prove safety or a vulnerability.

## User-provided sources

Read on 2026-10-30:

- [database/sql SQL injection](https://yuque.antfin.com/miantiao.lpc/golangsec/wc3rzuv5of5lt3zm), doc ID 408553147.
- [GORM SQL injection](https://yuque.antfin.com/miantiao.lpc/golangsec/gg3feq1gn5r6inlr), doc ID 408553148.

The first supplies method-search leads. The second discusses conditions, tables,
columns, ordering, grouping, raw queries and clause expressions; its join/preload
coverage is explicitly unfinished. Use these as historical research notes, not
version-independent API guarantees or compile-tested fixtures. Do not run their
database setup, migration or query examples against a target database.

## Relevant leads, when the project uses these components

| Context | Possible search leads | Required distinction |
| --- | --- | --- |
| database/sql and driver wrappers | Query/QueryRow/Exec/Prepare and context variants on DB, Tx, Conn or statements | Query text vs bound args; construction/preparation vs actual execution; internal helper names vary by Go version |
| ORM conditions | Actual filter/condition methods, including Where/Not/Or/Having and inline lookup conditions | Overload, argument type, controlled SQL text vs value and guards |
| Projection/target selection | Select/Table/Distinct and equivalent builders | Identifier quoting, raw expression handling, fixed mapping and parameter roles |
| Ordering/grouping/join/loading | Order/Group/Joins/Preload and project-specific equivalents | Which inputs contribute syntax vs safe metadata/values; trace callbacks and final builder |
| Clauses/expressions | Expr SQL/Vars, clause objects, custom builders, raw flags | Typed wrapper does not itself guarantee safe contents; raw SQL text vs bound variables and quoted identifiers |
| Raw queries | Raw/Exec and equivalent methods | Fixed query with bound args vs controllable text; preparation elsewhere does not protect interpolated fragments |

Discover other ORMs, builders, SQL gateways and private repository methods from
source, even when none of these symbols appears. No method list is complete.

## Do not carry over blanket conclusions

- Struct/map input is not universally safe; inspect key/field handling, expression
  values and custom implementation. Correct binding is not merely doubling quotes.
- A method taking multiple arguments does not prove parameter binding; inspect
  actual placeholders and overload resolution. Missing placeholders may produce
  errors or different behavior, not a valid safe-query pattern to recommend.
- Raw identifier flags and expression fields require resolved builder semantics;
  do not generalize a single flag check into safety for every possible clause.
- Hard-coded SQL containing unusual syntax does not demonstrate attacker control.
- Logged interpolated SQL and historical sample payloads are not evidence of what
  the driver executed or what the production caller can supply.
