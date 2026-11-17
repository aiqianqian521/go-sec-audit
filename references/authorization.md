# Authentication and Authorization Review

## 1. Establish the policy and threat model

Use the surface inventory to identify the endpoint, principal, action, resource
and intended access rule. Derive intended restrictions from documented behavior,
role/permission definitions, service contracts, UI/backend agreement and existing
policy enforcement. Also infer security boundaries from actual capability and
resource ownership; clearly distinguish inferred expectations from explicit policy.
Route names such as `/admin` alone do not prove a restriction.

Distinguish anonymous callers, ordinary authenticated users, tenant admins,
cross-tenant admins, service accounts and local CLI operators where applicable.
Do not assume a user can mint identities or change server-managed claims.

Read [capability-assessment.md](capability-assessment.md). Use business semantics,
execution identity, controllable inputs and ultimate effects to discover sensitive
capabilities, not a fixed list of administrative actions. Kubernetes apps require
particular attention to delegated cluster authority and controller-mediated effects.
Sensitivity assessment is required even when the operation has an innocuous name.

If intent is ambiguous, retain the sensitive capability, explain the inferred risk
and identify the policy question. Do not suppress it merely because the application
has no permission documentation, but do not label it a confirmed bypass without an
established violated boundary. Ordinary-user access may be intentional and bounded.

## 2. Reconstruct effective enforcement per endpoint

For HTTP, connect outer handlers, router/group/route middleware or filters,
controller hooks and handler-local checks in actual execution order. Inspect
registration timing, nested groups, mounts, path/method matchers and exclusions.
Middleware with an authentication-related name is only a lead.

For gRPC, inspect the actual server's unary AND stream interceptors, chains,
full-method selectors and service methods. A unary interceptor does not by itself
protect streaming methods. Generated registration functions do not establish auth.

For gateways, trace both HTTP and RPC paths. Verify how trusted identity is
forwarded, whether backend checks remain effective, and whether direct RPC access
is an independently reachable path. Do not claim a backend bypass just because it
has no HTTP middleware or because backend network exposure is unknown.

For CLI, inspect command and inherited hooks plus service-layer checks. Ordinary
local CLI execution is not automatically a remotely exploitable authorization
issue. Identify the relevant OS identity, credentials, remote API or privilege
boundary before calling command availability a vulnerability.

For every relevant guard, determine:

- What input or identity does it trust? Who can control that input?
- What permission/policy does it evaluate, for this action and resource?
- On failure, does execution actually stop before protected work?
- Can errors, alternate methods, allowlists or missing context take a permissive path?
- Is it attached to this endpoint on this server instance, not merely defined?

Check the framework's actual control-flow semantics. Writing a 401/403 response,
calling an abort-like API, or returning from a helper may not prevent subsequent
statements or downstream work. Conversely, do not require every framework to use
the same explicit abort API when its return/dispatch semantics already stop work.

## 3. Authentication: prove the identity boundary

Follow cookies, sessions, tokens, mTLS or trusted-proxy identity to a verified
principal. Inspect relevant verification and failure handling, not just extraction
of a user ID. Token decoding alone is not verification.

Track client-provided IDs and identity headers separately from verified claims.
Headers may be trustworthy behind an enforced proxy boundary, but that boundary
requires evidence; if deployment controls are unavailable, record the dependency.
Do not presume either universal header trust or an exploitable direct connection.

Record authentication as enforced, bypassed, not required by supported policy, or
unresolved. A public health/login endpoint is not automatically a missing-auth bug.

## 4. Functional authorization: prove who may perform the action

First summarize what the endpoint can actually cause, under whose authority, and
within which resource scope. Do not substitute its name or final SDK call for
business-effect analysis. Include deferred work through jobs, controllers and APIs.

Starting with a valid ordinary-user identity, trace role, permission, scope, ACL,
policy-engine or capability checks through the handler and service layer. Confirm
the evaluated action matches the operation ultimately performed. Examine default
allow paths, ignored errors and selectors that omit endpoints.

An authentication check alone is not functional authorization. Hiding UI controls
or requiring a frontend-supplied `isAdmin` flag is not server-side authorization.
However, a downstream service check can enforce the policy even when the handler
has no role check. Read that layer before reporting a missing guard.

For an "any authenticated user can invoke a privileged operation" finding, show:

1. The established policy or trust boundary the operation violates. Label the basis
   as explicit policy, implementation-enforced elsewhere, or inferred capability
   risk; inferred sensitivity alone does not establish a violation.
2. How an ordinary user's verified identity reaches it.
3. Why all relevant enforcement layers allow that identity or are bypassed.
4. Which protected side effect or information becomes available.

Do not require RBAC specifically; valid ownership, capabilities or attribute-based
policies may legitimately grant the action.

## 5. Data authorization: trace identity to the actual data operation

Identify object IDs, tenant IDs, parent IDs, user IDs, search filters and batch
selectors from paths, query/body fields, RPC messages and CLI arguments. Follow
their use into service/repository methods, ORM scopes, SQL predicates and external
services. Parameterized SQL prevents injection, not unauthorized object access.

Look for an effective authorization relationship, such as verified subject to
owner, membership, sharing ACL, tenant scope, resource capability or policy decision.
Do not require an explicit `owner_id` comparison if an equivalent control exists.

Check:

- Read/list/search/export/count paths and sensitive response fields.
- Update/delete/create paths, including parent/container membership.
- Tenant scope derived from a trusted principal rather than an unchecked selector.
- Batch operations: every affected object must satisfy the applicable policy.
- Body binding: caller-controlled owner, tenant, role or permission fields that can
  override verified state or change the authorization meaning of an update.
- Check/use consistency: authorization and the eventual query/mutation must refer
  to the same resource and scope, including asynchronous jobs and cached results.
- Database row-level policies and external resource services, when applicable.

A `WHERE id = ?` query is a lead, not conclusive proof of IDOR. Check earlier
authorization, data visibility rules and database enforcement. An unguessable ID
is not itself authorization, but exploit prerequisites and valid sharing tokens
still matter. Distinguish horizontal access, vertical privilege and cross-tenant
access; do not inflate one into another without evidence.

## 6. Alternate paths and denial behavior

Compare equivalent operations exposed by alternate HTTP methods, versioned routes,
legacy/admin/debug listeners, direct RPC, gateway mappings and background commands.
An alternate path is relevant only if it reaches the protected operation under a
different effective policy. Note external exposure uncertainty separately.

Check authorization before data return or mutation, not only the final status.
A forbidden response after a write is not successful enforcement. Do not assume
404 conceals a resource safely unless the data and side effects were also blocked.

## 7. Conclusion thresholds

- `source-confirmed`: the inspected code establishes a concrete unauthorized path,
  including principal, expected rule, ineffective control and protected effect.
  This does not mean a live exploit or deployment exposure was tested.
- `candidate`: a specific suspicious path exists, but a named policy, downstream
  implementation, registration condition or deployment boundary is unresolved.
  Keep a sensitive-capability/policy concern distinct from a suspected bypass and
  state exactly which boundary has not yet been established.
- `control-observed`: an effective control was traced for this action and resource;
  describe its scope, not a blanket "endpoint secure" verdict.
- `intentional-public`: supported policy permits anonymous access to this operation.
- `not-applicable`: this dimension does not apply; explain why, such as an endpoint
  with no caller-selected or private resource. Do not use it to hide uncertainty.

Use the dimensions independently. Public endpoints can still need data controls;
authenticated endpoints can lack action or object authorization. Report actual
coverage, including unresolved delegates; no findings does not imply no risk.

Suggest bounded local regression cases: anonymous, unauthenticated/invalid identity,
ordinary authorized user, ordinary unauthorized user, other owner, other tenant,
mixed-owner batch, alternate transport and downstream denial. Do not execute probes
or use production accounts/data without authorization.
