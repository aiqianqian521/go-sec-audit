# Capability and Sensitivity Assessment

## Reason from effects, not a catalog

Use domain knowledge to understand the application, then verify the concrete
behavior in source. Framework choice tells where controls attach, not how sensitive
an operation is. Neither Go nor Kubernetes implies that every operation is privileged.

For each endpoint, answer:

1. What business capability does this expose, including returned data and deferred
   effects? Follow wrappers and service calls until the relevant effect is known.
2. What does the caller control: target, namespace, cluster, manifest/spec, command,
   image, credential selection, identity, destination or other capability parameters?
3. Under whose identity does the effect execute? Separate the application user from
   the application's OS identity, cloud principal, cluster credential and controllers.
4. What is the reach: own object, namespace, tenant, cluster, multiple clusters or
   external infrastructure? Explain how scope is constrained, not merely requested.
5. What trust boundary can this cross: ownership, tenant isolation, credential use,
   code execution, control-plane authority, disclosure or availability?
6. Which controls actually bound that capability: application policy, impersonated
   user RBAC, admission, validation, namespace confinement or downstream checks?

Produce a short causal statement, for example: "Caller-controlled configuration is
submitted under the service's cluster identity; a controller consumes it and creates
resources in the selected namespace." Every material link needs source evidence or
an explicit unknown. An unknown downstream effect is not permission to invent one.

## Kubernetes and control-plane applications

Apply this lens when cluster-related imports, manifests or behavior support it.
These are reasoning prompts, not an exhaustive sensitive-function list.

### Follow identity and delegated authority

Trace client construction: in-cluster ServiceAccount, kubeconfig, per-cluster stored
credentials, user token or impersonation. Resolve the identity used by each actual
operation, including async workers. Inspect relevant RBAC manifests when present;
a bundled ClusterRole does not prove the deployed binding or credential grants it.

Kubernetes API authorization of a shared ServiceAccount establishes that service's
authority, not necessarily the requesting user's authority. Determine whether the
application intentionally offers a constrained capability, forwards the user's
identity, or independently authorizes each target/action. Do not label shared
credentials a vulnerability by themselves.

Where permission reviews are used, inspect SubjectAccessReview/SelfSubjectAccessReview
or equivalent policy inputs: subject, verb, API group, resource/subresource, namespace
and name must match the eventual operation. A self-review under the application's
credential does not establish the end user's rights. Check errors and mismatched
check/use targets, while recognizing equivalent application policies as valid.

### Follow input through Kubernetes semantics

Resolve typed, dynamic, REST and proxy clients to resource, verb, subresource and
target scope. Include special paths such as exec/attach/port-forward/logs, generic
resource handlers and aggregated APIs when present; do not infer support merely
from importing client-go. Read-only calls may expose credentials or private data;
write calls can be appropriately bounded self-service operations.

For manifests, charts, templates or arbitrary resource operations, analyze which
fields and kinds remain caller-controlled after validation/rendering. Infer the
capabilities those choices actually allow. For workload creation, relevant fields
may affect execution identity, mounted data and host access. Account for admission
and workload policy; creating a Pod does not automatically prove host compromise.

For custom resources, identify CRD scope, schema and the operator's reconcile path
or downstream contract. A harmless-looking CR update may trigger resource creation,
credential use or external provisioning. A CR name or schema alone does not prove
those effects; unavailable operator code is a named analysis limit.

Consider compositions: input accepted by a web endpoint can be consumed later by a
controller running with a different identity. Track ownership and tenant boundaries
through that handoff. A secured initial write does not necessarily authorize every
effect, and a privileged controller does not by itself establish escalation.

### Assess the effective boundary

Determine whether caller-supplied namespace/cluster selectors are tied to verified
membership. Distinguish selecting an authorized target from delegating arbitrary
cluster authority. Keep cluster-scoped and namespaced resources separate.

Explain how controls constrain effective capability, rather than judging only by
RBAC presence or absence. External admission, cloud IAM or controller policy that
cannot be inspected remains an explicit dependency, not assumed protection or an
assumed bypass. Missing deployment evidence does not erase source-demonstrated
excess delegation; state the additional prerequisites instead.

## Output: sensitivity is separate from authorization

For every assessed capability, record:

- Endpoint and actual business effect, including indirect operations.
- Sensitivity: high, moderate, low or unresolved, with a concrete reason. High may
  reflect credential disclosure, execution authority, cross-boundary effects or
  broad availability impact; bound the rating to the inspected conditions.
- Caller-controlled parameters, execution identity and enforced resource scope.
- Expected boundary and basis: explicit policy, implementation evidence or inference.
- Observed constraints and permission result, separately from sensitivity.
- Unresolved links and the precise evidence needed to resolve them.

Do not force a numeric score or require an admin role. A sensitive capability may
legitimately be available to ordinary users within their own namespace. Conversely,
an unremarkable "preview", "validate" or "sync" endpoint may delegate powerful
authority. Infer that from code effects, not from those example names.

Report a high-sensitivity capability with uncertain intended access as a policy/risk
review item. Report a confirmed authorization defect when the actual access path
and violated boundary are established. Keep exploit severity separate from the
capability's inherent sensitivity and do not claim runtime exploitation.
