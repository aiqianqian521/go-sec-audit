# SSRF: Controlled Destination to Dispatched Request

## Discover and trace independently

Discover actual outbound capabilities from application behavior, clients, wrappers,
SDKs, transports and worker consumers. Do not restrict discovery to a supplied HTTP
method list. Webhooks, fetch/import/preview features, reverse proxies, cloud/storage
endpoint overrides and delegated fetchers can be relevant when present in code.
An SDK import or URL string alone establishes neither a request nor SSRF.

Connect:

`caller/source -> URL/target construction -> guards -> client/transport -> dispatch -> destination`

Track full URL, scheme, host/IP, port, base endpoint, relative references, proxy,
redirect destinations and resource-to-address lookups. Separate user-selected paths
and query values under a fixed origin from destination control; show any actual
origin override, URL joining behavior or server-side relay instead of assuming one.
Follow stored callback/config values into later jobs. A request constructor or URL
parser is not dispatch; resolve the real consumer and client instance.

For unfamiliar private/remote fetch APIs, inspect implementation or a reliable
contract. Record the worker's network origin and credential context if known.
Unavailable dispatch/destination semantics stay specific candidates.

## Assess the destination policy and actual connection

Identify what destinations the feature is intended to reach and why a target is
outside that boundary. Public fetching can be legitimate. Establish attacker
control and unauthorized reach, not merely that a server accepts a URL.

Inspect the actual implementation for:

- Parsed scheme, hostname, port and userinfo handling; exact host/allowed-subdomain
  matching rather than substring checks. Confirm which schemes the consumer really
  supports; default HTTP clients do not automatically fetch arbitrary URL schemes.
- URL normalization, relative resolution and later rewrites that can invalidate a
  guard. Check the final URL object consumed, not just an earlier display string.
- Redirect policy on that client and validation of each followed destination.
  Validate the redirected connection too; rejecting only the original URL can leave
  a distinct target path. No redirect bypass exists on a path that does not follow it.
- DNS/IP handling for IPv4, IPv6, mapped forms and special/local address ranges
  under the application's policy. Account for multiple resolver results and actual
  address selection. Do not assume the runtime accepts every alternate IP encoding.
- Whether checked resolution matches dialing. A separate lookup followed by a fresh
  hostname resolution can leave a check/use gap; establish the relevant resolver and
  attacker control rather than claiming DNS rebinding from any hostname input.
- Custom DialContext/RoundTripper, proxy selection and environment proxy behavior
  when relevant. URL host, HTTP Host header, TLS server name and connected peer are
  not interchangeable. A Host-header change alone does not change the TCP peer,
  but may affect a verified virtual-host/proxy route.
- HTTP method, body, forwarded headers, credentials, signed requests and response
  handling, to bound reachable effects and possible disclosure.

Context controls matter: egress restrictions, fixed target selection, credential
scoping and enforced proxies can change reachability. Do not assume invisible
infrastructure blocks a source-demonstrated policy failure, or that every private
endpoint is reachable. State deployment prerequisites and missing evidence.

## Classify, bound impact and remediate

A source-confirmed SSRF finding establishes a lower-trust source, meaningful target
control, an actual outbound path, an ineffective target guard and an unauthorized
destination class under supported policy. If the key override, consumer or policy
is unresolved, retain a candidate and the missing evidence. Static confirmation
does not establish that a live target responded.

Distinguish response-disclosing and blind effects: lack of returned body does not
prevent a request, but neither a request nor a timeout proves secret disclosure or
state change. Do not infer metadata credentials, Kubernetes API access or privileged
internal actions without the required destination, method and credential evidence.
An intentional authorized internal proxy is not automatically SSRF.

Recommend fixed target IDs or precise destination policy, consistent parsing,
validation of redirects and effective resolved/dialed targets, plus least-privilege
credentials/egress. Avoid recommending one private-IP check as a universal repair.
Do not perform DNS/network probes, callbacks, metadata access or internal requests
without authorization. Use static evidence or authorized isolated mock transports.

Optional source context: [io-template-reference-notes.md](io-template-reference-notes.md).
