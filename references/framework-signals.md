# Framework Discovery and Enforcement Hooks

Use these as search hints, not authoritative API definitions or a closed allowlist.
Resolve symbols against the actual imported version, vendored code or local fork.
Similar names in an unrelated package do not establish framework identity.

| Ecosystem / import clues | Registration and startup leads | Permission-chain leads |
| --- | --- | --- |
| Standard `net/http` | `ServeMux`, `Handle`, `HandleFunc`, `Server`, `Serve`, `ListenAndServe`; custom `Handler` | Handler wrappers, router mount order, direct handler invocation; unwrapped secondary muxes |
| Gin: `github.com/gin-gonic/gin` | `New`, `Default`, `Group`, method registration, `Run`, mounting as handler | Engine/group/route `Use`, `HandlersChain`, `Next`, `Abort`; check termination before/after side effects |
| go-restful: `github.com/emicklei/go-restful` and `/v3` | Containers, `WebService`, `Path`, `Route`, verb builders, `To`, HTTP mounting | Container/service/route filters, `ProcessFilter`, `FilterChain`; inspect actual chain continuation |
| gRPC: `google.golang.org/grpc` | `NewServer`, generated `Register...Server`, `Serve`, service descriptors | Unary and stream interceptors, interceptor chains, per-method policy, handler/service authorization |
| gRPC-Gateway: `github.com/grpc-ecosystem/grpc-gateway` and `/v2` | `runtime.NewServeMux`, generated `Register...Handler...`, generated `.pb.gw.go`, HTTP mounting | Outer HTTP wrappers, gateway middleware/options in the resolved version, metadata forwarding and backend controls |
| Nirvana: `github.com/caicloud/nirvana` | Server/config construction, descriptors, route registration and startup in resolved source | Descriptor inheritance, filters and middleware; inspect version-specific APIs rather than guessing names |
| Beego: `github.com/astaxie/beego`, `github.com/beego/beego/v2` | Routers, namespaces, controllers, included/generated router files, run configuration | `InsertFilter`, filter positions, controller `Prepare`, namespace filters, exclusions and termination behavior |
| Echo: `github.com/labstack/echo` and versioned paths | Instance, groups, HTTP method registration, start/server mounting | Global/group/route middleware, pre-routing hooks, skipper conditions and handler return paths |
| Fiber: `github.com/gofiber/fiber` and versioned paths | App, groups, method registration, `Listen` | Registration-order `Use`, path matching, `Next`, group composition; do not assume Gin semantics |
| Chi: `github.com/go-chi/chi` and `/v5` | Router, `Route`, `Mount`, method handlers, HTTP server | `Use`, `With`, `Group`, mounted handlers and wrapper inheritance |
| Gorilla Mux: `github.com/gorilla/mux` | Routers, subrouters, path/host/method matchers, HTTP server | Router/subrouter middleware, parent match restrictions, alternate mounts |
| Hertz: `github.com/cloudwego/hertz` | Server construction, groups, methods, server startup | Global/group/route middleware and abort behavior in the actual version |
| go-zero: `github.com/zeromicro/go-zero` | REST/rpc servers, `.api` plus actual generated route registration | Registered middleware, route JWT settings, RPC interceptors and service-layer policies |
| Kratos: `github.com/go-kratos/kratos` and `/v2` | HTTP/gRPC transport servers, generated service registration | Transport middleware, operation selectors, matcher exclusions and downstream policy |
| Kitex: `github.com/cloudwego/kitex` | Generated service server constructors, server options, `Run` | Server middleware, endpoint wrappers, generic methods and service implementation checks |
| Connect-Go: `connectrpc.com/connect`, older `github.com/bufbuild/connect-go` | Generated handler constructors and HTTP mux mounts | HTTP wrappers, Connect interceptors, unary/streaming handling and protocol options |
| Cobra: `github.com/spf13/cobra` | Root/subcommands, `AddCommand`, `Execute`, `Run`/`RunE` | `PreRun`/`PersistentPreRun` variants, inherited hooks and error handling; check actual hook traversal settings |
| urfave/cli: `github.com/urfave/cli` and versioned paths | App/command construction, subcommands, `Run`, `Action` | `Before`, middleware/version-specific hooks, returned errors and action execution |
| Standard `flag`, Kong, Kingpin | Flag parsing or command model and executable dispatch | Command hooks and downstream checks; local invocation trust model |

Recognize other frameworks through source evidence. For each newly encountered
framework, identify registration semantics, nesting/mounting, enforcement hooks,
matching/exclusion rules and how denial prevents handler execution.

Do not assume a middleware method has identical ordering, inheritance or abort
semantics across frameworks or major versions. Record the implementation location
or the uncertainty whenever it affects a permission conclusion.
