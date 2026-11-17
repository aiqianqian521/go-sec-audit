# 可达性：Go 里怎么从入口追到 sink

扫描器只给出"某个函数里有 sink"。真工作是回答：**谁能调到这里，带什么数据**。

Go 有个好处：没有 Spring 那种隐式绑定，调用链通常 2–5 跳。也有坏处：下面这些写法会让朴素污点追踪直接失效。

---

## 1. 先建入口面清单（别从 sink 开始）

从路由注册往下看，比从 sink 往上猜快 10 倍。

```bash
rg -n 'HandleFunc|Handle\(|\.GET\(|\.POST\(|\.PUT\(|\.DELETE\(|\.Group\(' -t go
rg -n 'grpc\.NewServer|Register.*Server\(' -t go
rg -n 'cobra\.Command\{|flag\.' -t go
rg -n 'cron\.|time\.Ticker|fsnotify' -t go
```

产出一张表：

| 入口 | 方法+路径 | handler | 中间件链 | 认证状态 |
|------|-----------|---------|----------|----------|
| `routers/api/v1/repo/patch.go:31` | POST `/repos/:id/diffpatch` | `ApplyDiffPatch` | `repoAssignment` → `ReqRepoWriter` | 任意登录用户 |

**认证状态比 sink 更重要。** 未认证可达 + E4 = 严重；仅管理员可达 + E2 = 通常不是漏洞（管理员本就能改配置）。

判断鉴权不要只读 handler 内部，要读**注册处**：

```go
auth := r.Group("/api", middleware.Auth())   // 这一层的 Use 决定下面全部
auth.POST("/repos/:id/diffpatch", handler)    // 继承 auth
```

若 handler 挂在上层 `r` 上而非 `auth` 上，就是未认证。

---

## 2. 反向追：sink → 入口

扫描器已经给了每个 sink 函数的 3 个调用点（报告 C 节）。手工继续：

```bash
rg -n '\bWriteHook\(' -t go          # 谁调它
rg -n 'func WriteHook' -t go         # 它的签名（参数类型决定能传什么）
```

判读调用点实参，只分三类：
- **常量**：`WriteHook("post-merge", tmpl)` → 这条路径死
- **配置**：`WriteHook(cfg.HookName, ...)` → 追配置来源（文件？环境变量？API 可改？）
- **请求数据**：`WriteHook(r.FormValue("x"), ...)` → 活的

---

## 3. 七个会让追踪失效的 Go 写法

### 3.1 interface 动态派发
```go
type Runner interface{ Run(ctx context.Context, spec Spec) error }
```
`sink` 在某实现里，调用点只看到接口。必须找全实现：
```bash
rg -n 'func \([a-z]+ \*?\w+\) Run\(' -t go
```
漏掉实现 = 漏掉路径。报告里写明"接口有 N 个实现，逐一检查"。

### 3.2 中间件重排与短路
```go
r.Use(Auth(), RateLimit())
r.POST("/x", h)
```
`Auth()` 里 `c.Abort()` 的路径不可达；`c.Next()` 之后的代码在 handler 返回后才跑。Echo/Fiber/gin 语义不同，别套用。

### 3.3 goroutine 闭包捕获
```go
for _, job := range jobs {
    go func() { exec.Command("sh","-c", job.Cmd).Run() }()   // job 被捕获
}
```
扫描器看到 sink 在匿名函数里，函数名是 `func1`，调用点找不到。这类**必须人工读**：`job.Cmd` 从哪来。

### 3.4 回调注册表
```go
var handlers = map[string]func(string) error{"export": exportCmd}
fn := handlers[r.URL.Query().Get("action")]
fn(r.FormValue("arg"))
```
键可控 → 目标函数可控。追表里每个 value 的实现，而不是追调用链。

### 3.5 反射与 struct tag
```go
reflect.ValueOf(obj).MethodByName(action).Call(args)
```
方法名可控 = 任意方法调用。列出目标类型的**导出方法**，找其中有副作用的。

### 3.6 生成代码
`*.pb.go` / `*_gen.go` / `wire_gen.go` 里的 sink 不能直接改，修复在 `.proto` 或生成器模板。报告要写"生成物，源头在 X"，否则开发改完重新生成又回来了。

### 3.7 构建标签
```go
//go:build linux && cgo
```
这个文件在 Windows 上不参与编译。你在 Windows 上看代码，看到的不是线上编译的东西。
```bash
rg -n '^//go:build|^// \+build' -t go
```
报告里必须声明"当前审计覆盖的平台/标签组合"，否则"未发现问题"这句话无意义。

---

## 4. 数据形态判定（sink 处的最后一米）

到了 sink，只看这一行不够，往回找**最后一次变换**：

```go
name := r.FormValue("f")            // 原始
name = filepath.Base(name)          // 只剩文件名 → 路径穿越死
name = strings.TrimSuffix(name,".txt")
cmd := exec.Command("sh","-c","cat "+name)   // 仍然 E1，因为 Base 不防 shell 元字符
```

判据表：

| 变换 | 挡住什么 | 挡不住什么 |
|------|---------|-----------|
| `filepath.Base` | 路径穿越 | shell 元字符、`-` 开头 |
| `filepath.Clean` + 前缀校验 | 路径穿越 | shell 元字符 |
| `strconv.Atoi` 成功 | 一切字符串注入 | 数值边界问题 |
| 白名单枚举 `switch` | 一切 | 白名单本身有危险值 |
| `shellescape.Quote` | E1 注入 | E5 参数注入、路径穿越 |
| `html.EscapeString` | XSS | 一切 RCE 相 |
| `url.QueryEscape` | URL 注入 | 一切 RCE 相 |

**这张表是最容易出错的地方**：`html.EscapeString` 和 `url.QueryEscape` 在 RCE 语境里等于没做。

---

## 5. 写出可达性结论的格式

不要写"用户输入流入 exec"。要写：

```
entry   POST /api/repos/:id/hooks         routers/api/repo.go:44
auth    auth.Group 下，任意登录用户        routers/api/repo.go:12
hop1    c.PostForm("content") -> body      api/hooks.go:31
hop2    hookBody -> writeHook(body)        api/hooks.go:37
hop3    filepath.Join(repo,".git","hooks","post-receive")  hooks.go:41
sink    os.WriteFile(target, body, 0755)   hooks.go:41
valid   none（无 Clean、无前缀校验、无内容校验）
```

有 hop 编号、有 `path:line`、有 validation 结论。缺任一项就是 L0/L1，不能升 L2。

---

## 6. 常见"看起来可达但不可达"

- 函数没被任何地方调用（死代码）——`rg` 一下确认调用点数为 0
- 只在 `_test.go` 里被调用
- 只在 `//go:build ignore` 的工具文件里
- 被 `if false` / 编译期常量关掉
- 注册在未启用的路由组（feature flag 默认关）
- handler 存在但路由没注册（写完忘了挂）

最后一条在 Go 项目里比想象中常见。**先确认路由真的注册了**，再谈可达。
