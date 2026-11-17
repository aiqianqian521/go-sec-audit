# Sink 规则对照表

每条规则对应 `scripts/scan_sinks.py` 的 `RULES`。ID 稳定，改动规则时同步改这里。

**读法**：规则只回答"值得看一眼"，不回答"有漏洞"。每条给三件事：匹配什么、真阳性长什么样、噪声长什么样。

---

## E1 命令拼接

### `E1-SHELL-C` (critical)
- **匹配**：`exec.Command` / `exec.CommandContext` 的调用文本里同时出现 shell 名（sh/bash/zsh/dash/ash/ksh）与 `-c`
- **真阳性**：`exec.Command("sh", "-c", "cat /reports/"+name)`，`name` 来自请求
- **噪声**：~~`exec.Command("sh", "-c", "nginx -s reload")` 常量脚本~~
  **（2026-11-16 压力测试修正：常量脚本已被规则 `none_of` 直接排除，实测不进候选，
  纯字面量白占 critical 的形态在 760k LOC 回归时已修掉）**；
  残余噪声 = `exec.Command("bash", "-c", script)` 其中 `script` 是变量但内容为仓库内置配置
  ——规则看不见数据流，这类才需要人工判 KILL
- **判据**：脚本串里含用户数据吗？含 `shellescape.Quote` 了吗？

### `E1-SHELL-EXPR` (high)
- **匹配**：任意名字里带 `Command`/`Cmd` 的调用，含 `-c`，且 **`-c` 之后的实参不是字面量**（是变量、表达式或 `fmt.Sprintf(...)`）
- **为什么要单列**：`E1-SHELL-C` 要求 shell 是字面量，而真实代码里最常见的两种写法都绕开了它——
  ① `exec.Command(shell, "-c", script)`（shell 在变量里，来自配置/`step.Image`）；
  ② `newCmd(ctx, "/bin/sh", "-c", fmt.Sprintf(...))`（被包装函数转发，`exec.Command` 不在这行）
- **真阳性**：Woodpecker `pipeline/backend/local/command.go:182`、`clone.go:103`（实测两处都被命中）
- **噪声**：`script` 是常量（如 `probeShellIsPosix` 的探针脚本，字面量常量被赋给变量）；
  非 shell 的 `-c`（`git -c key=value`）
- **判据**：`-c` 后面那个表达式的**根**是什么？常量 → 降级；请求/配置 → 继续追。
  **注意**：规则只看形态不看数据流，命中等价于"这里有一个 shell 解释点"，不等于注入
- **已知漏检**：argv 在**别的函数里组装**再传进来的形态——
  `genCmdByShell` 返回 `[]string{"-e", "-c", script}`（`command.go:122`），
  调用方 `newCmd(ctx, shellPath, args...)`（`:60`）里根本没有 `-c` 字面量。这类必须靠 `--callers` 人工接


### `E1-SHELL-WIN` (critical)
- **匹配**：cmd/powershell/pwsh + `/c`|`/k`|`-Command`|`-c`
- **真阳性**：kubelet 类 —— 参数看似"分开传"，但 `cmd /c` 与 PowerShell 会二次解析字符串内的 `&`、`$()`、`|`
- **噪声**：`exec.Command("cmd", "/c", "ver")` 常量
- **判据**：被解析的 token 里有用户数据吗？即便作为独立 argv，Windows shell 仍会解释它

### `E1-STARTPROC` (high)
- **匹配**：`os.StartProcess`
- **真阳性**：argv 由 `strings.Fields(userCmd)` 构造
- **噪声**：固定 argv 启动子进程
- **判据**：argv 切片怎么来的

### `E1-CMD-INTERP` (high)
- **匹配**：字面量 shell 命令行紧跟 `+` 拼接
- **真阳性**：`"/bin/sh -c '" + userCmd + "'"` 整串拼接后交给某处执行
- **噪声**：日志里打印了一条命令字符串（不执行）
- **判据**：这串最终进没进 `exec`/`syscall`

---

## E5 参数注入

### `E5-GIT-OPT` (high)
- **匹配**：外部程序（git/hg/svn/pandoc/ffmpeg/tar/zip/rsync/curl/wget/ssh）+ 拼接或已知危险 flag
- **真阳性**：`exec.Command("git","clone","--upload-pack="+u)`；`exec.Command("git","clone",u)` 且 `u` 以 `-` 可控（规则抓不到，靠 `E5-ARG-NONCONST`）
- **噪声**：`exec.Command("git","log","--oneline", "-n", "10")` 全常量
- **判据**：危险选项清单 —— git: `--upload-pack` `--receive-pack` `-c core.sshCommand` `-c core.pager`；tar: `-I` `--to-command`；ssh: `-o ProxyCommand`；pandoc: `--filter` `--lua-filter`；rsync: `-e`

### `E5-ARG-NONCONST` (low)
- **匹配**：程序名之后的实参是**裸标识符**（不是字面量、不是字面量前缀拼接）
- **真阳性**：`exec.Command("git", "clone", userRef)` —— `userRef="-c core.pager=id"` 不成立（git 的 `-c` 必须在子命令前），但 `"--upload-pack=..."` 成立
- **噪声**：`exec.Command("cat", filename)` —— `filename` 以 `-` 开头最多让 `cat` 读别的文件，不升级为执行
- **判据**：这个程序有没有"把参数值当命令跑"的选项。没有 → 降级

> 这条规则故意设成 `low`：它的目的是让人看一眼参数位置，不是报警。

---

## E2 模板

### `E2-FUNCMAP-EXEC` (critical)
- **匹配**：`.Funcs(` 里注册的键名像 exec/run/shell/cmd/system/readfile/writefile，或值来自 `os.`/`exec.`/`syscall.`
- **真阳性**：`{"run": func(c string) string { exec.Command("sh","-c",c) ... }}` —— 模板里 `{{ run "id" }}`
- **噪声**：`{"upper": strings.ToUpper}`；`{"now": time.Now}`
- **判据**：把每个 FuncMap 键的实现读一遍。**模板可能完全固定，门仍然开着**（若模板文件可写 → 转 E4）
- **已知漏检（2026-11-16 压力测试）**：FuncMap 作为独立 `var` 定义、在别处
  `.Funcs(fmap)` 注册时，本规则锚不到键名——由 `E2-FUNCMAP-DEF` 兜住（见下）

### `E2-FUNCMAP-DEF` (critical) — `scope=func`（2026-11-16 新增）
- **匹配**：`FuncMap{` 字面量（不要求 `.Funcs(` 在场），函数/顶层作用域内出现
  执行类键名（`"run":`、`"exec":`…）或键值紧跟 `exec.`/`os.`/`syscall.`
- **为什么要单列**：真实代码里 FuncMap 常独立成 var、注册点与定义点分离，
  `E2-FUNCMAP-EXEC` 的锚只看调用点
- **真阳性**：`var fmap = template.FuncMap{"run": func(c string){ exec.Command("sh","-c",c) }}`
- **噪声**：键全为纯函数（`upper`/`printf`）；同文件无关的 `x := exec.Command`
  不构成键名（`:=` 不匹配 `:\s*exec\.`）
- **判据**：同 E2-FUNCMAP-EXEC——读每个键的实现；负样本 `neg_e2_funcmap_benign.go.txt`

### `E2-TPL-USERSTRING` (high)
- **匹配**：`Parse`/`ParseFiles`/`ParseGlob` 的唯一实参不是字符串字面量
- **真阳性**：`template.New("x").Parse(r.FormValue("tpl"))`
- **噪声**：`ParseFS(embedFS, "*.tmpl")`；`ParseFiles("a.tmpl","b.tmpl")` 多参（`first_arg_is_literal` 只跳过单参，多参场景需人工看）
- **历史噪声（2026-11-13 已修）**：`time.Parse` / `url.Parse` / `schema.Parse` / `ini.Parse`
  曾被当模板求值。gogs 的 21 条 Tier A 里 18 条是这类，alist 40 条里 27 条是这类。
  根因不只是正则宽——扫描器原先的 `target` 只取 `(` 之后的调用体，`none_of` 看不到 `time.`
  这个前缀，所以**第一版修复无效**。修法是 `scope="callee"` + 排除 22 个非模板包。
  负样本 `assets/selftest/neg_e2_time_parse.go.txt`。
- **判据**：实参能否被请求影响？不能则降级

### `E2-SPRIG` (high)
- **匹配**：`sprig.TxtFuncMap` / `GenericFuncMap` / `HermeticTxtFuncMap`
- **真阳性**：模板可控 + sprig 的 `env`/`expandenv` → 泄漏密钥；配合 Helm `tpl` 可递归求值
- **噪声**：模板固定、数据固定
- **判据**：sprig 本身不执行命令，是放大器不是起点

### `E2-TPL-CALL` (medium)
- **匹配**：模板源码里出现 `{{ ... call ... }}`
- **真阳性**：`{{call .Cmd "id"}}`，`.Cmd` 是传入的函数值
- **噪声**：`call` 作为普通字段名
- **判据**：能不能控到被 call 的函数值

---

## E3 反序列化

> 这一相的所有规则都只是"入口"，**单独都不构成 RCE**。必须接下游用途。

### `E3-GOB-NET` (high)
- **匹配**：`gob.NewDecoder(` 且实参涉及 `.Body` / `conn` / `Accept()` / `PostBody`
- **真阳性**：`gob.NewDecoder(r.Body).Decode(&job)` —— 先看 DoS（长度前缀预分配），再看 `job` 字段去向
- **噪声**：解码本地文件、解码自己刚编码的内存缓冲
- **判据**：解码结果去哪了

### `E3-SESSION-DECODE` (high)
- **匹配**：`securecookie.Decode` / `sessions.NewCookieStore` / 引 `gorilla/sessions`
- **真阳性**：key 硬编码在仓库 → 伪造 cookie → 提权 → 接 E4
- **噪声**：key 来自环境变量且长度足够、`MaxAge` 合理
- **判据**：key 可预测吗？伪造后能拿到什么权限？权限能干什么？

### `E3-YAML-IFACE` (low)
- **匹配**：`yaml.Unmarshal` 到 `interface{}` / `map[string]interface{}`
- **真阳性**：解出来的 map 被反射塞进配置，配置里有 `command` 字段 → E1
- **噪声**：配置加载（本地文件，非请求）
- **判据**：来源是不是请求；解出来的值有没有进执行路径

---

## E4 写入即执行

> 这一相最容易被漏，因为**不含 exec**。四个条件缺一不可：路径可控/位置固定 + 内容可控 + 权限 + 下游执行者。

### `E4-HOOK-WRITE` (critical) — `scope=func`
- **匹配**：写文件类调用所在的**函数体**内出现 `hooks/`、`.git/`
- **真阳性**：`filepath.Join(repo, ".git", "hooks", "post-merge")` + `os.WriteFile(..., 0755)`
- **噪声**：读 hooks 目录做展示；写入后立刻删除且无执行
- **判据**：写入路径能否 `..` 逃逸到 `.git/hooks`；内容是否含用户数据；谁触发 git

### `E4-EXECPATH-WRITE` (critical) — `scope=func`
- **匹配**：写文件 + 函数体内出现 crontab/cron、authorized_keys、.bashrc/.profile/.zshrc、systemd、.ssh、bin
- **真阳性**：`os.WriteFile("/etc/cron.d/x", []byte(userCron), 0644)`
- **噪声**：写入 `~/.ssh/known_hosts`（不执行）；写日志到 `bin/` 下的名字但不是可执行文件
- **判据**：落点是否被系统/解释器读取并执行

### `E4-ZIPSLIP` (high)
- **匹配**：`zip.NewReader` / `tar.NewReader` / `archiver.Unarchive|Extract` / `ExtractAll(` / `ExtractTo(`
- **已知漏检（2026-11-16 压力测试）**：reader 经**函数参数**传入（`func unzip(dst string, zr *zip.Reader)`）
  时锚不到 `zip.NewReader`，本规则不命中——靠 `X-PATHTRAV-JOIN` 对
  `os.Create(filepath.Join(dst, f.Name))` 的唤醒兜底。判读解压函数以 X 判据为准，
  不因 ZIPSLIP 未命中就写"无解压风险"。
- **真阳性**：`os.Create(filepath.Join(dst, hdr.Name))`，`hdr.Name = "../../etc/cron.d/x"`
- **噪声**：解压到临时目录且不校验（影响有限）；已做 `filepath.Clean` + 前缀校验
- **历史噪声（2026-11-13 已修）**：原正则写作 `Extract(?:All|To)?`，问号让分组可选，
  退化成"匹配任何叫 `Extract` 的词"。alist 的 22 条 Tier B **全部**是
  `func (d *Gofile) Extract(...)` 这类云盘驱动方法定义，cloudreve 18 条同理。
  教训：**方法名不是规则**——`Extract` 在文件服务类项目里是接口方法名，不是解压动作。
  修法是去掉可选分组，只匹配 `ExtractAll(` / `ExtractTo(` 与真正的归档 reader。
  负样本 `assets/selftest/neg_e4_extract_iface.go.txt`。
- **判据**：目标目录是否可执行位置；有无 `..` 校验
- **新判据（Go ≥ 1.24）**：解压根是 `os.OpenRoot(dst)` 得到的 `*os.Root`，随后的
  `root.OpenFile(header.Name, ...)` 走内核级 `RESOLVE_BENEATH`，`../` 直接返回错误。
  **见到 `os.OpenRoot` 就是结构性修复，不必再找 `Clean`+前缀校验**。
  实例：Woodpecker `cli/update/tar.go:35`（`root, err := os.OpenRoot(dst)`）→
  同一个 `UnTar` 因此不可能 zip slip，尽管它完全没做字符串校验

### `E4-PLUGIN-DIR` (high)
- **匹配**：路径里出现 `plugin`/`plugins` 目录，或 `plugin.Open`
- **真阳性**：上传 → 落在插件目录 → 下次加载
- **噪声**：只是命名空间叫 plugins，实际存的是配置
- **判据**：目录内容会被加载吗

---

## E6 动态加载

### `E6-PLUGIN-OPEN` (high)
- **匹配**：`plugin.Open(` 且实参非字符串字面量
- **真阳性**：`plugin.Open(r.FormValue("mod"))`
- **噪声**：`plugin.Open(fmt.Sprintf("plugins/%s.so", cfg.Name))` 且 `cfg` 来自本地配置文件
- **判据**：路径可控 + 文件可写 + 构建启用 CGO（`go env CGO_ENABLED`，且 plugin 只支持 Linux）

### `E6-SYSCALL-EXEC` (high)
- **匹配**：`syscall.Exec(`
- **真阳性**：`syscall.Exec("/bin/sh", []string{"sh","-c",user}, env)`
- **噪声**：容器 init 进程切换（常量路径、自举场景）
- **判据**：路径与 argv 来源

### `E6-REFLECT-CALL` (low)
- **匹配**：`.MethodByName(` / `.Call(` / `.CallSlice(`
- **真阳性**：插件式路由 `obj.MethodByName(cmd).Call(args)`
- **噪声**：ORM/序列化库内部反射
- **判据**：方法名可控吗

### `E6-CGO` (low)
- **匹配**：`#cgo` 或 `import "C"`
- **用途**：标记内存安全假设在此失效，且 `plugin` 需要 CGO。不是漏洞信号
- **判据**：仅作为上下文

---

## X 辅助信号（不是 RCE）

### `X-PPROF-EXPOSED` (low)
- **匹配**：`net/http/pprof`
- **用途**：`/debug/pprof/` 暴露常是链前侦察（goroutine 栈泄漏路径、堆泄漏数据）。`/debug/pprof/symbol` + 大内存可 DoS
- **判据**：是否绑定到公网监听
- **必须额外查一步（2026-11-16 实测评）**：本规则**看不见路由中间件**。
  Woodpecker 的 6 条命中全部落在 `server/api/debug/debug.go`，而
  `server/router/api.go:273` 是 `debugger.Use(session.MustAdmin())`，且整组路由
  只在 debug 日志级别挂载 → 6 条是误报。
  **判据补充**：先 grep 该 handler 的注册点，找 `Use(...)`/`Group(...)` 上的鉴权；
  没有鉴权中间件才继续

### `X-NETRPC` (low)
- **匹配**：`net/rpc` / `rpc.NewServer`
- **用途**：net/rpc 默认 gob 编解码 → 等价 E3 入口，且默认无认证
- **判据**：服务暴露给谁

### `X-PATHTRAV-JOIN` (high)
- **匹配**：`os.Open / OpenFile / ReadFile / WriteFile / Create / Stat / RemoveAll` 的路径参数，**在同一函数内**由 `filepath.Join` 或 `path.Join` 拼接，且拼接项含变量（全字面量的 Join 已排除）
- **为什么要单列**：Go 的 RCE 极少能一步从输入走到 `exec`，但"任意文件写"几乎总能补成 RCE —— 写 git hooks（落 E4）、写模板（落 E2）、写 `authorized_keys`。所以路径穿越是 RCE 链最常见的**前半段**
- **判据 1（是否修复）**：Join 之后有没有 `filepath.Clean` **且**前缀校验（`strings.HasPrefix(clean, base)`）。**只有 Clean 没有前缀校验不算修复**，`../../` 依然能穿出去
- **判据 2（写侧能不能用）**：命中 `WriteFile/OpenFile/Create` 时，**必须往回看写入前有没有内容闸门**。典型反例 Gitea 1.4.0 `content_store.go:67-72`：先写 `<path>.tmp`，再比对 `sha256(content) == meta.Oid`，不等就删 tmp、不 Rename。此时**「路径可控」与「内容可控」互斥** —— 路径由 Oid 决定，Oid 又必须是内容的哈希。**见到"写临时文件 + 校验 + Rename"三段式，直接判为不可写任意文件**
- **判据 3（写侧残余副作用）**：即使内容闸门存在，`os.MkdirAll(dir)` 常位于闸门**之前**（Gitea 同函数 `:56`）→ **任意目录创建**仍成立。别把它写成"可写文件"，但也不要不写
- **判据 4（读侧能不能拿到字节）**：读 handler 若用 DB 里存的 `Size` 去 `Set("Content-Length", ...)`，而该 `Size` 是攻击者可控的，则**内容长度超过 Size 时会被 net/http 整块丢弃**（`http.response.Write` 超限返 `ErrContentLength`），表现为「200 + 0 字节」。排查顺序：先看 200 还是 404（200 说明 `os.Open` 成功），再核对 `Size` 与目标文件真实长度
- **实测**：Gitea 1.4.0 `modules/lfs/content_store.go:29`（`Get`）与 `:49`（`Put`）双命中 —— 读侧成立（未授权任意文件读），写侧被 sha256 闸门挡住


### `X-PATHTRAV-SLICE` (high)
- **匹配**：`filepath.Join(x[0:2], x[2:4], x[4:])` 这类用下标切片重组路径的写法
- **为什么必须单列**：切片看起来像"取固定长度前缀做分片目录"，审查者容易判定安全。但**切片结果本身可以含 `..`**，而父级校验通常只做一次、做的事是"确认前 4 个字符是十六进制"这类形式检查
- **实测**：Gitea 1.4.0 `transformKey()`：
  ```go
  if len(key) < 5 { return key }                      // 短 key 完全不处理
  return filepath.Join(key[0:2], key[2:4], key[4:])   // 无 .. 校验
  ```
  攻击者传 `....../../../../etc/passwd`：前 4 个点被吃成两级目录，剩下的照常穿越。**这也解释了 vulhub payload 里那个奇怪前缀的由来**——不是填充，是给切片函数喂参数

---

## 不在规则里、但必须人工看的三类

1. **生成代码**：`*.pb.go`、`*_gen.go`、`wire_gen.go`。规则会扫到，但改不动源码，要在报告里注明"生成物，修复在上游 .proto/idl"。
2. **构建标签文件**：`//go:build linux` 的文件在你当前机器上不参与编译。要么看 CI 的构建矩阵，要么显式说明"未覆盖该平台"。
3. **`vendor/`**：默认跳过。若项目 vendored 了自己 fork 的库（改过源码），必须 `--include-vendor` 重跑，否则报告对 vendor 不构成任何结论。

## 人工 grep 补充（跑一遍，防规则盲区）

```bash
rg -n 'sh", "-c|bash", "-c|/c", |-Command' -t go
rg -n 'hooks/|hooks\\\\|\.git/hooks|authorized_keys|cron\.d|crontab' -t go
rg -n 'Funcs\(|FuncMap\{|ParseFiles|ParseFS|plugin\.Open|syscall\.Exec' -t go
rg -n 'http\.ListenAndServe|gin\.Default|echo\.New|fiber\.New' -t go   # 入口面
```

正则不是扫描器。它只用来确认"扫描器没扫到的地方，我亲自看过"。
