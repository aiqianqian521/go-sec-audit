# 路线图：拿到一个 Go 项目后先看哪里

本文件解决的是**顺序**问题，不是知识问题。六相（E1–E6 + X）告诉你漏洞有哪些形态，
但真实项目的候选动辄上百条，决定效率的是"先排除哪 90 条"。

原则：**先证伪，再证实**。每一条路线都设计成"能在 5 分钟内被判死"，而不是"能在 5 分钟内被确认"。

**校准数据（2026-11-13，10 个真实项目 / 760k LOC / 586 命中）**：密度 0.77 命中每千行；
其中 Tier S 14 条（2.4%）、Tier A 16 条（2.7%），**S+A 合计只有 5.1%**；
而命中数最多的三条规则（E2 模板 40%、X 路径 22%、E6 反射 15%）恰好最不可直接利用。
**按命中数排序 = 按噪声排序**，这是本文件存在的全部理由。

---

## 0. 三条硬顺序（违反任何一条，后面全是白做）

1. **路由注册 → 认证态 → sink**。顺序不能反。
   未注册的 handler（配置开关关掉、build tag 排除、插件没启用）里写什么都是死代码。
   实测教训：Gitea 1.4.0 的 LFS 全套 handler 都在，但 `LFS.StartServer=false` 时路由压根不注册，
   所有请求 404 —— 我先猜了三轮才发现是 git 版本闸门。
2. **先确定部署形态，再谈影响**。`FROM scratch` / distroless 镜像里**没有 `sh`**，
   E1 类 payload 在源码层完全成立、在运行时直接失败。同理：非 root、只读 rootfs、seccomp。
3. **没有"入口"的 sink 不进正文**。库函数被 40 个包调用但没有任何一个是从请求数据流过来的，
   它的等级是 L0，写进正文会稀释整份报告。

---

## 1. 框架指纹 → 直接跳到路由文件

| 指纹（grep 这些） | 框架 | 路由注册通常在哪 | 认证中间件在哪 |
|---|---|---|---|
| `http.HandleFunc` / `http.ListenAndServe` / `http.ServeMux` | net/http | 与 handler 同文件，散落 | 无统一层，**每个 handler 自己判断**（最危险） |
| `gin.Default()` / `.GET(` / `.Group(` / `.Use(` | gin | `router/`、`routers/`、`internal/router` | `.Use(...)` 链，注意 group 级 `Use` 只作用于该组 |
| `echo.New()` / `e.Group(` / `e.Use(` | echo | 同上 | 同上；`e.Group("/api", mw)` 的 mw 只在其内 |
| `chi.NewRouter()` / `r.Route(` / `r.Group(func(r chi.Router)` | chi | `routes.go`，常在 `func Routes()` 里 | `r.Group` 内 `r.Use(auth)`，**组外端点默认无认证** |
| `macaron.Classic()` / `m.Get(` / `m.Group(` | macaron（Gitea/Gogs ≤1.9） | `routers/routes/routes.go` | `m.Use(...)` 全局 + `reqSignIn` |
| `app.Get(` / `app.Use(` | fiber | `main.go` 集中 | 全局 `Use`，注意顺序 |
| `web.Router("...", &ctrl{}, "post:Method")` | beego | `routers/router.go` | `web.InsertFilter` |
| `mux.HandleFunc(...).Methods(` / `r.Handle(` | gorilla/mux | 分散 | 无统一层 |

**判定动作**：`grep -rn "\.Use(\|\.Group(\|Middleware\|RequireSignIn\|BasicAuth\|csrf" --type go | head -40`
- 有全局 `Use`：把"需要认证"当默认，重点找**显式排除**的端点（白名单、`/api/public`、webhook、登录页）
- **找不到统一中间件**：全部按"未授权"算，这是效率最高的一种项目

**优先看这些端点**（未授权概率从高到低）：
公开注册/登录/找回密码 → webhook 接收 → 文件上传/下载 → 导入（URL/包/仓库）→ 预览/渲染 → 导出 → 健康检查/调试 → 静态资源处理器

---

## 2. 入口形态 → 优先相（这一步决定 80% 的走向）

| 入口特征 | 优先查 | 为什么 | 一句话证伪 |
|---|---|---|---|
| 调外部命令（git/tar/zip/ffmpeg/rsync/7z） | **E5** | 参数拼进 argv 时，用户控制的一个 `--upload-pack=…` 就够 | argv 里所有用户可控项前面都有字面前缀或 `--` |
| `exec.Command("sh"/"bash"/"cmd"/"powershell", …)` | **E1** | 唯一"直接"形态 | 参数是分开传的 `[]string`，且**目标平台不是 Windows** |
| 模板文本来自用户 / FuncMap 含 os、exec、readfile | **E2** | Go SSTI 多为 shadow vuln，无 CVE | 模板字面量固定 + FuncMap 纯函数 |
| 能写文件（上传、解压、checkout、patch、备份还原） | **E4** | 写对位置就执行，全程可以没有 `exec` | 写入目录下没有任何执行者（hook/cron/webroot/plugin/模板） |
| 解码（gob/yaml/cookie/session/pickle-lite） | **E3** | 解码本身永不执行，必须看解码结果的用途 | 结果只做展示/比较，不进命令、不进路径、不进权限判断 |
| 加载（`plugin.Open`、`dlopen`、扩展、解释器内建 LOAD） | **E6** | 目标可控就是代码加载 | 路径为字面量或签名校验 |
| 纯数值/ID/枚举参数 | 跳过 | 除非进入上述任一路径 | — |

**注意"标签 ≠ 相"**：CVE-2024-9264 标签是 SQL 注入，实质是 E6（能 `LOAD` 扩展的解释器）；
CVE-2026-60004 全程没有 `exec.Command`，是纯 E4。**按标签审计会给出错误的修复建议。**

**同样，"方法名 ≠ 规则"**（2026-11-13 盲测教训）：`Extract` 在文件服务类项目里是驱动接口的方法名，
不是解压动作；`Parse` 在时间/URL 场景里是格式化，不是模板求值。规则一旦退化成"匹配一个常见单词"，
Tier A/B 就会被灌满——实测 alist 的 22 条 Tier B 全部是 `func (d *X) Extract(...)` 定义。
**Tier A/B 命中率突然偏高时，先怀疑规则，再怀疑项目。**

---

## 3. 危险函数按"可执行性半径"排序

扫描器命中后按这张表排序，Tier S/A 花时间，Tier C 只在有明确下游时才看。

| Tier | 形态 | 代表符号 | 到 RCE 的距离 |
|---|---|---|---|
| **S** | 直达执行 | `exec.Command("sh","-c",…)`、`exec.Command(<变量>, "-c", <表达式>)`（规则 `E1-SHELL-EXPR`，含 `newCmd(...)` 这类包装）、`syscall.Exec`、`plugin.Open(变量)`、`os.StartProcess` | 1 跳 |
| **A** | 间接执行 | `exec.Command("git"/"tar"/"rsync", 用户参数…)`、`template.Parse(用户串)`、`Funcs(map 含 exec)`、`text/template` 渲染用户模板 | 1–2 跳，且需要环境配合 |
| **B** | 写入执行位 | `WriteFile`/`Create`/`OpenFile`/`Rename` 落在 `hooks/`、`cron.d`、`authorized_keys`、`webroot`、`.git/config`、插件目录 | 等一次外部触发 |
| **C** | 解码/反射 | `gob.Decode`、`yaml.Unmarshal`、`json.Unmarshal`（仅当结果被当命令/路径/权限用） | 3+ 跳，多数是假阳 |
| **X** | 前置原语 | `filepath.Join` 无前缀校验、路径参数未净化、`filepath.Join(x[0:2],…)` | 本身不是 RCE，是链的前半段 |

**Tier B 的判定要求**：必须写出"谁在什么时机执行这个目录下的文件"。
写不出执行者 → 降到 L0。`hooks/` 有 git 执行、`cron.d` 有 cron、`authorized_keys` 有 sshd；
写到 `data/` 或 `uploads/` 下面通常没人执行，别硬编一个。

---

## 4. 三十五分钟标准路线

| 阶段 | 分钟 | 动作 | 产出 | 什么时候直接放弃 |
|---|---|---|---|---|
| T0 范围 | 5 | `go.mod` 版本、框架、部署形态（Dockerfile）、是否公开注册 | 一页事实卡 | 项目是库，无入口 → 只出 L0 附录 |
| T1 入口 | 10 | 找路由注册文件，标出**无认证**端点 | 端点清单（URL + 参数名） | 找不到任何路由（CLI/守护进程）→ 转 CLI 入口重新做 T1 |
| T2 候选 | 10 | 跑扫描器 + 三条 `rg` 兜底，只看 Tier S/A | 候选清单（带 path:line） | 扫描器 0 命中且 `rg` 也 0 → 记"未命中"，不写"安全" |
| T3 通链 | 5/条 | 每个候选写：入口→参数→变换链→闸门 | L1 或降级理由 | 闸门清单里命中任一条且无法绕过 → 降级并记录 |
| T4 注入性 | 5/条 | 写具体 payload 串 + 必须存活的字符 | L2 | 字符在某跳被剥离 → 退回 L1 |

L3 只在"能编译 + 能起服务 + 有隔离环境"时做；做不了就明写"未复现"，不要用"应该可以利用"替代。

---

## 5. 已知闸门清单（把"看着像"变成"打不通"的东西）

命中任一条就必须在报告里写出**闸门位置**，否则结论站不住：

| 闸门 | 表现 | 识别方法 |
|---|---|---|
| 路由未注册 | 请求 404，源码里 handler 齐全 | 搜配置开关（`if cfg.XxxEnable`、`m.Group` 的条件）、build tag |
| 版本闸门 | 功能整体关闭 | 启动日志里的告警、`setting.go` 里的版本比较（Gitea 的 git ≥ 2.1.2 即此） |
| 内容闸门 | 写进去但被删/不落盘 | "写临时文件 → 校验 → Rename"三段式（sha256 必须等于文件名） |
| 长度闸门 | 响应 200 但 0 字节 | handler 用入参/DB 里的 `Size` 设 `Content-Length` |
| shell 缺失 | 源码成立，运行时失败 | 镜像 `FROM scratch`/distroless；`sh` 不在 PATH |
| 权限 | 写不进 / 读不到 | 服务账号、目录 mode、只读 rootfs |
| 参数白名单 | 注入字符被剥离 | 找 `--` 分隔符、前导 `-` 拒绝、正则白名单 |
| 沙箱 | 系统调用被拒 | seccomp/AppArmor 配置、容器 `--security-opt` |
| 认证态 | 根本不是未授权 | 读**注册处**的中间件，不是读 handler 内部 |

---

## 6. 输出：把路线写进报告

每个候选一行，缺列就说明没做到：

```
F1 | E5 | repo/import.go:118 | POST /repo/import (未认证) | 参数: clone_addr
   | 链: handler → models.Migrate → git clone <url> (argv 拼接) | 闸门: 无
   | 等级: L2 | 存活字符: 空格 / `-` / `/`
```

以及**必须有一节 Rejected**，写清哪条被什么闸门挡掉。只有"确认漏洞"的报告，
读者无法区分你是查过了还是没想到。
