# 漏洞关键词特征库（全类型）

**定位**：本文件是"唤醒层"。关键词只回答"这里值得看一眼"，不回答"这里有漏洞"。
判决归三层：**本文件判据 → 各维度方法论文件 → 证据门（L0-L3）**。

两条纪律（缺一不可）：

1. **关键词不是判决**。扫描器规则只覆盖 E/X 相（RCE 类，27 条，见
   [sink-catalog.md](sink-catalog.md)）；SQLi / SSRF / 越权 / 秘钥 / 内存类没有机械规则，
   靠本文件的 rg 关键词通道 + 人工追。命中 ≠ 漏洞，未命中 ≠ 安全。
2. **方法论文件优先于关键词**。每类的深读判据在对应方法论文件里（见每节"深读"），
   关键词只是入口。本方法论的核心教训：从应用行为出发做独立发现，
   不能把关键词表当完备清单。

用法：Phase 2 对目标树逐类跑 rg 命中，把命中记入候选表（C-###，来源标 `KW`），
再按每类判据裁决。三类人工必查盲区（生成代码 / 构建标签 / vendor）见
[sink-catalog.md](sink-catalog.md) 末节。
判读说明：关键词命中**注释行与字符串字面量是常态**（grep 型通道固有，测试标记、
文档注释都会被唤醒），判读时人工过滤；这不算通道缺陷，但**把注释命中写进报告**算。

---

## E1 命令拼接（shell 参与解析）

- **机械规则**：`E1-SHELL-C` / `E1-SHELL-EXPR` / `E1-SHELL-WIN` / `E1-STARTPROC` / `E1-CMD-INTERP`（扫描器覆盖）
- **补充关键词**（扫描器盲区）：
  ```bash
  rg -n 'CommandContext\(' -t go                       # CommandContext 包装点
  rg -n 'sh", "-c|/bin/sh|/bin/bash' -t go        # shell 路径变体
  rg -n '"-c"\s*,\s*\w' -t go                      # -c 后接标识符
  ```
- **真阳性**：`exec.Command("sh","-c", "tar czf "+userDir)`；shell 名藏在变量里（`step.Image`）
- **噪声**：全常量脚本；`shellescape.Quote` 包裹；位置参数传值
- **证伪**：argv 分开传且无 shell（→ 是路径穿越不是注入）；shell 串无用户片段
- **深读**：[six-paths.md](six-paths.md) §E1、[command-execution.md](command-execution.md)、[sink-catalog.md](sink-catalog.md)

## E5 参数注入（argv 变成选项）

- **机械规则**：`E5-GIT-OPT` / `E5-ARG-NONCONST`
- **危险选项清单**（判据的核心）：git `--upload-pack` `--receive-pack` `-c core.sshCommand`；
  tar `-I` `--to-command`；ssh `-o ProxyCommand`；pandoc `--filter` `--lua-filter`；
  rsync `-e`；find `-exec`
- **真阳性**：`exec.Command("git","clone", userURL)`，`userURL` 以 `-` 开头可控
- **噪声**：用户数据拼在字面量前缀后（`"/reports/"+n`）——不会变成选项，不是 E5
- **证伪**：目标程序没有"把参数值当命令跑"的选项 → 降级
- **深读**：[six-paths.md](six-paths.md) §E5、[command-execution.md](command-execution.md) §4

## E2 模板求值（SSTI）

- **机械规则**：`E2-FUNCMAP-EXEC` / `E2-TPL-USERSTRING` / `E2-SPRIG` / `E2-TPL-CALL`
- **补充关键词**：
  ```bash
  rg -n 'FuncMap\{|\.Funcs\(' -t go                 # 门在 FuncMap，不在 Parse
  rg -n 'goja|otto|starlark|cel-go|expr\.' -t go    # 嵌入式解释器（等价 FuncMap 审计）
  rg -n 'tpl\s*=|\.tpl|render.*template' -t go       # 模板文件从哪加载
  ```
- **真阳性**：`Parse(r.FormValue("tpl"))`；FuncMap 注册 `run/exec/readfile` 实现函数
- **噪声**：`time.Parse`/`url.Parse`（历史教训，已有负样本）；`ParseFS(embedFS,...)`；纯函数 FuncMap
- **证伪**：模板字面量 + FuncMap 全是 `upper/printf` 纯函数 → 删
- **深读**：[six-paths.md](six-paths.md) §E2、[template-injection.md](template-injection.md)

## E3 反序列化

- **机械规则**：`E3-GOB-NET` / `E3-SESSION-DECODE` / `E3-YAML-IFACE`
- **判据核心**：**解码本身不执行**。Go 无 gadget 链。问"解码结果被用作命令/路径/权限/加载目标了吗"
- **真阳性**：session key 硬编码 → 伪造身份 → 接 E4；解码结果进 `exec`
- **噪声**：解码本地文件；解码后只写日志/比较
- **证伪**：解码后无下游敏感用途 → 最多 DoS（gob 长度前缀预分配）
- **深读**：[six-paths.md](six-paths.md) §E3、[case-library.md](case-library.md) A1（三跳链正例）

## E4 写入即执行（grep exec 找不到的主流形态）

- **机械规则**：`E4-HOOK-WRITE` / `E4-EXECPATH-WRITE` / `E4-ZIPSLIP` / `E4-PLUGIN-DIR`
- **落点×下游执行者清单**（四个条件缺一不可，见 six-paths）：
  `.git/hooks`→git；`cron.d`/crontab→cron；`authorized_keys`→sshd；
  `.bashrc`/`.profile`→登录 shell；systemd→systemd；插件目录→应用；
  模板目录（热加载）→应用；`.github/workflows`→CI；`go.mod replace`→构建
- **真阳性**：Zip Slip 落到 `/etc/cron.d`；写 `.git/hooks/post-merge` 且内容含用户数据
- **噪声**：读 hooks 目录做展示；写入即删且无执行者
- **证伪**：**没有下游执行者 + 触发时机 = 只是任意文件写**。这是最可证伪的一条
- **深读**：[six-paths.md](six-paths.md) §E4、[file-transfers.md](file-transfers.md)（任意路径写 vs 任意内容写的区分）

## E6 动态加载

- **机械规则**：`E6-PLUGIN-OPEN` / `E6-SYSCALL-EXEC` / `E6-REFLECT-CALL` / `E6-CGO`
- **补充关键词**：`INSTALL EXTENSION` / `LOAD\s+\w+fs`（数据库扩展，Grafana CVE-2024-9264 形态）
- **证伪**：加载路径是常量 + 加载物不可写
- **深读**：[six-paths.md](six-paths.md) §E6、[case-library.md](case-library.md) A4

## X 路径穿越 / 任意文件读写（RCE 链的常见前半段）

- **机械规则**：`X-PATHTRAV-JOIN` / `X-PATHTRAV-SLICE`
- **修复识别**：`os.OpenRoot`（Go ≥1.24，结构性修复，见即降级）；
  `Clean`+前缀校验（只有 Clean 不算）；"写临时文件+校验+Rename"三段式（路径与内容互斥，见判据 2）
- **深读**：[sink-catalog.md](sink-catalog.md) X 节（判据 1-4 含 Gitea 1.4.0 实测）

---

## SQL 注入（无机械规则，纯关键词通道）

- **唤醒关键词**：
  ```bash
  rg -n 'fmt\.Sprintf.*(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER)' -t go -i
  rg -n '\.(Query|Exec|QueryRow)\([^)]*\+' -t go          # 拼接进执行调用
  rg -n '\.(Raw|Where|Order|Group|Having|Select)\([^)]*(\+|Sprintf)' -t go   # GORM/ORM 拼接
  rg -n 'Order\(\s*\w+\s*\)' -t go                        # 排序字段直传（占位符管不了标识符）
  rg -n 'gorm\.Expr|clause\.Expr|AllowGlobalUpdate' -t go
  ```
- **真阳性**：`db.Raw("SELECT * FROM t WHERE name = " + name)`；
  `Order(sortCol + " " + sortDir)`（标识符位置，绑定参数管不了）；延迟执行（存的查询片段后来被插值）
- **噪声**：`Where("name = ?", x)`（值绑定）；ORM debug 输出渲染出的字符串（不是真正发的 SQL）；
  拼接后调 `Prepare`（先把不可信文本拼进 SQL 再 Prepare 不恢复边界）
- **判据核心**：值位置 vs **标识符/片段位置**分开追。占位符只保护自己的位置。
  报告要写清插入点落在 SQL 语法的哪个位置（值/标识符/条件/排序/表名）
- **证伪**：攻击者片段只进值位置且正确绑定；转换错误被处理（`strconv.Atoi` 错误未忽略）
- **深读**：[sql-injection.md](sql-injection.md)、[sql-reference-notes.md](sql-reference-notes.md)

## SSRF（无机械规则，纯关键词通道）

- **唤醒关键词**：
  ```bash
  rg -n 'http\.(Get|Post|Head)\(' -t go
  rg -n 'NewRequest\(' -t go
  rg -n 'url\.Parse|ParseRequestURI' -t go
  rg -n 'webhook|callback|ReverseProxy|[Pp]roxy[Uu]rl' -t go -i
  rg -n '[Ff]etch(Url|URL|Remote|External)|Import(Data|File|URL|[Uu]rl)|\.Preview\(' -t go
  rg -n 'CheckRedirect|DialContext|ProxyURL|ReverseProxy' -t go
  ```
  > 教训（2026-11-16 压力测试）：裸 `import` 命中每个 Go 文件的 import 语句——100% 噪声
  > 的词不进关键词表；特征词必须带形态（`Import(Data|File|URL)`）排歧。
  > **改关键词必须跑 `assets/stress/stress_kwcheck.py` 回归**（对扫描器规则的同款纪律）。
- **真阳性**：请求体/配置里的 URL 直达 `client.Do`，且校验是子串匹配（`strings.Contains(host,"internal")`）；
  校验了原始 URL 但 `CheckRedirect` 后的目标没验；校验用的 resolver 和实际拨号的 resolver 不是同一个（check/use gap）
- **噪声**：固定字面量 URL，用户只控 path/query（固定 origin 不算目标控制）；
  `url.Parse` 只构造不派发（构造器≠dispatch，要找到真实 consumer）
- **判据核心**：到达的是**派发后的最终目标**（重定向逐跳验、解析后 IP 验、IPv6/十进制编码过一遍），
  且该目标类在应用策略里未被授权
- **证伪**：入口是授权的固定目标白名单；scheme 不被 client 支持
- **深读**：[ssrf.md](ssrf.md)、[io-template-reference-notes.md](io-template-reference-notes.md)

## 认证 / 越权（无机械规则，最依赖人工链路追踪）

- **唤醒关键词**：
  ```bash
  rg -n '\.Use\(|middleware' -t go              # 中间件链组装点
  rg -n 'session\.|GetCurrentUser|MustGet' -t go  # 身份提取点
  rg -n 'IsAdmin|isAdmin|role|tenant|owner' -t go -i
  rg -n 'ctx\.Param\(|FormValue|PostForm' -t go   # 调用方可控 ID 进入数据操作
  rg -n 'http\.Error\([^)]*40[13]|StatusUnauthorized|AbortWithStatus|unauthor' -t go -i
  # ↑ 装饰化形态：特征不在名字在控制流——401/403 写完响应后有没有 return/Abort
  ```
- **真阳性**（三类，判据完全不同）：
  1. **功能越权**：普通已验证用户能调敏感操作（下游 service 层也没拦）
  2. **数据越权（IDOR）**：`ctx.Param("id")` 直接进查询，缺"验证主体→资源归属"关系
  3. **鉴权装饰化**：`requireAuth` 写了响应但**没 return/没 Abort**，函数继续执行
     ——Gitea 1.4.0 `server.go:221` 与 Woodpecker `org.go:127`（`if user == nil` 在使用之后）都是这一类
- **噪声**：handler 无检查但**下游 service/DB RLS 有**（报告"缺守卫"前必须读到那一层）；
  公开端点；前端隐藏按钮
- **判据核心**：按"入口→有效中间件→handler→service→数据操作"重建**实际执行顺序**，
  中间件名字带 Auth 不等于拦住了（要验失败语义：写 403 后代码停不停）
- **证伪**：验证过的主体到资源存在等价归属控制（不要求非得是 `owner_id` 比较）
- **深读**：[authorization.md](authorization.md)、[capability-assessment.md](capability-assessment.md)（k8s/控制面）

## 凭据 / 秘钥（高频低门槛类）

- **唤醒关键词**：
  ```bash
  rg -n 'NewCookieStore\(\[\]byte|NewHMAC\(\[\]byte|\[\]byte\(".*"\)' -t go   # 硬编码 key
  rg -n 'SECRET|API_KEY|TOKEN\s*(:=|=)\s*"' -t go -i
  rg -n 'expandenv|getenv' -t go        # 模板内环境变量展开（sprig）
  rg -n 'net/http/pprof|debug/' -t go   # 侦察面（X-PPROF-EXPOSED 配套）
  ```
- **判据核心**：硬编码 key 要写清**伪造后能拿到什么权限、权限能干什么**（接 E3/E4），
  不是"有个 key"就完事
- **脱敏反例（必须追到消费点再定级）**：`Secret.Copy()` 之类不复制 `Value` 字段的模式，
  意味着明文不出 HTTP。不追消费点直接报 High 是典型误报（Woodpecker `model/secret.go:112` 实测）
- **深读**：[case-library.md](case-library.md) A1（key→伪造→提权链）

## 不安全内存 / panic 面

- **唤醒关键词**：`unsafe.Pointer` / `uintptr` / `import "C"` / `reflect.SliceHeader` / `syscall.Mmap`
- **真阳性**：unsafe 转换 + 长度来自不可信输入；cgo 缓冲区契约不匹配
- **噪声（高频）**：普通 nil 解引用 panic → `gin.Recovery()`/net/http recovery → 500。
  这是 **DoS/可用性问题**，不是内存破坏，单独分类报告（Woodpecker F-001 实测：
  `session.User(c)` 返回 nil → 立即 `ForgeFromUser(user)` 取字段 → panic）
- **判据核心**：区分"越界原生访问 / 悬垂引用"（真内存破坏）与"可恢复 panic"（可用性）。
  报告里不许把后者写成 RCE
- **深读**：[unsafe-memory.md](unsafe-memory.md)

## 上传 / 下载 / 归档

- **机械规则**：`E4-ZIPSLIP`（解压侧）；其余关键词通道：
  ```bash
  rg -n 'FormFile|multipart' -t go
  rg -n 'zip\.NewReader|tar\.NewReader|Unarchive|ExtractTo' -t go
  rg -n 'Symlink|Lstat|O_NOFOLLOW' -t go          # 有防护痕迹，别急着报
  ```
- **判据核心**：**任意路径写 ≠ 任意内容写**（内容固定时只能覆盖/截断/DoS，不能种可执行物）。
  上传的后续消费（执行/解析/模板加载）决定定级；扩展名/MIME 检查既非万能也非摆设
- **深读**：[file-transfers.md](file-transfers.md)

## XML / 外部实体

- Go `encoding/xml` 默认不解析外部实体（无经典 XXE）。看到 XML 解码先确认是否用了
  `xml.Decoder` 自定义实体解析或第三方库，默认按噪声处理，一句话说明即可。

---

## 链组合（真实漏洞几乎都是链）

```
E3 解码 → 伪造身份 → E4 写 hook → 执行          (Gogs/Gitea 2018)
X 穿越读 → 拿到 app.ini/凭据 → 二次接管           (Gitea 1.4.0)
E4 落盘 → E6 加载 → 执行                         (插件类)
E5 参数注入 → 外部程序代执行                      (git/pandoc 类)
越权(装饰化 requireAuth) → X 任意读 → 凭据泄漏     (组合前半段高频)
```

写报告时一跳一跳列，每跳带 `path:line`。压缩跳数是最常见的失信行为。
校准样本：[case-library.md](case-library.md)（含伪 CVE 识别表——引用任何 CVE 前必查）。
