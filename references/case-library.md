# 公开 Go RCE 案例库

用途：给"什么算真 RCE"提供校准样本，避免把 E3 当 E1、把路径穿越当命令注入。

每条都标**证据等级**与**来源**。等级定义见 [verification gates](verification-gates.md)。
**没有来源的条目已被剔除**——本文件不接受"我记得有个 CVE"。

**证据等级必须区分来源（2026-11-13 修订）**：`L3` 曾被同时用于"厂商/公开研究已证实"和"我们本机复现过"，
两者可信度差一个量级，评审无法分辨。现拆成两级：

| 标记 | 含义 | 谁打的 payload |
|---|---|---|
| `L3-repro` | 我们自己在隔离环境打通，有负样本对照 | 本 skill 维护者 |
| `L3-lit` | 有厂商公告 / 在野利用 / 公开 PoC / 补丁 diff 佐证，**我们没复现** | 外部 |
| `L2` | 只有机制分析与来源，注入性未证 | 无人 |

当前计数（2026-11-13）：`L3-repro` = **1**（A7，且**不是 RCE**，是任意文件读）；
`L3-lit` = 4（A1–A4）；`L2` = 2（A5、A6）。**本库尚未有任何一条 Go RCE 是本机复现的** ——
引用时不要把它读成"已验证可利用"。


---

## A. 已核验案例

### A1. Gogs / Gitea session 反序列化 → 提权 → git hooks RCE
- **CVE**：CVE-2018-18925（Gogs）/ CVE-2018-18926（Gitea）
- **影响**：Gogs ≤ 0.11.66，Gitea ≤ 1.5.3
- **相**：E3（入口）→ 提权 → **E4**（终点）
- **链条**：session 反序列化 → 普通用户被伪造成管理员 → 用管理员的 git hooks 编辑能力写入命令 → 服务账号执行
- **证据**：L3-lit（外部已证实，本机未复现）。360CERT 报告 + NVD + gogs/gogs#5469 修复记录
- **为什么收录**：这是"E3 不直达 RCE"最好的反例教材。把这条写成"gob 反序列化导致 RCE"就是把三跳压成一跳，属于失真。
- **来源**：`https://www.secrss.com/articles/6190`

### A2. Gitea diffpatch 写入 git hook → RCE（在野利用）
- **CVE**：CVE-2026-60004，CVSS 9.8
- **影响**：>= 1.17.0, < 1.27.1；修复 1.27.1（后续 1.27.2）
- **状态**：CISA KEV，2026-08 起在野利用，公开 PoC 与 Nuclei 模板存在
- **相**：**E4**，全程无 `exec.Command`
- **链条**（据 Acronis 报告转述，未逐行核对 git 源码）：
  1. 入口 `diffpatch` 端点，开放注册时任意访客可用
  2. 同一份构造 patch 提交两次
  3. 第一次把 payload 放进 git index；第二次在 merge 时触发 add 冲突，文件被直接写到磁盘
  4. bare clone 的仓库根**即** `$GIT_DIR`，故写入 `hooks/post-index-change` 直接落进活的 hook 目录
  5. git 下次触碰 index 时执行，身份为 Gitea 服务账号
- **证据**：L3-lit（外部已证实，本机未复现）（在野利用 + PoC + 厂商公告）
- **为什么收录**：只 grep `exec` 的审计会 100% 漏掉这个。E4 相存在的理由就是它。
- **来源**：`https://www.helpnetsecurity.com/2026/08/26/gitea-cve-2026-60004-exploited-in-the-wild`、`https://securityonline.info/gitea-rce-vulnerability-exploited`

### A3. kubelet Windows SubPath 命令注入 → SYSTEM
- **CVE**：CVE-2023-3676（及同源 CVE-2023-3955、CVE-2023-5528），CVSS 8.8
- **影响**：kubelet ≤ v1.28.0 / v1.27.4 / v1.26.7 / v1.25.12 / v1.24.16 等（各分支修复版本已发布）；仅 Windows 节点
- **相**：**E1**（Windows shell 二次解析）
- **机制**：`MountSensitive()` 用 `exec.Command` 调 `cmd` 建符号链接；`subPath` 未净化，`cmd` 把参数当命令行解析 → `$()` 被执行
- **修复方式**：**删掉 cmd 调用**，改用原生 Go 符号链接函数；另一处改为从环境变量传参而非用户输入
- **证据**：L3-lit（外部已证实，本机未复现）（Akamai 研究 + 公开 PoC YAML + 修复提交）
- **为什么收录**：证明"参数分开传 = 安全"在 Windows shell 上不成立。这是 E1 与 E5 的分界教案。
- **来源**：`https://www.anquanke.com/post/id/293971`、`https://gbhackers.com/kubernetes-vulnerability-full-system-control`、阿里云 ACK 公告 2569524

### A4. Grafana DuckDB SQL 表达式 → 扩展加载 → 命令执行
- **CVE**：CVE-2024-9264
- **影响**：11.0.0–11.0.5、11.1.0–11.1.6、11.2.0–11.2.1；**RCE 仅 11.0.0**，其余版本可任意文件读
- **相**：**E6**（数据库扩展加载 + 解释器内建管道执行）
- **链条**：认证用户改 dashboard 表达式，把 datasource 从 `math` 改成 `sql` → `LOAD shellfs` 扩展 → `read_csv('id > /tmp/x 2>&1 |')` 的管道语法把内容交给 shell → `read_blob` 读回输出
- **修复**：整块删除 SQL Expressions 功能（补丁里 `pkg/expr/sql/db.go` 全部返回 `not implemented`）
- **证据**：L3-lit（外部已证实，本机未复现）（公开 PoC 仓库 + 补丁 diff + HTB 靶机 writeup）
- **为什么收录**：标签是"SQL 注入"，本质是"能加载扩展的解释器"。按标签审计会得出错误的修复建议（转义 SQL 无效）。
- **来源**：`https://onlybits.org/nollium/CVE-2024-9264`、`https://blog.gitcode.com/3c0afd30cb6c84547219818060a0a74a.html`

### A5. Gitea external renderer 参数注入
- **CVE**：CVE-2026-73539，CVSS 7.5，CWE-88
- **相**：**E5**
- **机制**：命令模板里由 markup Context 派生的 URL 未转义，可注入额外 renderer 参数（含加载可执行 filter 的选项）；配 pandoc 等 renderer + 可放置的 filter 文件 → 以服务账号执行
- **证据**：**L2**。单一来源（2026-10-14 发布），未见 NVD 原文核对 → 使用前需复核，勿直接引用版本号
- **为什么收录**：参数注入（CWE-88）与命令注入（CWE-78）的区分样本
- **来源**：`https://nextguardhq.com/en/vulnerabilities/cve-2026-73539-gitea-gitea`

### A6. Go SSTI 方法论（非单一 CVE）
- **相**：E2
- **要点**：Go 模板注入大量是 **shadow vulnerability**（无 CVE）：引擎按设计运行，是应用把模板文本或 FuncMap 暴露给了用户
- **可利用形态**：`{{.Method "arg"}}` 调对象方法；`{{call .Fn "arg"}}` 调函数值；FuncMap 注册了 exec/readfile 类函数
- **不可利用形态**：`html/template` + 固定模板 + 纯函数 FuncMap
- **证据**：L2（方法论层面，无需 CVE）
- **来源**：`https://www.onsecurity.io/blog/go-ssti-method-research/`、`https://blog.takemyhand.xyz/2020/06/ssti-breaking-gos-template-engine-to`、`https://www.oligo.security/blog/safe-by-default-or-vulnerable-by-design-golang-server-side-template-injection`

### A7. Gitea 1.4.0 LFS Oid 路径穿越 → **未授权任意文件读**（写侧被闸门挡住，非 RCE）
- **CVE**：无独立编号，vulhub 收录目录名为 `gitea/1.4-rce`；1.4.1 修复
- **相**：**X（路径穿越，入口）→ 仅到「凭据/配置泄露」**。**不落 E 相**
- **机制**：
  - `modules/lfs/content_store.go:29`（`Get`）与 `:49`（`Put`）均为 `filepath.Join(s.BasePath, transformKey(meta.Oid))`
  - `transformKey()` 不做 `..` 校验：`len(key) < 5` 原样返回，否则 `filepath.Join(key[0:2], key[2:4], key[4:])`
  - `Oid` 来自 LFS 请求体的 `oid` 字段
  - **未授权的根因是少一个 `return`**：`server.go:221` `if !authenticate(...) { requireAuth(ctx) }` 之后函数继续执行到 `NewLFSMetaObject`，401 只是个装饰
- **实测（2026-11-13，本机靶场，L3）**：
  - 环境：CentOS 7 + `gitea-1.4.0-linux-amd64`（dl.gitea.com，53,662,000 B）+ sqlite，`gitea migrate` + `admin create-user`
  - **硬前提：Git ≥ 2.1.2**。`modules/setting/setting.go:892` 在版本不足时执行 `LFS.StartServer = false`，LFS 路由**根本不注册**，一切 LFS 请求 404。CentOS 7 自带 git 1.8.3.1 因此必然踩坑
  - 扫描器验证：补 `X-PATHTRAV-JOIN` 前对 `modules/lfs/` **0 命中**；补后命中 `content_store.go:29 / 49 / 80 / 90`，即 `Get` / `Put` / `Exists` / `Verify` 四个方法
  - 读侧打通：`oid = "...." + "../../../../../../" + <绝对路径>`，无凭据即可读
    | 目标 | 字节 | 校验 |
    |---|---|---|
    | `/etc/passwd` | 1108 | 与 `wc -c` 完全一致 |
    | `/etc/shadow` | 699 | 含 root 的 `$6$` 哈希 |
    | `custom/conf/app.ini` | 802 | 含 `SECRET_KEY` / `INTERNAL_TOKEN` / `LFS_JWT_SECRET` |
  - **写侧不成立**：`content_store.go:67-72` 在 `os.Rename` 前比对 `sha256(content) == meta.Oid`。要写文件就必须让内容哈希等于 `Oid`，而 `Oid` 又决定路径 —— **「路径可控」与「内容可控」天然互斥**。实测 `PUT` → `500 {"message":"Content hash does not match OID"}`，目标文件未生成
  - **唯一写侧副作用**：`MkdirAll` 在闸门之前（`content_store.go:56`）→ **任意目录创建**成立（实测新建 `/root/x/pwn/deep/dir`）
- **为什么收录**：①"未授权 + 任意文件读"在 Go 生态里是高频真实形态，且拿 `/etc/shadow` 或 `app.ini` 后常能二次接管；②证明六相模型**不覆盖入口侧的净化缺失**，路径穿越必须单列 X 相；③记录一个真实环境闸门（git 版本），避免下次再从 404 开始猜；④**记录一次「名字说有 RCE、代码说只有读」的偏差** —— vulhub 目录名 `-rce` 不能当结论
- **来源**：vulhub `gitea/1.4-rce` README、`https://security.szurek.pl/gitea-1-4-0-unauthenticated-rce.html`、`https://www.leavesongs.com/PENETRATION/gitea-remote-command-execution.html`
- **与来源的偏差（重要）**：上述 writeup 声称 RCE，但 1.4.0 源码里 `Put()` 的 sha256 闸门使"任意文件写"不成立。**以源码为准**；若要复现写侧需换版本或另找 sink


---

## B. 已知伪造 / 污染样本（**不要引用**）

这些在搜索结果里出现频率很高，是 AI 生成的内容农场产物。收录在此是为了让你在别处再遇到时能立刻认出来。

| 伪 CVE | 声称内容 | 为什么是假的 |
|--------|----------|-------------|
| CVE-2024-34567 | gorilla/sessions 反序列化 RCE，影响 v1.2.0–v1.3.1 | 编号不存在；且 CookieStore 经 securecookie **强制 HMAC 签名**，不存在"未签名即 gob 解码"的路径 |
| CVE-2024-45678 | k8s.io/client-go 证书校验绕过，v0.28.0–v0.29.3 | 编号不存在；描述的"静默设 InsecureSkipVerify=true"无对应代码 |
| CVE-2024-56789 | spf13/cobra 命令注入 v1.7.0–v1.8.2 | 编号不存在；cobra 只做 flag 解析，不调用 shell |
| CVE-2025-XXXX | Go text/template FuncMap 反射调用 RCE | 编号是占位符；正文自承"X" |

**识别特征**：
1. 编号呈连续递增（34567 / 45678 / 56789）——真实 CVE 编号无此规律
2. 给出"受影响版本矩阵"却没有对应 GHSA / OSV / NVD 链接
3. 附"热补丁代码"但代码风格与上游不符（缩进、命名、错误处理习惯）
4. 站点本身是 SEO 内容农场，同页混杂多个不相干领域

**处置**：任何 CVE 引用前必须至少命中其一：`nvd.nist.gov/vuln/detail/<id>`、`cve.org/CVERecord?id=<id>`、厂商 advisory、OSV/GHSA 记录。查不到 → 不进报告。

---

## C. 待核验（本轮未取得一手来源，勿引用）

- runc / containerd / buildkit 系列容器逃逸（CVE-2024-21626 等）：属 Go 写的组件，但本轮未核对公告与修复 diff
- Caddy / Traefik / Consul / Nomad / Vault / MinIO 的 RCE 类 CVE：未逐个核验
- Go 标准库 `text/template` 历史 CVE-2023-24538：未核对影响面与真实利用条件

补进来的条件：拿到一手公告 + 修复 diff + （可选）PoC，并按 A 节格式补齐 `相 / 链条 / 证据 / 来源`。

---

## D. 怎么用这个库做训练

### D1. 差分扫描（最有效的单一练习）
对同一个项目取两个 commit：漏洞版本与修复版本，各跑一次扫描器。

```bash
git -C <repo> checkout <vuln-tag>   && python3 scripts/scan_sinks.py <repo> --out v-vuln.md
git -C <repo> checkout <fixed-tag> && python3 scripts/scan_sinks.py <repo> --out v-fixed.md
diff -u v-vuln.md v-fixed.md
```

期望：修复版本上，对应相的候选**消失或形状改变**（例如 `hooks/` 字符串被移除、`--upload-path` 加了校验）。
若两边完全一样 → 要么规则没覆盖这类，要么修复点在别处（常见：加了个前置校验而不是删 sink）。后者更有教学价值：**修复不一定动 sink**。

### D2. 规则回归
每个案例登记一条元数据，作为扫描器的验收用例：

```json
{
  "project": "gitea", "cve": "CVE-2026-60004",
  "vuln_commit": "<sha>", "fixed_commit": "<sha>",
  "path": "E4", "sink": "routers/api/v1/repo/patch.go:<line>",
  "must_hit_rules": ["E4-HOOK-WRITE"],
  "must_not_survive_fix": true,
  "note": "bare clone 根即 GIT_DIR，非 exec 类"
}
```

`must_hit_rules` 在 vuln commit 上必须命中；`must_not_survive_fix` 在 fixed commit 上必须不命中。两条都过，规则才算对这类漏洞有效。

### D3. 反面练习（比正样本更重要）
拿本文件 B 节的伪 CVE，去真实仓库里找它声称的代码。找不到是常态。
练的是"在 30 秒内判定一个 CVE 引用不可信"的能力——这比多挖一个洞更有价值，因为报告写错一次就没人信你后面的十条。

### D4. 靶场
A2/A4 有公开 PoC 与 Docker 镜像，可在隔离环境复现。复现必须带**负样本对照**：同一请求，payload 中和后不应触发。没有对照的"复现成功"通常是巧合。
