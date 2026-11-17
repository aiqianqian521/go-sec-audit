package stress

// 正样本：植入的已知漏洞形态（RCE 类：E1/E1W/E2/E4/E5/X）
// 每个植入点带 // PLANTED 标记与期望命中的规则/通道

import (
	"archive/zip"
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// P1 E1-SHELL-C：shell 拼接用户目录
func backupDir(userDir string) error {
	cmd := exec.Command("sh", "-c", "tar czf /tmp/out.tgz "+userDir) // PLANTED: E1-SHELL-C
	return cmd.Run()
}

// P2 E1-SHELL-WIN：Windows cmd 二次解析
func mkLink(link, target string) error {
	cmd := exec.Command("cmd", "/c", "mklink", link, target) // PLANTED: E1-SHELL-WIN
	return cmd.Run()
}

// P3 E2-TPL-USERSTRING：模板文本来自请求
func renderUserTpl(w http.ResponseWriter, r *http.Request) {
	tpl := r.FormValue("tpl") // PLANTED: E2-TPL-USERSTRING
	t := template.Must(template.New("x").Parse(tpl))
	t.Execute(w, nil)
}

// P4 E2-FUNCMAP-EXEC：FuncMap 注册执行函数
var fmap = template.FuncMap{
	"run": func(c string) string { // PLANTED: E2-FUNCMAP-EXEC
		out, _ := exec.Command("sh", "-c", c).CombinedOutput()
		return string(out)
	},
}

// P5 E4-HOOK-WRITE：写 git hook
func writeHook(repo, userScript string) error {
	p := filepath.Join(repo, ".git", "hooks", "post-merge") // PLANTED: E4-HOOK-WRITE
	return os.WriteFile(p, []byte(userScript), 0o755)
}

// P6 E4-ZIPSLIP：解压无 .. 校验
func unzip(dst string, zr *zip.Reader) error {
	for _, f := range zr.File {
		os.MkdirAll(dst, 0o755)
		out, _ := os.Create(filepath.Join(dst, f.Name)) // PLANTED: E4-ZIPSLIP
		f.Open()
		out.Close()
	}
	return nil
}

// P7 E5-ARG-NONCONST / E5-GIT-OPT：clone 目标可控
func gitClone(userURL string) error {
	return exec.Command("git", "clone", userURL).Run() // PLANTED: E5-ARG-NONCONST
}

// P8 X-PATHTRAV-JOIN：Join 拼用户路径后直接读
func readUserFile(base, userPath string) ([]byte, error) {
	return os.ReadFile(filepath.Join(base, userPath)) // PLANTED: X-PATHTRAV-JOIN
}

var _ = fmt.Sprintf
var _ = context.Background
var _ = sql.Open
