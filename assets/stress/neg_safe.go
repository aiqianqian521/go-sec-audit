package stress

// 负样本：形似危险、实为安全的写法——通道命中它们是误报信号（容忍低危唤醒，不许误判为漏洞）
// 每条带 // NEAR-MISS 标记与它"长得像"的规则

import (
	"archive/zip"
	"database/sql"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// N1 E1 反例：argv 分开传、无 shell——是路径拼接不是命令注入
func readReport(name string) error {
	return exec.Command("cat", "/reports/"+name).Run() // NEAR-MISS: E1-SHELL-C 不得命中
}

// N2 E1 反例：常量脚本
func reloadNginx() error {
	return exec.Command("sh", "-c", "nginx -s reload").Run() // NEAR-MISS: 允许低危唤醒，判 KILL
}

// N3 E2 反例：embed FS 模板 + 纯函数 FuncMap
var pageT = template.Must(template.New("p").
	Funcs(template.FuncMap{"upper": func(s string) string { return s }}).
	ParseFS(os.DirFS("templates"), "*.tmpl")) // NEAR-MISS: E2-TPL-USERSTRING 不得命中

// N4 E2 反例：time.Parse 不是模板解析
func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s) // NEAR-MISS: E2-TPL-USERSTRING 不得命中（历史噪声）
}

// N5 E4 反例：os.OpenRoot 结构性修复（Go ≥1.24）
func safeUnzip(dst string, zr *zip.Reader) error {
	root, err := os.OpenRoot(dst) // NEAR-MISS: X/E4 判据应直接判修复
	if err != nil {
		return err
	}
	defer root.Close()
	for _, f := range zr.File {
		rc, err := root.OpenFile(f.Name, os.O_RDONLY, 0o644)
		if err != nil {
			return err
		}
		rc.Close()
	}
	return nil
}

// N6 SQLi 反例：值绑定
func findSafe(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM t WHERE name = ?", name) // NEAR-MISS: KW-SQLI 不得命中
}

// N7 SECRET 反例：key 来自环境变量且校验长度
func newStore() *cookieStore {
	k := os.Getenv("SESSION_KEY")
	if len(k) < 32 {
		panic("weak key")
	}
	return newCookieStore([]byte(k)) // NEAR-MISS: KW-SECRET 不得命中
}

var _ = filepath.Join
var _ = http.Get
