package stress

// Positive samples: planted known-vulnerability shapes (RCE families: E1/E1W/E2/E4/E5/X)
// Every planting point carries a // PLANTED marker naming the rule/channel expected to fire.

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

// P1 E1-SHELL-C: shell concatenation with a user-supplied directory.
func backupDir(userDir string) error {
	cmd := exec.Command("sh", "-c", "tar czf /tmp/out.tgz "+userDir) // PLANTED: E1-SHELL-C
	return cmd.Run()
}

// P2 E1-SHELL-WIN: Windows cmd re-parses the command line.
func mkLink(link, target string) error {
	cmd := exec.Command("cmd", "/c", "mklink", link, target) // PLANTED: E1-SHELL-WIN
	return cmd.Run()
}

// P3 E2-TPL-USERSTRING: template text comes from the request.
func renderUserTpl(w http.ResponseWriter, r *http.Request) {
	tpl := r.FormValue("tpl") // PLANTED: E2-TPL-USERSTRING
	t := template.Must(template.New("x").Parse(tpl))
	t.Execute(w, nil)
}

// P4 E2-FUNCMAP-EXEC: FuncMap registers an exec function.
var fmap = template.FuncMap{
	"run": func(c string) string { // PLANTED: E2-FUNCMAP-EXEC
		out, _ := exec.Command("sh", "-c", c).CombinedOutput()
		return string(out)
	},
}

// P5 E4-HOOK-WRITE: writes a git hook.
func writeHook(repo, userScript string) error {
	p := filepath.Join(repo, ".git", "hooks", "post-merge") // PLANTED: E4-HOOK-WRITE
	return os.WriteFile(p, []byte(userScript), 0o755)
}

// P6 E4-ZIPSLIP: extraction with no .. validation.
func unzip(dst string, zr *zip.Reader) error {
	for _, f := range zr.File {
		os.MkdirAll(dst, 0o755)
		out, _ := os.Create(filepath.Join(dst, f.Name)) // PLANTED: E4-ZIPSLIP
		f.Open()
		out.Close()
	}
	return nil
}

// P7 E5-ARG-NONCONST / E5-GIT-OPT: clone target is controllable.
func gitClone(userURL string) error {
	return exec.Command("git", "clone", userURL).Run() // PLANTED: E5-ARG-NONCONST
}

// P8 X-PATHTRAV-JOIN: Join with a user path, then read it directly.
func readUserFile(base, userPath string) ([]byte, error) {
	return os.ReadFile(filepath.Join(base, userPath)) // PLANTED: X-PATHTRAV-JOIN
}

var _ = fmt.Sprintf
var _ = context.Background
var _ = sql.Open
