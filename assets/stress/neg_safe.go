package stress

// Negative samples: shapes that look dangerous but are safe. A channel hit here
// is a false-positive signal (a low-severity wake-up is tolerated; calling it a
// vulnerability is not).
// Every case carries a // NEAR-MISS marker naming the rule it resembles.

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

// N1 E1 counter-example: argv passed separately, no shell involved -- this is
// path concatenation, not command injection.
func readReport(name string) error {
	return exec.Command("cat", "/reports/"+name).Run() // NEAR-MISS: E1-SHELL-C must not fire
}

// N2 E1 counter-example: constant script string.
func reloadNginx() error {
	return exec.Command("sh", "-c", "nginx -s reload").Run() // NEAR-MISS: low-severity wake-up allowed, verdict KILL
}

// N3 E2 counter-example: embedded FS template + pure-function FuncMap.
var pageT = template.Must(template.New("p").
	Funcs(template.FuncMap{"upper": func(s string) string { return s }}).
	ParseFS(os.DirFS("templates"), "*.tmpl")) // NEAR-MISS: E2-TPL-USERSTRING must not fire

// N4 E2 counter-example: time.Parse is not template parsing.
func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s) // NEAR-MISS: E2-TPL-USERSTRING must not fire (historical noise)
}

// N5 E4 counter-example: os.OpenRoot is a structural fix (Go >= 1.24).
func safeUnzip(dst string, zr *zip.Reader) error {
	root, err := os.OpenRoot(dst) // NEAR-MISS: X/E4 criterion should rule this fixed outright
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

// N6 SQLi counter-example: value binding.
func findSafe(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM t WHERE name = ?", name) // NEAR-MISS: KW-SQLI must not fire
}

// N7 SECRET counter-example: key comes from the environment and its length is checked.
func newStore() *cookieStore {
	k := os.Getenv("SESSION_KEY")
	if len(k) < 32 {
		panic("weak key")
	}
	return newCookieStore([]byte(k)) // NEAR-MISS: KW-SECRET must not fire
}

var _ = filepath.Join
var _ = http.Get
