package stress

// Positive samples: planted known-vulnerability shapes handled by the keyword
// channel (SQLi / SSRF / missing authorization / hardcoded secret).
// These dimensions have no mechanical rule -- the point is to test whether the
// keyword channel in vuln-features.md wakes up on them.

import (
	"net/http"
)

// P9 SQLi-KW: concatenated into Raw.
func findByName(db interface {
	Raw(query string) *sqlRows
}, name string) {
	db.Raw("SELECT * FROM t WHERE name = " + name) // PLANTED: KW-SQLI
}

type sqlRows struct{}

// P10 SQLi-KW: sort field passed straight through (identifier position, where
// value binding cannot help).
func listSorted(db interface {
	Order(o string) *sqlRows
}, sortCol, sortDir string) {
	db.Order(sortCol + " " + sortDir) // PLANTED: KW-SQLI-ID
}

// P11 SSRF-KW: request URL goes directly into http.Get.
func fetchAvatar(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url") // PLANTED: KW-SSRF
	resp, _ := http.Get(url)
	defer resp.Body.Close()
}

// P12 AUTHZ-KW: decorative 401 (response written, no return, function continues).
func viewSecret(w http.ResponseWriter, r *http.Request) {
	if !sessionValid(r) {
		http.Error(w, "unauthorized", 401) // PLANTED: KW-AUTHZ-DECO (no return)
	}
	w.Write([]byte("the secret"))
}

func sessionValid(r *http.Request) bool { return false }

// P13 SECRET-KW: hardcoded cookie key.
var store = newCookieStore([]byte("hardcoded-secret-key-32-bytes!!")) // PLANTED: KW-SECRET

type cookieStore struct{}

func newCookieStore(key []byte) *cookieStore { return &cookieStore{} }
