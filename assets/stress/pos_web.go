package stress

// 正样本：植入的已知漏洞形态（关键词通道类：SQLi/SSRF/越权/秘钥）
// 这些维度没有机械规则——测试 vuln-features.md 的关键词通道能否唤醒

import (
	"net/http"
)

// P9 SQLi-KW：拼接进 Raw
func findByName(db interface {
	Raw(query string) *sqlRows
}, name string) {
	db.Raw("SELECT * FROM t WHERE name = " + name) // PLANTED: KW-SQLI
}

type sqlRows struct{}

// P10 SQLi-KW：排序字段直传（标识符位置，绑定管不了）
func listSorted(db interface {
	Order(o string) *sqlRows
}, sortCol, sortDir string) {
	db.Order(sortCol + " " + sortDir) // PLANTED: KW-SQLI-ID
}

// P11 SSRF-KW：请求 URL 直达 http.Get
func fetchAvatar(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url") // PLANTED: KW-SSRF
	resp, _ := http.Get(url)
	defer resp.Body.Close()
}

// P12 AUTHZ-KW：401 装饰化（写了响应没 return，函数继续执行）
func viewSecret(w http.ResponseWriter, r *http.Request) {
	if !sessionValid(r) {
		http.Error(w, "unauthorized", 401) // PLANTED: KW-AUTHZ-DECO (no return)
	}
	w.Write([]byte("the secret"))
}

func sessionValid(r *http.Request) bool { return false }

// P13 SECRET-KW：硬编码 cookie key
var store = newCookieStore([]byte("hardcoded-secret-key-32-bytes!!")) // PLANTED: KW-SECRET

type cookieStore struct{}

func newCookieStore(key []byte) *cookieStore { return &cookieStore{} }
